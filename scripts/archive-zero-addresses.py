#!/usr/bin/env python3
"""
archive-zero-addresses.py — двойной учёт адресов сдачи.

Переносит обнулённые адреса из основного кошелька агента
    /home/coin/.legacycoin/wallet.json
в архивный
    /home/coin/.legacycoin/wallet_change.json
и обратно, если на архивный адрес снова поступили средства.

Активность адреса определяется одним вызовом listunspent (есть UTXO ->
баланс ненулевой), чтобы не гонять getaddressbalance по каждому адресу:
нода rate-limitит RPC (~60/s burst, ~1/s sustained на IP).

Использование:
    archive-zero-addresses.py --dry-run   # только отчёт, без записи
    archive-zero-addresses.py             # перенос + ротация бэкапов
    archive-zero-addresses.py --force     # снять защиту «переносим всё»

Cron (crontab пользователя coin, каждые 10 минут):
    */10 * * * * /usr/bin/python3 /app/legacycore/scripts/archive-zero-addresses.py >> /home/coin/LegacyCore/logs/archive-zero.log 2>&1

Перенесён из /home/coin/LegacyCore/scripts/ в проект 2026-10-07.
"""

import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import datetime

DATADIR = "/home/coin/.legacycoin"
WALLET = os.path.join(DATADIR, "wallet.json")
ARCHIVE = os.path.join(DATADIR, "wallet_change.json")
LOGFILE = os.path.join(DATADIR, "archive-zero.log")
BACKUP_KEEP = 2

RPC_URL = os.environ.get("LEGACYCOIN_RPC_URL", "http://127.0.0.1:19556")
RPC_AUTH = os.environ.get("LEGACYCOIN_RPC_AUTH", "coin:coin")


def log(msg):
    line = "%s %s" % (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    try:
        with open(LOGFILE, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def rpc(method, params, timeout=60):
    body = json.dumps({"jsonrpc": "1.0", "id": "archive", "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC_URL, data=body, headers={"Content-Type": "application/json"})
    import base64
    req.add_header("Authorization", "Basic " + base64.b64encode(RPC_AUTH.encode()).decode())
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    if payload.get("error"):
        raise RuntimeError("rpc %s: %s" % (method, payload["error"]))
    return payload["result"]


def load_wallet(path):
    if not os.path.exists(path):
        return {"keys": {}, "addresses": [], "classic_key_count": 0}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("keys"), dict):
        raise RuntimeError("%s: неожиданная структура" % path)
    return data


def normalize(data):
    data["keys"] = {a: k for a, k in data["keys"].items() if isinstance(a, str) and isinstance(k, str) and a}
    data["addresses"] = list(data["keys"].keys())
    data["classic_key_count"] = len(data["keys"])
    return data


def backup(path):
    if not os.path.exists(path):
        return
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    dst = "%s.bak-%s" % (path, stamp)
    with open(path, "rb") as src, open(dst, "wb") as out:
        out.write(src.read())
    os.chmod(dst, 0o600)
    prune = [f for f in os.listdir(os.path.dirname(path))
             if f.startswith(os.path.basename(path) + ".bak-")]
    for old in sorted(prune)[-BACKUP_KEEP:]:
        # keep last N, remove older
        pass
    to_remove = sorted(prune)[:-BACKUP_KEEP]
    for old in to_remove:
        try:
            os.unlink(os.path.join(os.path.dirname(path), old))
        except OSError:
            pass


def save(path, data):
    normalize(data)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def active_addresses():
    utxos = rpc("listunspent", [0, 9999999])
    if not isinstance(utxos, list):
        raise RuntimeError("listunspent: неожиданный ответ")
    return {u["address"] for u in utxos if isinstance(u, dict) and u.get("address")}


def main():
    ap = argparse.ArgumentParser(description="перенос обнулённых адресов в архивный кошелёк")
    ap.add_argument("--dry-run", action="store_true", help="только отчёт, ничего не писать")
    ap.add_argument("--force", action="store_true", help="снять защиту от полного переноса")
    args = ap.parse_args()

    started = time.time()
    active = active_addresses()

    wallet = load_wallet(WALLET)
    archive = load_wallet(ARCHIVE)
    normalize(wallet)
    normalize(archive)

    w_keys, a_keys = wallet["keys"], archive["keys"]
    if not w_keys:
        log("wallet.json пуст — нечего делать")
        return 0

    # wallet_change.json копировался вручную и дублирует содержимое
    # wallet.json: источник правды — wallet.json, пересечение из архива убираем.
    overlap = set(w_keys) & set(a_keys)
    if overlap:
        mismatch = [a for a in overlap if w_keys[a] != a_keys[a]]
        if mismatch:
            raise RuntimeError("разные ключи в wallet.json и архиве: %s"
                               % ", ".join(mismatch[:3]))
        if args.dry_run:
            log("пересечение wallet.json/архива: %d адресов (в dry-run не трогаю)"
                % len(overlap))
            overlap = set()
        else:
            for a in overlap:
                del a_keys[a]
            log("пересечение wallet.json/архива убрано из архива: %d адресов"
                % len(overlap))

    to_archive = [a for a in w_keys if a not in active]
    to_restore = [a for a in a_keys if a in active]

    if not to_archive and not to_restore:
        log("изменений нет: активных %d, в архиве %d, заархивировано 0"
            % (len(active & set(w_keys)), len(a_keys)))
        return 0

    if len(to_archive) == len(w_keys) and not args.force:
        log("ОШИБКА: ушли бы все адреса (%d из %d), список активных пуст — "
            "проверьте ноду или запустите с --force" % (len(to_archive), len(w_keys)))
        return 2

    log("активных (есть UTXO): %d; в архиве: %d; к переносу в архив: %d; возврат из архива: %d"
        % (len(active), len(a_keys), len(to_archive), len(to_restore)))
    for label, batch in (("архив", to_archive), ("возврат", to_restore)):
        if batch:
            shown = ", ".join(batch[:5]) + ("…" if len(batch) > 5 else "")
            log("  %s (%d): %s" % (label, len(batch), shown))

    if args.dry_run:
        log("dry-run: файлы не изменялись")
        return 0

    backup(WALLET)
    backup(ARCHIVE)

    for a in to_archive:
        a_keys[a] = w_keys.pop(a)
    for a in to_restore:
        w_keys[a] = a_keys.pop(a)

    save(WALLET, wallet)
    save(ARCHIVE, archive)

    log("записано: wallet.json=%d адресов, wallet_change.json=%d адресов, за %.1f с"
        % (len(w_keys), len(a_keys), time.time() - started))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        log("ОШИБКА: %s" % exc)
        sys.exit(1)
