#!/usr/bin/env python3
"""
sweep-users-change.py
Собирает сдачу (change) из кошелька users (HD), которая «разбежалась» по пустым
адресам, и консолидирует её в адрес кошелька withdrawal, используя sweepallraw
(без создания change-выхода на адреса users).

Порог: адрес считается «пустым в истории юзеров» и годным для консолидации, если
у него нет UTXO (listunspent), а также мы не держим его как депозитный адрес
в БД (user_wallets). По умолчанию не трогает адреса, упомянутые в user_wallets
с currency='lbtc' (любой статус).

Использование:
  sweep-users-change.py --dry-run
  sweep-users-change.py
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import base64
from datetime import datetime

DATADIR = "/home/coin/.legacycoin/wallets/users"
WALLET = os.path.join(DATADIR, "wallet.json")

RPC_URL = os.environ.get("LEGACYCOIN_RPC_URL", "http://127.0.0.1:19556")
def _default_rpc_auth():
    # The node runs cookie-only (2026-11-12): static rpcuser/rpcpassword are
    # gone from legacycoin.conf, auth comes from the datadir .cookie, re-read
    # per process start so a rotated cookie is picked up on the next run.
    try:
        raw = open("/home/coin/.legacycoin/.cookie").read().strip()
        if ":" in raw:
            return raw
    except OSError:
        pass
    return "coin:coin"  # pre-cookie-only fallback, kept for old snapshots


RPC_AUTH = os.environ.get("LEGACYCOIN_RPC_AUTH") or _default_rpc_auth()
WITHDRAWAL_ADDR = os.environ.get("LBTC_WITHDRAWAL_ADDR", "LQehzjT3YXhTiQD8bVzM1suVSL2Ty3JZYB")
DB_CONN = os.environ.get("HOLLAX_DB_DSN", "host=127.0.0.1 port=5434 dbname=hollaex user=admin password=root")

def log(msg):
    line = "%s %s" % (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)

def rpc(method, params, wallet=None, timeout=60):
    body = json.dumps({"jsonrpc":"1.0","id":"sweep","method":method,"params":params}).encode()
    req = urllib.request.Request(RPC_URL, data=body, headers={"Content-Type":"application/json"})
    req.add_header("Authorization","Basic " + base64.b64encode(RPC_AUTH.encode()).decode())
    if wallet:
        req.add_header("X-LegacyCoin-Wallet", wallet)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode())
    except Exception as e:
        raise RuntimeError("rpc %s failed: %s" % (method, e))
    if payload.get("error"):
        raise RuntimeError("rpc %s: %s" % (method, payload["error"]))
    return payload["result"]

def load_wallet(path):
    if not os.path.exists(path):
        return {"keys": {}, "addresses": []}
    with open(path,"r",encoding="utf-8") as fh:
        data=json.load(fh)
    keys = data.get("keys") or {}
    data["keys"]=keys
    data["addresses"]=list(keys.keys())
    return data

def active_unspent(wallet="users"):
    utxos = rpc("listunspent",[0,9999999], wallet=wallet)
    return {u["address"] for u in utxos if isinstance(u,dict) and u.get("address")}

def protected_addresses():
    try:
        import psycopg2
        conn = psycopg2.connect(DB_CONN)
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT address FROM user_wallets WHERE currency='lbtc' AND address IS NOT NULL AND address <> ''")
        rows = cur.fetchall()
        cur.close(); conn.close()
        return {r[0] for r in rows}
    except Exception as e:
        log("WARN: cannot read user_wallets (%s), assuming empty protected set" % e)
        return set()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--fee-sat", type=int, default=1000, help="fee in base units (sat)")
    args = ap.parse_args()
    started=time.time()
    w = load_wallet(WALLET)
    all_addrs = set(w.get("keys",{}).keys())
    active = active_unspent("users")
    prot = protected_addresses()
    candidates = [a for a in all_addrs if a not in active and a not in prot]
    if not candidates:
        log("no candidates: all_addrs=%d active=%d prot=%d" % (len(all_addrs),len(active),len(prot)))
        return 0
    log("candidates to sweep: %d (e.g. %s)" % (len(candidates), ", ".join(list(candidates)[:5])))
    swept=0; failed=0
    for a in candidates:
        try:
            if args.dry_run:
                log("DRY-RUN sweepallraw %s -> %s" % (a, WITHDRAWAL_ADDR))
                swept+=1; continue
            res = rpc("sweepallraw",[a, WITHDRAWAL_ADDR, args.fee_sat], wallet="users")
            txid = res.get("txid") if isinstance(res,dict) else res
            log("swept %s -> %s tx=%s" % (a, WITHDRAWAL_ADDR, txid))
            swept+=1
            time.sleep(0.3)
        except Exception as e:
            log("ERR sweep %s: %s" % (a,e)); failed+=1
    log("done: swept=%d failed=%d in %.1fs" % (swept,failed,time.time()-started))
    return 0 if failed==0 else 1

if __name__=="__main__":
    sys.exit(main())
