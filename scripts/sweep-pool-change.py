#!/usr/bin/env python3
"""
sweep-pool-change.py
Консолидирует «сдачу» (change) кошелька pool, которая после каждого sendmany
пула оседает на новых адресах кошелька pool, обратно на DEV_WALLET (LMmTyz...).

В отличие от sweep-users-change.py берутся адреса, у которых ЕСТЬ UTXO
(баланс > 0), кроме основных адресов:
  - DEV_WALLET (награда пула),
  - DEV_FEE_ADDRESS (комиссия, не трогаем).

Списание — sweepallraw <addr> <DEV_WALLET> <fee_sat>, т.е. без создания нового
change-выхода. После обнуления адреса его подберёт archive-zero-addresses.py.

Использование:
  sweep-pool-change.py --dry-run
  sweep-pool-change.py
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.request
from datetime import datetime

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
POOL_WALLET = os.environ.get("LBTC_POOL_WALLET", "pool")
DEV_WALLET = os.environ.get("LBTC_POOL_DEV_WALLET", "LMmTyzLwhQjePbHuDLVtMvd6PyhuknktKA")
DEV_FEE_ADDRESS = os.environ.get("LBTC_POOL_DEV_FEE_ADDRESS", "LNsDCfUUi33qnU5M6RLxD1pLW8qvq5maaj")

PROTECTED = {DEV_WALLET, DEV_FEE_ADDRESS}


def log(msg):
    print("%s %s" % (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), msg))


def rpc(method, params, wallet=None, timeout=120):
    body = json.dumps({"jsonrpc": "1.0", "id": "sweep", "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC_URL, data=body, headers={"Content-Type": "application/json"})
    req.add_header("Authorization", "Basic " + base64.b64encode(RPC_AUTH.encode()).decode())
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


def funded_addresses(minconf=1):
    utxos = rpc("listunspent", [minconf, 9999999], wallet=POOL_WALLET) or []
    amounts = {}
    for u in utxos:
        addr = u.get("address")
        if addr:
            amounts[addr] = amounts.get(addr, 0.0) + float(u.get("amount", 0))
    return amounts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--fee-sat", type=int, default=1000, help="fee in base units (sat)")
    ap.add_argument("--minconf", type=int, default=1)
    args = ap.parse_args()

    started = time.time()
    amounts = funded_addresses(args.minconf)
    candidates = sorted(
        (a for a in amounts if a not in PROTECTED and amounts[a] > 0),
        key=lambda a: amounts[a],
        reverse=True,
    )
    total = sum(amounts[a] for a in candidates)
    log("pool change addresses with balance: %d (excl. DEV_WALLET/DEV_FEE), total=%.8f LBTC" % (len(candidates), total))
    if not candidates:
        log("nothing to sweep")
        return 0
    log("sample: %s" % ", ".join("%s=%.8f" % (a, amounts[a]) for a in candidates[:5]))

    swept = 0
    failed = 0
    for a in candidates:
        try:
            if args.dry_run:
                log("DRY-RUN sweepallraw %s (%.8f) -> %s" % (a, amounts[a], DEV_WALLET))
                swept += 1
                continue
            res = rpc("sweepallraw", [a, DEV_WALLET, args.fee_sat], wallet=POOL_WALLET)
            txid = res.get("txid") if isinstance(res, dict) else res
            log("swept %s (%.8f) -> %s tx=%s" % (a, amounts[a], DEV_WALLET, txid))
            swept += 1
            time.sleep(0.3)
        except Exception as e:
            log("ERR sweep %s: %s" % (a, e))
            failed += 1

    log("done: swept=%d failed=%d in %.1fs" % (swept, failed, time.time() - started))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
