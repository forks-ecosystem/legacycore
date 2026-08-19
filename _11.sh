#!/bin/bash

rpc() {
 local method="$1"
 local params="${2:-[]}"
 curl -s -u coin:coin -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":\"lb\",\"method\":\"$method\",\"params\":$params}" http://127.0.0.1:19556
}

while true; do
 clear
 echo "===== CHAIN ====="
 rpc getblockcount; echo
 rpc getbestblockhash; echo
 rpc getdifficulty; echo
 echo "===== WALLET ====="
 rpc getwalletsummary; echo
 echo "===== MINING ====="
 rpc getmininginfo; echo
 echo "===== STORAGE ====="
 rpc checkstorage; echo
 sleep 30
done
