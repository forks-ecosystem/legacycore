#!/bin/bash

rpc() {
 local method="$1"
 local params="${2:-[]}"
 curl -s -u coin:coin -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":\"lb\",\"method\":\"$method\",\"params\":$params}" http://127.0.0.1:19556
}

./legacycoin-cli -rpcuser=coin -rpcpassword=coin getbalance
#./legacycoin-cli -rpcuser=coin -rpcpassword=coin listunspent
#./legacycoin-cli -rpcuser=coin -rpcpassword=coin getminerstatus
#./legacycoin-cli -rpcuser=coin -rpcpassword=coin listimmature
 echo "===== WALLET ====="
# rpc getwalletsummary; echo
