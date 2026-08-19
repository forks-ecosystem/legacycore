#!/bin/bash

rpc() {
 local method="$1"
 local params="${2:-[]}"
 curl -s -u coin:coin -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":\"lb\",\"method\":\"$method\",\"params\":$params}" http://127.0.0.1:19556
}
echo getblockcount
rpc getblockcount
echo
echo getbestblockhash
rpc getbestblockhash
echo
echo getwalletsummary
rpc getwalletsummary
echo
echo getmininnginfo
rpc getmininginfo
echo
echo checkstorage
rpc checkstorage
echo