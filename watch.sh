#!/bin/sh


tail -f $1 | cat -v | grep -e WARN -e ERROR -e INFO -e CRIT -e ERRO -e Disconnected -e Error -e Established -e yamux -e "block is already" -e ERR -e "warn" -e "penalty" -e "promise" -e "Address updated" -e "score" -e "Invalid" -e "invalid" -e "banned"
