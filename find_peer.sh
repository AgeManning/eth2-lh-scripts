#!/bin/sh

QUERY=$(jq '.[] | select(.peer_id==$1)')

curl localhost:5052/lighthouse/peers | $QUERY
