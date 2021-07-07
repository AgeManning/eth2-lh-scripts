#!/bin/sh

curl localhost:5052/lighthouse/peers | jq '.[] | .peer_id,.peer_info.client.kind,.peer_info.seen_addresses'
