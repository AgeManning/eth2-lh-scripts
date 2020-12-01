#!/bin/sh

curl localhost:5052/lighthouse/peers | jq '.[] | select(.peer_info.score.Real.score<-20)'
