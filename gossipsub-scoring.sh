#!/bin/env python3

# This script analyses lighthouse beacon node's log files.
# To work the beacon node has to run with DEBUG level libp2p and lighthouse logs, i.e. 
# `RUST_LOG="libp2p_gossipsub=debug" lighthouse -l bn --debug-level debug ...`.
# 
# The script accepts four optional positional arguments:
# First argument:  The path to the log file to analyze (default "lighthouse.log")
# Second argument: The path where the grepped files will get stored. (default ".")
# Third argument:  The command to use for grepping. (default "grep")
# Fourth argument: A boolean flag. If it is "1" then it will regrep everything, otherwise it will 
#                  use the stored files in the path of argument 1 (default "1")

import sys
import re
import tempfile
import os
import stat
from datetime import datetime
from subprocess import run

# parse args
save_dir = "."
log_files = "lighthouse.log"
grep_command = "grep"
apply_grep = True


if len(sys.argv) > 1:
    log_files = sys.argv[1]
if len(sys.argv) > 2:
    save_dir = sys.argv[2] 
if len(sys.argv) > 3:
    grep_command = sys.argv[3]
if len(sys.argv) > 4:
    apply_grep = sys.argv[4] == "1"


# create save_dir
run(["mkdir", "-p", save_dir])
# create tmp script
if apply_grep:
    with open(save_dir + "/gossipsub_penalties", "w") as f:
        # search for relevant log lines
        run([grep_command, "-P", "peer_score\] (?!(Remove ip|Add ip))", log_files], stdout=f)

    with open(save_dir + "/peer_identities", "w") as f:
        # search for relevant log lines
        run([grep_command, "Identified Peer", log_files], stdout=f)

prefix = r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z DEBUG libp2p_gossipsub::peer_score\] "
behavioral_penalty_pattern = re.compile(prefix + r"Behavioral penalty for peer ([0-9a-zA-Z]*), count = (\d*)\.$")
deliveries_penalty_pattern = re.compile(prefix + r"The peer ([0-9a-zA-Z]*) has a mesh message delivieries deficit of (\d*\.?\d*) in topic/eth2/[0-9a-f]*/([a-z0-9_]*)/ssz_snappy and will get penalized by (-\d*\.?\d*)$")
ip_penalty_pattern = re.compile(prefix + r"The peer ([0-9a-zA-Z]*) gets penalized because of too many peers with the ip ([0-9\.]*)\. The surplus is (\d*)\.$")
invalid_penalty_pattern = re.compile(prefix + r"Peer ([0-9a-zA-Z]*) delivered an invalid message in topic /eth2/[0-9a-f]*/([a-z0-9_]*)/ssz_snappy and gets penalized for it$")
lighthouse_pattern = re.compile("DEBG")
libp2p_pattern = re.compile("Z (TRACE|DEBUG|INFO)")

behavior_penalty_decay = pow(0.01, 1.0 / (12 * 32 * 10))

behavioral_penalties_per_peer = {}
behavioral_penalties = {}
deliveries_deficits_per_topic = {}
deliveries_deficits = {}
ip_penalties = {}
invalid_penalties = {}

def apply(d, peer_id, value):
    if peer_id not in d or d[peer_id] < value:
        d[peer_id] = value

def behavioral_penalty(line):
    m = behavioral_penalty_pattern.search(line)
    if m:
        timestamp = datetime.fromisoformat(m.groups()[0])
        peer_id = m.groups()[1]
        penalties = int(m.groups()[2])
        if peer_id in behavioral_penalties_per_peer:
            passed_seconds = (timestamp - behavioral_penalties_per_peer[peer_id]["last_updated"]).total_seconds()
            penalties += behavioral_penalties_per_peer[peer_id]["penalties"] * pow(behavior_penalty_decay, passed_seconds)
        behavioral_penalties_per_peer[peer_id] = {"penalties": penalties, "last_updated": timestamp}
        if penalties > 6.0:
            apply(behavioral_penalties, peer_id, penalties)
    return m

def deliveries_penalty(line):
    m = deliveries_penalty_pattern.search(line)
    if m:
        peer_id = m.groups()[1]
        deficit = float(m.groups()[2])
        topic = m.groups()[3]
        if topic not in deliveries_deficits_per_topic:
            deliveries_deficits_per_topic[topic] = {}
        apply(deliveries_deficits_per_topic[topic], peer_id, deficit)
        apply(deliveries_deficits, peer_id, 1)
    return m

def ip_penalty(line):
    m = ip_penalty_pattern.search(line)
    if m:
        peer_id = m.groups()[1]
        surplus = int(m.groups()[3])
        apply(ip_penalties, peer_id, urplus)
    return m

def invalid_penalty(line):
    m = invalid_penalty_pattern.search(line)
    if m:
        peer_id = m.groups()[1]
        if peer_id not in invalid_penalties:
            invalid_penalties[peer_id] = 0
        invalid_penalties[peer_id] += 1
    return m

with open(save_dir + "/gossipsub_penalties", "r") as f:
    for line in f:
        line = line.rstrip()
        if not (behavioral_penalty(line) or deliveries_penalty(line) or ip_penalty(line) or invalid_penalty(line) or lighthouse_pattern.search(line)):
            print("Unknown log line: " + line)

identified_peer_pattern = re.compile(r"agent_version: ([^/,]*).*, peer: ([0-9a-zA-Z]*),")
clients = {}

def client(peer_id):
    if peer_id in clients:
        return clients[peer_id]
    else:
        "NotFound"

with open(save_dir + "/peer_identities", "r") as f:
    for line in f:
        line = line.rstrip()
        m = identified_peer_pattern.search(line)
        if m:
            clients[m.groups()[1]] = m.groups()[0]
        elif libp2p_pattern.search(line):
            # do nothing
            continue
        else:
            print("Unknown log line: " + line)

def per_client(d):
    result = {}
    for (peer_id, value) in d.items():
        c = client(peer_id)
        if c not in result:
            result[c] = 0
        result[c] += 1
    return result

client_counts = per_client(clients)

def statistic(d, name):
    print()
    print("Statistic for {}:".format(name))
    print("Number of affected peers: {} ({:.3%})".format(len(d), len(d)/len(clients)))
    pc = per_client(d) 
    print("Per Client: ")
    for (c, count) in pc.items():
        relative = 1.0
        if c in client_counts:
            relative =  count / client_counts[c]
        print("  {}: {} ({:.3%})".format(c, count, relative))


for (topic, d) in deliveries_deficits_per_topic.items():
    statistic(d, "mesh message deliveries deficits in topic " + topic)
statistic(deliveries_deficits, "overall mesh message deliveries deficits")
statistic(behavioral_penalties, "behavioral penalties")
statistic(ip_penalties, "IP penalties")
statistic(invalid_penalties, "invalid penalties")
statistic(clients, "Peer DB")s
