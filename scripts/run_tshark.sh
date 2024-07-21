#!/bin/bash

# Run tshark to read the capture file incrementally and output to CSV
tshark -r /data/capture-1-0.pcap -T fields -E separator=, -E quote=d -E occurrence=f \
-e frame.time_relative -e frame.len -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e udp.length \
-e tcp.srcport -e tcp.dstport -e tcp.flags -e icmp.type -e icmp.code \
-e eth.src -e eth.dst \
-e ip.ttl -e ip.proto -l > /data/live_traffic.csv