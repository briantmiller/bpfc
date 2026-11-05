# LEO SATCOM (Starlink-class pLEO): the terminal moves to another satellite
# about every 15 s, and capacity and delay change with it; a handover can
# lose a short burst of packets. RTT is short enough for ARQ to be the main
# repair, so FEC turns on when loss persists and stays on for two handovers.
# The link delivers in frames (about 1.33 ms on Starlink): two packets sent
# back to back usually leave in the same frame and read far too fast, so
# capacity is measured with 20 ms trains, timed from 10 % in, every 3 s and
# not slowed while FEC is on; the estimate is the median of the samples of
# the last 15 s, so it follows each satellite and never mixes in the last.
description = LEO satellite (100 Mbit/s, 60 ms RTT, 15 s handover)
link-rate = 100m
rtt = 60ms
fec-threshold = 1
fec-cooldown = 30s
report-interval = 250ms
congestion-delay = 50ms
arq-with-fec = keep
probe-interval = 3s
probe-backoff = 1
probe-train = 20ms
probe-train-max = 256
probe-train-skip = 10
capacity-percentile = 50
capacity-window = 15s
