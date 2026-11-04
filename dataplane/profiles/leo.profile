# LEO SATCOM (Starlink-class pLEO): the terminal moves to another satellite
# about every 15 s, and capacity and delay change with it; a handover can
# lose a short burst of packets. RTT is short enough for ARQ to be the main
# repair, so FEC turns on when loss persists and stays on for two handovers.
# Probes every 5 s, not slowed while FEC is on, and a 15 s capacity window
# make the estimate follow each satellite (the default 16-sample ring would
# still hold the last satellite's numbers a minute later).
description = LEO satellite (100 Mbit/s, 60 ms RTT, 15 s handover)
link-rate = 100m
rtt = 60ms
fec-threshold = 1
fec-cooldown = 30s
report-interval = 250ms
congestion-delay = 50ms
arq-with-fec = keep
probe-interval = 5s
probe-backoff = 1
capacity-window = 15s
