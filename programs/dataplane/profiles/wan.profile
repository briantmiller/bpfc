# Terrestrial WAN: MPLS, private WAN, metro Ethernet (L2 carrier for now;
# the UDP carriers come in a later step). ARQ is the main repair, FEC turns
# on under persistent loss and keeps ARQ for the last 50 ms of traffic.
description = Terrestrial WAN (MPLS, private WAN, metro Ethernet)
link-rate = 1g
rtt = 30ms
fec-threshold = 1
fec-cooldown = 10s
report-interval = 1000ms
congestion-delay = 30ms
arq-with-fec = 50ms
