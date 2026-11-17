# GEO SATCOM: long RTT, so a retransmission arrives about one RTT late -
# about when TCP would resend anyway. FEC is the main repair and always on
# (floor 1:15, about 7 %), scaling to 1:4 with loss. ARQ stays as a backup
# for everything it still holds. Faster reports shorten the reaction time.
description = GEO satellite (20 Mbit/s, 800 ms RTT class)
link-rate = 20m
rtt = 800ms
fec-floor = 15
fec-k-min = 4
fec-k-max = 15
fec-threshold = 1
fec-cooldown = 30s
fec-timeout = 100ms
report-interval = 500ms
arq-with-fec = keep
congestion-delay = 150ms
probe-interval = 10s
probe-backoff = 3
