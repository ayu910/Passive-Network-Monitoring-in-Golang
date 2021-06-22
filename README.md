# Passive-Network-Monitoring-in-Golang

The code monitors the network traffic as man-on-the-side and performs two tasks:
  1. DNS poison - Poisons the DNS server by listening for dns requests and spoofing a response
  2. DNS detect - Detects if a DNS response is poisoned by monitoring the network traffic and checking number of responses recieved in the last 60 seconds.
