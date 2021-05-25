import socket
import time
import threading
import subprocess
data = []

def threadPing(ipC):
    res = subprocess.call(["ping","-c", "1",ipC], stdout=subprocess.PIPE)
    if not res: 
        print(ipC)

def icmpScan(ips):
    print("==========Result for ICMP Scan==========")

    for i in ips:
        th = threading.Thread(target=threadPing, args=(i,))
        th.start()