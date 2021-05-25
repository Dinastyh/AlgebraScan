import threading
import subprocess


def threadPing(ipC):
    #Use ping of the computer
    res = subprocess.call(["ping","-c", "1",ipC], stdout=subprocess.PIPE)
    if not res: 
        print(ipC)

def icmpScan(ips):
    print("==========Result for ICMP Scan==========")

    #Using thread to make icmp faster -> other way is to use icmp of scapy

    for i in ips:
        th = threading.Thread(target=threadPing, args=(i,))
        th.start()