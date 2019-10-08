#!/usr/bin/env python
import argparse, sys, socket, random, struct, time

from scapy.all import sendp, send, get_if_list, get_if_list, get_if_hwaddr, hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, IPv6, UDP, TCP 

def get_if():
    iface=None 
    for i in get_if_list():
        # find hx-eth0
        if "eth0" in i:
            iface=i;
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser(description="Scapy sender program template")
    parser.add_argument('-v', type=int, help="Specify using (4)IPv4/(6)IPv6.", default=4)
    parser.add_argument('--intf', type=str, help="Specify interface.", default="eth0")
    parser.add_argument('--dip', type=str, help="The destination IP address.", default="255.255.255.255")
    parser.add_argument('--l4', type=str, help="Specify using TCP or UDP.", default="tcp")
    # parser.add_argument('--loop', type=int, help="Number of loop.", default=0)
    # parser.add_argument('--msg', type=str, help="The message which will send to dst.",default="Hello World")
    parser.add_argument('--dport', type=int, help="TCP/UDP destination port.", default=1234)
    parser.add_argument('--sport', type=int, help="TCP/UDP source port.", default=random.randint(49152,65535))

    # parse
    args = parser.parse_args()
    # parser.print_help()

    # get value from args
    ipv = args.v 
    addr = socket.gethostbyname(args.dip)
    iface = args.intf #get_if()
    dip = args.dip
    l4flag = args.l4 
    dport = args.dport
    sport = args.sport

    # print all 
    print("IP version: IPv", ipv)
    print("Destination IP address: ", dip)
    print("Interface: ", iface)
    print("Layer 4: ", l4flag)
    print("Desintation Port number: ", dport)
    print("Source Port number: ", sport)

    # start to pack
    if ipv is 4:
        print "sending on interface {} to IP addr {}".format(iface, str(addr))
        # for x in range(0, args.loop):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        if l4flag is 'tcp':
            pkt = pkt / IP(dst=addr) / TCP(dport=dport, sport=sport) / "Scapy Template"
        else:
            pkt = pkt / IP(dst=addr) / UDP(dport=dport, sport=sport) / "Scapy Template"
        # show
        pkt.show2()
        # send 
        sendp(pkt, iface=iface, verbose=True)
        # sleep 
        time.sleep(1)
    elif ipv is 6:
        print "sending on interface {} to IPv6 addr {}".format(iface, str(addr))
        #for x in range(0, args.loop):
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IPv6(dst=addr) / TCP(dport=dport, sport=sport) / "Scapy Template"
        # show
        pkt.show2()
        # send 
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()