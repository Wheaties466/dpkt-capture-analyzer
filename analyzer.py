#!/usr/bin/env python
"""
This supports python2.7 should also work on python2.6
The only dependency needed should be dpkt which can be installed with
for py2.7
pip install dpkt
for py2.6
pip install dpkt==1.8.8
"""
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord
from collections import Counter
import sys

sess_index = []
sess_index_dip = []

def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)



def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def print_packets(pcap):

    for timestamp, buf in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        #print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data
        if isinstance(ip.data, dpkt.icmp.ICMP):
            continue

        tcp = ip.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        sess_index.append(inet_to_str(ip.src) + ':' + str(tcp.sport))
        sess_index_dip.append(inet_to_str(ip.dst) + ':' + str(tcp.dport))
    sip = Counter(sess_index).most_common(5)
    dip = Counter(sess_index_dip).most_common(5)
    print "5 most common source IPs in capture"
    print sip
    print "5 most common dest IPs in capture"
    print dip
    print "Total number of packets in capture: " + str(len(sess_index))

def test():
    """Open up a test pcap file and print out the packets"""
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)



if __name__ == '__main__':
    test()
