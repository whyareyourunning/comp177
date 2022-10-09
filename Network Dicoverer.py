# from scapy.all import *
import scapy.all as scapy
import socket
import time

from scapy.config import conf

hostname = socket.gethostname()
Ipv4 = socket.gethostbyname( hostname )
print( "Interfaces: \n " + hostname + "\n" + "----\n" )


def scan(ip):
    conf.verb = 0
    arp_req = scapy.ARP( pdst=ip )
    broadcast = scapy.Ether( dst="ff:ff:ff:ff:ff:ff" )
    broadcast_arp_req = broadcast / arp_req
    
    answered_list = scapy.srp( broadcast_arp_req,timeout=1,verbose=False )[0]
    result = []
    for i in range( 0,len( answered_list ) ):
        client_dict = {"ip": answered_list[i][1].psrc,"mac": answered_list[i][1].hwsrc}
        result.append( client_dict )
    
    return result


def net_display( result ):
    print( "Interfaces:\n" )
    for i in result:
        print("IP: {}\t\t MAC: {}".format( i["ip"],i["mac"] ) )


scanner = scan( Ipv4 )

net_report = net_display( scanner )
