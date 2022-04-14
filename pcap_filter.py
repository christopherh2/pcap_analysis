# Import libraries
import argparse
import os
import sys

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

# Create a function to read the file name
def process_pcap(file_name, client_add, server_add):
    print("Opening {} ...".format(file_name))
    
    # Can also use an argument to get the ip's
    #client = '192.168.1.137:57080'
    #server = '152.19.134.43:80'

    (client_ip, client_port) = client_add.split(':')
    (server_ip, server_port) = server_add.split(':')
    
    # Count packets and interesting packets using a loop
    count = 0
    interesting_pkt_count = 0
    
    for (pkt_data, pkt_metadata) in RawPcapReader(file_name):
        count += 1
        
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue
        
        # Get the ipv4 header
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue
       
        if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
            # Uninteresting source IP address
            continue
        
        # Uninteresting destination ip
        if (ip_pkt.dst != server_ip) and (ip_pkt.dst != client_ip):
            continue
        
        # Get the tcp packet from the ip packet
        tcp_pkt = ip_pkt[TCP]
        
        # Uninteresting source tcp port
        if (tcp_pkt.sport != int(server_port)) and \
            (tcp_pkt.sport != int(client_port)):
                continue
               
        if (tcp_pkt.dport != int(server_port)) and \
           (tcp_pkt.dport != int(client_port)):
            # Uninteresting destination TCP port
            continue
            
        interesting_pkt_count +=1 
    print('{} contains {} packets ({} interesting packets)'.format(file_name, count, interesting_pkt_count))
    
    
    
# Code to run if script is run directly rather than imported
if __name__ == '__main__':
    # Create a parser that can be run in the command line
    parser = argparse.ArgumentParser(description='Pcap reader') 
    # Add a required long argument called pcap
    parser.add_argument('--pcap', metavar = '<pcap file name>',
                         help = 'pcap file to parse', required= True)
    
    parser.add_argument('--client', metavar = '<client address>',
                         help = 'client address without quotations', required= True)
     
    parser.add_argument('--server', metavar = '<server address>',
                         help = 'server address without quotations', required= True)
                  
    # Execute the parse_args method on the parser object to get properties of the input arguments received at the cli
    args = parser.parse_args()
    # Retrieve the pcap argument passed in as it is the file name
    file_name = args.pcap
    client_add = args.client
    server_add = args.server
    
    # Check if the file exists 
    if not os.path.isfile(file_name):
        # If file does not exist abort the program
        print("{} does not exist".format(file_name))
        sys.exit(-1)
    
    # If the file exists run the process_pcap function
    process_pcap(file_name, client_add, server_add)
    sys.exit(0) # Exit with successfuly run code