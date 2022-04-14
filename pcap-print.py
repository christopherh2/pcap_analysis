import argparse
import os
import sys
import pickle

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


from pcap_pkl import PktDirection

def analyze_pickle(input_file):

    packets_for_analysis = []
    
    with open(input_file, 'rb') as pickle_fd:
        client_ip_addr_port = pickle.load(pickle_fd)
        server_ip_addr_port = pickle.load(pickle_fd)
        packets_for_analysis = pickle.load(pickle_fd)

    # Print a header
    print('##################################################################')
    print('TCP session between client {} and server {}'.
          format(client_ip_addr_port, server_ip_addr_port))
    print('##################################################################')
        
    # Print format string
    fmt = ('[{ordnl:>5}]{ts:>10.6f}s {flag:<3s} seq={seq:<8d} '
           'ack={ack:<8d} len={len:<6d} win={win:<9d}')

    for pkt_data in packets_for_analysis:

        direction = pkt_data['direction']

        if direction == PktDirection.client_to_server:
            print('{}'.format('-->'), end='')
        else:
            print('{:>60}'.format('<--'), end='')

        print(fmt.format(ordnl = pkt_data['ordinal'],
                         ts = pkt_data['relative_timestamp'],
                         flag = pkt_data['tcp_flags'],
                         seq = pkt_data['seqno'],
                         ack = pkt_data['ackno'],
                         len = pkt_data['tcp_payload_len'],
                         win = pkt_data['window']))
                         

# Code to run if script is run directly
if __name__ == '__main__':
    # Create a parser that can be run in the command line
    parser = argparse.ArgumentParser(description='Pcap reader') 
    
    # Add a required long argument called pcap
    parser.add_argument('-i','--inputf', metavar = '<input file name>',
                         help = 'pickle file to parse')
    
    # Execute the parse_args method on the parser object to get properties of the input arguments received at the cli
    args = parser.parse_args()
    
    file_name = args.inputf
    if not os.path.isfile(file_name):
        # If file does not exist abort the program        
        print("{} does not exist".format(file_name))
        sys.exit(-1)
        
    # Arguments for pickle mode
    analyze_pickle(file_name)

    sys.exit(0)