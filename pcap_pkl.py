# Import libraries
import argparse
import os
import sys
import pickle

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

# Create a packet direction class to determine the receiver of a packet
class PktDirection():
    not_defined = 0
    client_to_server = 1
    server_to_client = 2
    
# Create a function to read the file name
def process_pcap(file_name, client_add, server_add, output_file):
    print("Opening {} ...".format(file_name))
    
    # Can also use an argument to get the ip's
    #client = '192.168.1.137:57080'
    #server = '152.19.134.43:80'

    (client_ip, client_port) = client_add.split(':')
    (server_ip, server_port) = server_add.split(':')
    
    # Count packets and interesting packets using a loop
    count = 0
    interesting_pkt_count = 0
    
    # Specify sequence offsets  
    server_sequence_offset = None
    client_sequence_offset = None
    
    # List of interesting packets to be pickled
    # Each element of the list is a dictionary that contains the fields of interest from the packet
    packets_for_analysis =[]
    
    client_recv_window_scale = 0
    server_recv_window_scale = 0
    
    
    # Metadata contains timestamp data in unix time
    # Time resolution in us or ns
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
        
        # Create an instance of pktdirection class and set it to 0 
        # since packet direction is assumed to be unknown
        direction = PktDirection.not_defined
        
        # Check the actual direction of a packet
        if ip_pkt.src == client_ip:
            # Check if client port matches with port in the tcp packet
            if tcp_pkt.sport != int(client_port):
                continue
            # Check if destination ip matches with the server ip
            if ip_pkt.dst != server_ip:
                continue
            # Check if destination port is the server port
            if tcp_pkt.dport != int(server_port):
                continue
            # Only update direction if criteria is met
            direction = PktDirection.client_to_server
        
        # Repeat the process using opposite criteria for checking server to client
        elif ip_pkt.src == server_ip:
            if tcp_pkt.sport != int(server_port):
                continue
            if ip_pkt.dst != client_ip:
                continue
            if tcp_pkt.dport != int(client_port):
                continue
            # Update direction if criteria is met
            direction = PktDirection.server_to_client
        
        # Do not update the direction if match failed
        else:
            continue
        
        # Uninteresting source tcp port
        if (tcp_pkt.sport != int(server_port)) and \
            (tcp_pkt.sport != int(client_port)):
                continue
               
        if (tcp_pkt.dport != int(server_port)) and \
           (tcp_pkt.dport != int(client_port)):
            # Uninteresting destination TCP port
            continue
            
        interesting_pkt_count +=1 
        # Store the first packet's information
        if interesting_pkt_count == 1:
            first_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            first_pkt_timestamp_resolution = pkt_metadata.tsresol
            first_pkt_ordinal = count
        
        # Store the last packet's information
        last_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        last_pkt_timestamp_resolution = pkt_metadata.tsresol
        last_pkt_ordinal = count
        
        # Compute the time elapsed between current packet and first packet
        this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp
        
        if direction == PktDirection.client_to_server:
            if client_sequence_offset is None:
                client_sequence_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - client_sequence_offset
        
        else:
            assert direction == PktDirection.server_to_client
            if server_sequence_offset is None:
                server_sequence_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - server_sequence_offset
            
        # If tcp packet has ACK bit set then it has an ack number
        if 'A' not in str(tcp_pkt.flags):
            relative_offset_ack = 0
        else:
            # Find the ack offset 
            if direction == PktDirection.client_to_server:
                relative_offset_ack = tcp_pkt.ack - server_sequence_offset
            else:
                relative_offset_ack = tcp_pkt.ack - client_sequence_offset
        
        
        # Determine the TCP payload length. IP fragmentation will mess up this
        # logic, so first check that this is an unfragmented packet
        if (ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
            print('No support for fragmented IP packets')
            break
        
        # Payload length is ip packet length minus header length minus offset length
        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)
        
        # Look for 'window scale' tcp option if packet is syn or syn-ack
        if 'S' in str(tcp_pkt.flags):
            for (opt_name, opt_value) in tcp_pkt.options:
                if opt_name == 'WScale' :
                    # Check the direction
                    if direction == PktDirection.client_to_server:
                        client_recv_window_scale = opt_value
                    else:
                        server_recv_window_scale = opt_value
                    break
                    
        
        # Create a dictionary and populate it with data that we'll need in the
        # analysis phase.
        
        pkt_data = {}
        pkt_data['direction'] = direction
        pkt_data['ordinal'] = last_pkt_ordinal
        pkt_data['relative_timestamp'] = this_pkt_relative_timestamp / \
                                         pkt_metadata.tsresol
        pkt_data['tcp_flags'] = str(tcp_pkt.flags)
        pkt_data['seqno'] = relative_offset_seq
        pkt_data['ackno'] = relative_offset_ack
        pkt_data['tcp_payload_len'] = tcp_payload_len
        if direction == PktDirection.client_to_server:
            pkt_data['window'] = tcp_pkt.window << client_recv_window_scale
        else:
            pkt_data['window'] = tcp_pkt.window << server_recv_window_scale

        packets_for_analysis.append(pkt_data)

        
    # Print useful information
    print('{} contains {} packets ({} interesting packets)'.
            format(file_name, count, interesting_pkt_count))
    
    print('First packet in connection: Packet #{} {}'.
          format(first_pkt_ordinal,
                 printable_timestamp(first_pkt_timestamp,
                                     first_pkt_timestamp_resolution)))
    print(' Last packet in connection: Packet #{} {}'.
          format(last_pkt_ordinal,
                 printable_timestamp(last_pkt_timestamp,
                                     last_pkt_timestamp_resolution)))
    
    # Dump the packet data into a pickle file
    print('Writing pickle file {}...'.format(output_file), end='')
    with open(output_file, 'wb') as pickle_fd:
        pickle.dump(client_add, pickle_fd)
        pickle.dump(server_add, pickle_fd)
        pickle.dump(packets_for_analysis, pickle_fd)
    print('done.')

import time
# Function to get the timestamp
def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    return '{}.{}'.format(ts_sec_str, ts_subsec)
    
    
# Code to run if script is run directly rather than imported
if __name__ == '__main__':
    # Create a parser that can be run in the command line
    parser = argparse.ArgumentParser(description='Pcap reader') 
    
    # Add a required long argument called pcap
    parser.add_argument('--pcap', metavar = '<pcap file name>',
                         help = 'pcap file to parse')
    
    parser.add_argument('--client', metavar = '<client address>',
                         help = 'client address without quotations')
     
    parser.add_argument('--server', metavar = '<server address>',
                         help = 'server address without quotations')
    
    parser.add_argument('--output', metavar ='<output file>',
                        help = 'output file name')
    
    parser.add_argument('-i','--inputf', metavar='<input pickle file>',
                        help ='input file name')
    # Execute the parse_args method on the parser object to get properties of the input arguments received at the cli
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        # If file does not exist abort the program        
        print("{} does not exist".format(file_name))
        sys.exit(-1)
        
    # Arguments for pickle mode
    client_add = args.client
    server_add = args.server
    output_file = args.output
    process_pcap(file_name, client_add, server_add, output_file)

    sys.exit(0)
   