import os
import sys
import pickle
import argparse

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib

from pcap_pkl import PktDirection

def analyze_pickle(pickle_file_in):
    packets_for_analysis = []
    
    with open(pickle_file_in, 'rb') as pickle_fd:
        client_ip_addr_port = pickle.load(pickle_fd)
        server_ip_addr_port = pickle.load(pickle_fd)
        packets_for_analysis = pickle.load(pickle_fd)

    # Plot the receive window size and ack number on the client side.
    client_pkts = []
    for pkt_data in packets_for_analysis:
        if pkt_data['direction'] == PktDirection.server_to_client:
            continue

        # Don't include the SYN packet
        if 'S' in pkt_data['tcp_flags']:
            continue

        client_pkts.append({'Time': pkt_data['relative_timestamp'],
                            'Client window size': pkt_data['window'],
                            'Client Ack No' : pkt_data['ackno']})

    df = pd.DataFrame(data=client_pkts)

    fig, ax1 = plt.subplots()
    ax2 = ax1.twinx()

    df.plot(x='Time', y='Client window size', color='r', ax=ax1)
    df.plot(x='Time', y='Client Ack No', color='b', ax=ax2)
    
    ax1.tick_params('y', colors='r')
    ax2.tick_params('y', colors='b')
    
    plt.xlabel('Time (ms)')
    
    plt.show()
    plt.close()

    
        




# Code to run if script is run directly rather than imported
if __name__ == '__main__':
    # Create a parser that can be run in the command line
    parser = argparse.ArgumentParser(description='Pcap reader') 
    # Add a required long argument called file name
    parser.add_argument('-i','--inputf', metavar = '<input file name>',
                         help = 'pickle file containing packet data', required= True)
                  
    # Execute the parse_args method on the parser object to get properties of the input arguments received at the cli
    args = parser.parse_args()
    # Retrieve the pcap argument passed in as it is the file name
    file_name = args.inputf

    # Check if the file exists 
    if not os.path.isfile(file_name):
        # If file does not exist abort the program
        print("{} does not exist".format(file_name))
        sys.exit(-1)
    
    # If the file exists run the process_pcap function
    analyze_pickle(file_name)
    sys.exit(0) # Exit with successfuly run code