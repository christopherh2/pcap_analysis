'''
This program is the skeleton file for creating a pcap analyzer.
The process_pcap function will be edited for more functionality.
This version of the program only counts the number of packets in a given pcap file.
'''

# Import libraries
import argparse
import os
import sys
from scapy.utils import RawPcapReader

# Create a function to read the file name
def process_pcap(file_name):
    print("Opening {} ...".format(file_name))
    
    # Count packets using a loop
    count = 0
    for (pkt_data, pkt_metadata) in RawPcapReader(file_name):
        count += 1
    print('{} contains {} packets'.format(file_name, count))
    
# Code to run if script is run directly rather than imported
if __name__ == '__main__':
    # Create a parser that can be run in the command line
    parser = argparse.ArgumentParser(description='Pcap reader') 
    # Add a required long argument called pcap
    parser.add_argument('--pcap', metavar = '<pcap file name>',
                         help = 'pcap file to parse', required= True)
    
    # Execute the parse_args method on the parser object to get properties of the input arguments received at the cli
    args = parser.parse_args()
    # Retrieve the pcap argument passed in as it is the file name
    file_name = args.pcap
    
    # Check if the file exists 
    if not os.path.isfile(file_name):
        # If file does not exist abort the program
        print("{} does not exist".format(file_name))
        sys.exit(-1)
    
    # If the file exists run the process_pcap function
    process_pcap(file_name)
    sys.exit(0) # Exit with successfuly run code
