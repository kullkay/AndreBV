#!/usr/bin/env python3

import csv
import time
import subprocess
import struct
import sys


port='2345'
path_to_data ="/home/andrew/work/test/data.csv"
time_per = 5
data=[	0,	#time_now,
	0,	#bytes_received,
	0,	#bytes_sent,
	0,	#count_client=0
	''	#error
]
	

	
	
def read_pcap():	#function for reading the pacets.pcap file
	global sent 
	global recv 
	sent=0
	recv=0

	with open('pacets.pcap', 'rb') as f:
    
		header_file = f.read(24)			# global header
		

    
		while True:
			header = f.read(16)			# header packet
			if not header:
				break

      
			(_, _, incl_len, _) = struct.unpack('IIII', header)
			
			
			packet_data = f.read(incl_len)		
			
			eth_header = packet_data[:14]    
			ip_header = packet_data[14:34]	
			tcp_header = packet_data[34:54]
           
			src_mac = ':'.join(format(x, '02x') for x in eth_header[6:12])
			dst_mac = ':'.join(format(x, '02x') for x in eth_header[:6])

			(total_length,) = struct.unpack('!H', ip_header[2:4])
			
			(src_port,) = struct.unpack('!H', tcp_header[:2])
			(dst_port,) = struct.unpack('!H', tcp_header[2:4])
			
			pc_mac = find_mac_address()
			
			if src_mac in pc_mac:
				sent+=total_length
			if dst_mac in pc_mac:
				recv+=total_length
			if src_port == dst_port:
				data[4] = 'Warning: dst_port == src_port == 2345'
		data[1]=recv
		data[2]=sent
        	
        		
		
	
def find_mac_address():				# finds all the mac addresses of the host
	mac_address = subprocess.run('ip link show | awk \'$2 ~ /^[0-9]+:/ {print $2}\' ', shell=True, capture_output=True).stdout.decode()
	mac_address = mac_address.split()
	return(mac_address)


def catch_packet(time_per ):			# the main function of collecting metrics
	subprocess.run('sudo timeout 5 tcpdump tcp port 2345 -w pacets.pcap', shell=True, capture_output=True)	
	read_pcap()
	
	data[0] = int(time.time())
	
	buf_ip=subprocess.run('ss -tr state established \'( sport = :2345 )\' | awk \'{print $4}\'', shell=True, capture_output=True).stdout.decode()
	buf_ip=buf_ip.split()

	data[3]=len(buf_ip)-1






def save_data(path_to_data):			#the function of saving to a FILE.csv
	with open(path_to_data, "a") as file:
		writer = csv.writer(file)
		writer.writerow(
		data
		)
		


	



def main(): 
	global data
	args = sys.argv
	time_per = args[1]
	path_to_data = args[2]
	while True:		
		catch_packet(time_per)
		save_data(path_to_data)	
		#print(data)
		data=[0,0,0,0,'']
		
		
		
	
	
if __name__ == "__main__":
	main()