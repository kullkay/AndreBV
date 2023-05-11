#!/usr/bin/env python3

import csv
import time
import subprocess
import struct
import sys
import socket
import multiprocessing

port='2345'

time_interval = 5
data=[	0,	#time_now,
	0,	#bytes_received,
	0,	#bytes_sent,
	0,	#count_client=0

]

sent = multiprocessing.Value('i', 0)
recv = multiprocessing.Value('i', 0)


	

def check_socket(clients_port): 		#my sniff that intercepts packets and if we raise port 2345 to listen, then we read the traffic
	global sent
	global recv
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
	recv.value=0
	sent.value=0

	while True:

		data, addr = sock.recvfrom(65535)
	

		eth_header = data[:14]
		ip_header = data[14:34]
		tcp_header = data[34:54]

		
		(src_ip, dst_ip) = struct.unpack('!4s4s', ip_header[12:20])
		(src_port, dst_port) = struct.unpack('!HH', tcp_header[0:4])

		packet_size = len(data)
		
		
		
		
		if src_port==2345 or dst_port==2345:
			lstening_ip_str=subprocess.run('ss -tr state listening \'( sport = :2345 )\' | awk \'{print $3}\' | grep -oE \'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\'', 					shell=True, capture_output=True).stdout.decode() 
			lstening_ip=lstening_ip_str.split()
			if len(lstening_ip)==0:
				continue
				
			host_ip_str=subprocess.run('ip addr | grep -Eo \'inet [0-9.]+\' | awk \'{print $2}\'', shell=True, capture_output=True).stdout.decode()
			host_ip=host_ip_str.split()
			
			if str(socket.inet_ntoa(dst_ip)) in host_ip and dst_port==2345:
				recv.value += packet_size
				continue
			
			if str(socket.inet_ntoa(src_ip)) in host_ip and src_port==2345:
				sent.value += packet_size
				continue
				 
				
			
		

		
			
		
	


	
def check_metricks(): 			#check_metrics the main function about collecting metrics collects the time and number of users. Starts a separate thread for the check_socket function until the end time of the period arrives
	data[0] = int(time.time())
	
	clients_port_str=subprocess.run('ss -tr state established \'( sport = :2345 )\' | awk -F\':\' \'{print $NF}\' | sed -n \'2,$p\'', shell=True, capture_output=True).stdout.decode()
	clients_port=clients_port_str.split()
	
	lstening_ip_str=subprocess.run('ss -tr state listening \'( sport = :2345 )\' | awk \'{print $3}\' | grep -oE \'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\'', 					shell=True, capture_output=True).stdout.decode()
	lstening_ip=lstening_ip_str.split()
	
	if len(lstening_ip)==0:		#if port 2345 is not raised, then we reset the number of users
		clients_port=''
	

	data[3]=len(clients_port)
	
		
	
	
	process = multiprocessing.Process(target=check_socket, args=(clients_port,))
	process.start()
	while True:
		now_time=time.time()
		if data[0]+time_interval<=now_time:
			break
	data[1]=recv.value
	data[2]=sent.value
	clients_port=0
	
	process.terminate()
	process.join()
	
	
	
	

def save_data(path_to_data):			#the function of saving to a FILE.csv
	with open(path_to_data, "a") as file:
		writer = csv.writer(file)
		writer.writerow(
		data
		)
		


	



def main(): 
	global time_interval
	global data
	args = sys.argv

	time_interval = int(args[1])
	path_to_data = args[2]
	
	while True:		
		check_metricks()
		save_data(path_to_data)	
		#print(data)
		data=[0,0,0,0,'']
		
		
		
	
	
if __name__ == "__main__":
	main()