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
	''	#error
]

sent = multiprocessing.Value('i', 0)
recv = multiprocessing.Value('i', 0)
error = multiprocessing.Value('i', 0)

	

def check_socket(clients_port):
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

		(src_mac,) = struct.unpack('!6s', eth_header[6:12])
		(src_ip, dst_ip) = struct.unpack('!4s4s', ip_header[12:20])
		(src_port, dst_port) = struct.unpack('!HH', tcp_header[0:4])

		packet_size = len(data)
		if dst_port == src_port and src_port==2345:
			error.value=1
			continue	
			
		if dst_port == 2345 and str(src_port) in clients_port:
			recv.value += packet_size
			
			continue

		if src_port == 2345 and str(dst_port) in clients_port:
			sent.value += packet_size
			
			continue
			
		if src_port == 2345 and tcp_header[13] & 0x12 == 0x12:
			host_ip_str=subprocess.run('ip addr | grep -Eo \'inet [0-9.]+\' | awk \'{print $2}\'', shell=True, capture_output=True).stdout.decode()
			host_ip=host_ip_str.split()
			if str(socket.inet_ntoa(dst_ip)) in host_ip:
				continue
			
			sent.value += packet_size
			clients_port.append(str(dst_port))
			
			continue

		if dst_port == 2345 and tcp_header[13] & 0x02 == 0x02:
			host_ip_str=subprocess.run('ip addr | grep -Eo \'inet [0-9.]+\' | awk \'{print $2}\'', shell=True, capture_output=True).stdout.decode()
			host_ip=host_ip_str.split()
			if str(socket.inet_ntoa(src_ip)) in host_ip:
				continue
			recv.value += packet_size
			
			continue
			
		
	


	
def check_metricks():
	data[0] = int(time.time())
	
	clients_port_str=subprocess.run('ss -tr state established \'( sport = :2345 )\' | awk -F\':\' \'{print $NF}\' | sed -n \'2,$p\'', shell=True, capture_output=True).stdout.decode()
	clients_port=clients_port_str.split()
	
	data[3]=len(clients_port)
	
	
	
	process = multiprocessing.Process(target=check_socket, args=(clients_port,))
	process.start()
	while True:
		now_time=int(time.time())
		if data[0]+time_interval<=now_time:
			data[1]=recv.value
			data[2]=sent.value
			if error.value == 1:
				data[4]="Error src_port==dst_port==2345"
				error.value=0
			clients_port=0
			break
	
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
	args = sys.argv

    	time_interval = int(args[1])
	path_to_data = args[2]
	
	global data
	while True:		
		check_metricks()
		save_data(path_to_data)	
		#print(data)
		data=[0,0,0,0,'']
		
		
		
	
	
if __name__ == "__main__":
	main()
