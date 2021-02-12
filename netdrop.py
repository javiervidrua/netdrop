'''
MIT License

Copyright (c) 2021 Javier Vidal Ruano

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

import argparse
import asyncio
import os
import re
import signal
import sys
from multiprocessing import Process

import websockets  # https://websockets.readthedocs.io/en/stable/intro.html#installation

import ndModules

# Global variables
verbose = False
is_client = False # True = client, False = Server


# Handles SIGINT signal
def keyboard_interrupt_handler(signal, frame):
	print("\n[*] KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signal))
	ok_join = ndModules.join_threads()
	if not ok_join:
		sys.exit(8)
	else:
		sys.exit(9)


# Handles a file send
def client(server, f):
	try:
		asyncio.get_event_loop().run_until_complete(ndModules.file_send(server, f))
	except Exception as e:
		if hasattr(e, 'message'):
			print('[-] client: Error sending the file in file_send: ' + str(e.message))
		else:
			print('[-] client: Error sending the file in file_send: ' + str(e))


def main():
	# Register the signal handlers
	signal.signal(signal.SIGINT, keyboard_interrupt_handler)

	# Check the arguments
	my_description="""By default works in server mode, for client mode use -f or --file arguments""" # https://stackoverflow.com/questions/18106327/display-pydocs-description-as-part-of-argparse-help
	parser = argparse.ArgumentParser(prog='netdrop', description=my_description, conflict_handler='resolve')
	parser.add_argument("-f", "--file", type=str, required=False, help="client mode: Input file to share")
	parser.add_argument('-v','--verbose', action='store_true', default=False, dest='verbose_input', required=False, help="verbose mode: Output more info") # If present, sets verbose_input to True
	args = parser.parse_args()
	file = args.file
	# Set the verbosity
	global verbose
	verbose = args.verbose_input
	ndModules.files.verbose = verbose
	ndModules.network.verbose = verbose
	ndModules.scanNetwork.verbose = verbose

	# Get the network info
	iface = ndModules.get_iface()
	print('[*] netdrop: Host\'s IP is ' + str(iface.ip))
	print('[*] netdrop: Host\'s network is ' + str(iface.network))

	# Check if client or server
	if file:
		# Client
		is_client = True
		# Check if the files exists and are readable
		is_file_readable = os.path.isfile(file)
		if is_file_readable == False:
			print('[-] netdrop: The input file ' + file + ' is not readable, quitting...')
			exit(1)
		# Scan the network
		try:
			servers = ndModules.network_scanner_fast(str(iface.network).split('/')[0], str(iface.network).split('/')[1])
		except Exception as e:
			if hasattr(e, 'message'):
				print('[-] netdrop: Exception caugth while scanning the network: ' + str(e.message))
			else:
				print('[-] netdrop: Exception caugth while scanning the network ' + str(e))
			sys.exit(7)
		print('[+] netdrop: Servers found on the local network: ' + str(servers))
		# Ask for a server (receiver of the file)
		server = ''
		regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$" # my_regex = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
		while not re.match(regex, server):
			server = input("[*] netdrop: Enter the IP of the end server: ")
		# Create a process to send the file
		p = Process(target=client, args=(str(server), str(file),))
		p.start()
		p.join()
		if verbose: print('[v] netdrop: File sent')
	else:
		# Server
		is_client = False
		# Start the server
		print('[+] netdrop: Listening for incoming connections...')
		try:
			start_server = websockets.serve(ndModules.file_download, str(iface.ip), 8765)
			asyncio.get_event_loop().run_until_complete(start_server)
			asyncio.get_event_loop().run_forever()
		except Exception as e:
			if hasattr(e, 'message'):
				print('[-] netdrop: Error downloading the file in file_download: ' + str(e.message))
			else:
				print('[-] netdrop: Error downloading the file in file_download: ' + str(e))

	return 0


if __name__ == "__main__":
	main()
