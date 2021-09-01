<<<<<<< HEAD
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

import modules

# Global variables
verbose = False
is_client = False # True = client, False = Server


# Handles SIGINT signal
def keyboard_interrupt_handler(signal, frame):
	print("\n[*] KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signal))
	ok_join = modules.join_threads()
	if not ok_join:
		sys.exit(8)
	else:
		sys.exit(9)


# Handles a file send
def client(server, f):
	try:
		asyncio.get_event_loop().run_until_complete(modules.file_send(server, f))
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
	modules.filetransmission.verbose = verbose
	modules.networkutils.verbose = verbose

	# Get the network info
	iface = modules.get_iface()
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
			servers = modules.network_scanner_fast(str(iface.network).split('/')[0], str(iface.network).split('/')[1])
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
			start_server = websockets.serve(modules.file_download, str(iface.ip), 8765)
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
=======
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


# For everything
import os
import socket
import sys
import netifaces
import threading
# For the SSL stuff
import rsa
import pickle
import random
import string
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import time


# Globals
PORTDISCOVER = 30000
PORTACK = 30001
PORTDATA = 30001
BUFFSIZE = 4096
RSAKEYSIZE = 1024
arguments = { "verbose": False }
interfaceWithInternetConnection = None
keys = None


# Classes
class Client():
    def __init__(self):
        super().__init__()
        self.servers = []
        self.threads = []

        self.running = True
        t = threading.Thread(target=self.handle_broadcasts_ack)
        self.threads.append(t)
        t.start()

        self.discover_servers()
    
    def discover_servers(self):
        if arguments['verbose']: print("[+] Client: Sending broadcast DISCOVER packet on port '{0}'".format(PORTDISCOVER))
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.sendto("DISCOVER".encode(), (interfaceWithInternetConnection["broadcast"], PORTDISCOVER))
    
    def download_file(self, server):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, PORTDATA))

        # Generate the RSA key pair
        keys = generate_rsa_keys()

        # Send public key using pickle
        s.send(pickle.dumps(keys[0]))

        # Receive the aesKey, and decrypt it with the privateKey
        response = s.recv(1024)
        response = rsa.decrypt(response, keys[1])
        self.aesKey = response
        if arguments['verbose']: print("[*] Client: The AES key is {0}".format(self.aesKey))

        # Create the cipher
        cipher = AES.new(self.aesKey, AES.MODE_CFB, b'0'*AES.block_size)

        # Send the name of the file, if ok, receive the file
        if arguments['verbose']: print("[*] Client: Sending the filename")
        s.send(cipher.encrypt(arguments['new'].encode()))

        # Receive the file, and decrypt it with the aesKey
        self.receive(s)

    def handle_broadcasts_ack(self):
        if arguments['verbose']: print("[*] Client: Starting to listen for ACK packets from servers on port '{0}'".format(PORTACK))
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.bind((interfaceWithInternetConnection["addr"], PORTACK))
        while self.running:
            (data, addr) = self.sock.recvfrom(1024)
            if data.decode() == "DISCOVER ACK":
                if arguments['verbose']: print("[+] Client: Appending server '{0}' to the servers list".format(addr[0]))
                self.servers.append(addr[0])

                self.download_file(addr[0])
            
    def receive(self, conn):
        # Create the cipher
        cipher = AES.new(self.aesKey, AES.MODE_CFB, b'0'*AES.block_size)

        file = open(arguments['new'], 'wb')

        print("[+] Client: Downloading the file")
        buff = conn.recv(BUFFSIZE)
        start = time.time()
        while buff:
            buff = cipher.decrypt(buff)
            file.write(buff)
            buff = conn.recv(BUFFSIZE)
            if not buff:
                break

        end = time.time()
        size = round((os.path.getsize(arguments['new'])/1024)/1024, 4)
        try:
            print('[+] Server: Downloaded ' + str(size) + 'MB in ' + str(round(end - start, 4)) + ' seconds at ' + str(round(size / (end - start), 4)) + 'MB/s')
        except:
            pass

        file.close()
        self.stop()
        sys.exit()

    def stop(self):
        self.running = False
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.sendto(''.encode(), (interfaceWithInternetConnection["addr"], PORTACK))

class Server():
    def __init__(self):
        super().__init__()
        self.threads = []

        self.running = True
        t = threading.Thread(target=self.handle_broadcasts)
        self.threads.append(t)
        t.start()
        t = threading.Thread(target=self.handle_connections)
        self.threads.append(t)
        t.start()
    
    def handle_broadcasts(self):
        self.sockBroadcasts = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sockBroadcasts.bind((interfaceWithInternetConnection["addr"], PORTDISCOVER))

        if arguments['verbose']: print("[*] Server: Starting to listen for DISCOVER packets from clients on port '{0}'".format(PORTDISCOVER))
        while self.running:
            try:
                (data, addr) = self.sockBroadcasts.recvfrom(1024)
                if data.decode() == "DISCOVER":
                    if arguments['verbose']: print("[*] Server: Client '{0}' has found us".format(addr[0]))
                    self.sockBroadcasts.sendto("DISCOVER ACK".encode(), (addr[0], PORTACK))
            except Exception as e:
                print("[-] Error: handle_broadcasts error: {0}".format(e.__repr__()))
    
    def handle_connections(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((interfaceWithInternetConnection["addr"], PORTDATA))
        
        s.listen(4)

        while self.running:
            (conn, addr) = s.accept()
            threading.Thread(target=self.handle_connection, args=(conn, addr)).start()
    
    def handle_connection(self, conn, addr):
        while self.running:
            # Get the public key
            response = conn.recv(4096)

            # Check if no data
            if not response:
                break

            # Unpickle the key
            clientPublicKey = pickle.loads(response)

            # Check if the key really is a key
            if isinstance(clientPublicKey, rsa.PublicKey): # https://stuvel.eu/python-rsa-doc/reference.html#classes
                # Valid key
                if arguments['verbose']: print("[+] Server: Valid public key from client '{0}'".format(addr[0]))

                # Generate aesKey # https://stuvel.eu/python-rsa-doc/usage.html
                self.aesKey = ''.join((random.choice(string.ascii_uppercase) for x in range(16))).encode()

                # Create cipher
                cipher = AES.new(self.aesKey, AES.MODE_CFB, b'0'*AES.block_size)

                # Send aesKey, encrypted with the clientPublicKey
                response = rsa.encrypt(self.aesKey, clientPublicKey)
                conn.send(response)
                if arguments['verbose']: print("[*] Server: The AES key is {0}".format(self.aesKey))

                # Get the name of the file, if match, send the file
                if arguments['verbose']: print("[*] Server: Waiting for the filename")
                filename = conn.recv(1024)
                if cipher.decrypt(filename).decode() == arguments['file']:
                    # Send the file, encrypted with the aesKey
                    if arguments['verbose']: print("[+] Server: Correct filename")
                    self.send(conn)
                else:
                    print("[-] Server: Wrong filename, shutting down the connection")
                    conn.shutdown(socket.SHUT_WR) # https://stackoverflow.com/questions/27241804/sending-a-file-over-tcp-sockets-in-python
                    break

            else:
                # Invalid key
                if arguments['verbose']: print("[-] Server: Invalid public key from client '{0}'".format(addr[0]))
                break

    def send(self, conn):
        cipher = AES.new(self.aesKey, AES.MODE_CFB, b'0'*AES.block_size)

        size = round((os.path.getsize(arguments['file'])/1024)/1024, 4)
        file = open(arguments["file"], "rb")
        buff = file.read(BUFFSIZE)

        print("[+] Server: Sending the file")
        start = time.time()
        while buff:
            buff = cipher.encrypt(buff)
            conn.send(buff)

            buff = file.read(BUFFSIZE)

        end = time.time()
        print('[+] Server: Downloaded ' + str(size) + 'MB in ' + str(round(end - start, 4)) + ' seconds at ' + str(round(size / (end - start), 4)) + 'MB/s')

        conn.shutdown(socket.SHUT_WR) # https://stackoverflow.com/questions/27241804/sending-a-file-over-tcp-sockets-in-python

        file.close()

    def stop(self):
        self.running = False
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.sendto(''.encode(), (interfaceWithInternetConnection["addr"], PORTDISCOVER))
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        sock.connect((interfaceWithInternetConnection["addr"], PORTDATA))


# Functions
def directory_exists(directory):
    if os.path.isdir('./'+directory):
        return True
    return False

def file_exists(file):
    if os.path.isfile('./'+file):
        return True
    return False

def generate_rsa_keys():
    # Generate new RSA key pair # https://stuvel.eu/python-rsa-doc/usage.html#generating-keys
    if arguments['verbose']: print("[+] Generating RSA {} bits key pair".format(RSAKEYSIZE))
    return rsa.newkeys(RSAKEYSIZE) # (pubkey, privkey)

def get_ip_address():
    '''https://stackoverflow.com/questions/55296584/getting-127-0-1-1-instead-of-192-168-1-ip-ubuntu-python'''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def print_help_and_exit():
    print('''
NAME
        Netdrop - Transfer files the easy way
SYNOPSIS
        netdrop.py -f <FILE> [OPTIONS]
DESCRIPTION
        Transfers a file between hosts of the same subnet.
        
        Mandatory arguments:
        -f FILE
                File to transfer
        Optional arguments:
        -v      be more verbose
        -h      print this help and exit''')
    sys.exit(0)


# Main
if __name__ == '__main__':
    # Parse the arguments
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-h':
            print_help_and_exit()
        elif sys.argv[i] == '-v':
            arguments["verbose"] = True
            print("[*] Verbose mode")
            i +=1
        elif sys.argv[i] == '-f':
            if file_exists(sys.argv[i+1]):
                arguments.update({"file": sys.argv[i+1]})
                i += 2
            else:
                arguments.update({"new": sys.argv[i+1]})
                i += 2
        else:
            print("[-] Error: Not an argument nor an option: '" + sys.argv[i] + "'")
            i += 1
    
    # Check if file or directory where supplied
    if not "file" in arguments and not "new" in arguments:
        print_help_and_exit()

    # Get the IP of the interface with Internet connection
    interfaceWithInternetConnectionIP = get_ip_address()

    # Get the info about the interface with Internet connection
    found = False
    for interface in netifaces.interfaces():
        for key in netifaces.ifaddresses(interface).values(): # https://pypi.org/project/netifaces/
            if arguments['verbose']: print("[*] Checking if the following interface is the one with Internet connection: " + str(key))
            for interfaceInformationDictionary in key:
                if "addr" in interfaceInformationDictionary:
                    # If the IP is the same as the one found by the Google DNS query method, store the info
                    if interfaceInformationDictionary["addr"] == interfaceWithInternetConnectionIP:
                        interfaceWithInternetConnection = interfaceInformationDictionary
                        if arguments['verbose']: print("[+] Found the interface with Internet connection: " + str(interfaceWithInternetConnection))
                        # Set a flag to be able to break all the loops when the interface is found
                        found = True
                        break
            if found: break
        if found: break
    
    if not found:
        print("[-] Could not find the interface with Internet connection, aborting")
        sys.exit(1)
    
    # Check if the user receives or sends
    if "new" in arguments:
        if arguments['verbose']: print("[*] Receiving mode")
        user = Client()
    else:
        if arguments['verbose']: print("[*] Sending mode")
        user = Server()
    
    # If the user presses enter, exit
    #while True:
    if not input("[*] Press enter to stop the program\n"):  # i.e. enter key pressed
        user.stop()
>>>>>>> dev
