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
from os.path import expanduser
from OpenSSL import crypto
import ssl


# Globals
PORTDISCOVER = 30000
PORTACK = 30001
PORTDATA = 30001
arguments = { "verbose": False }
interfaceWithInternetConnection = None


# Classes
class Client():
    def __init__(self):
        super().__init__()
        self.servers = []
        self.threads = []
        self.lock = threading.Lock()

        self.running = True
        t = threading.Thread(target=self.handle_broadcasts_ack)
        self.threads.append(t)
        t.start()

        self.lock.acquire()
        self.discover_servers()

        self.find_file_server()
    
    def discover_servers(self):
        if arguments['verbose']: print("[+] Client: Sending broadcast DISCOVER packet on port '{0}'".format(PORTDISCOVER))
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.sendto("DISCOVER".encode(), (interfaceWithInternetConnection["broadcast"], PORTDISCOVER))
    
    def find_file_server(self):
        self.lock.acquire()
        # For each server that answered the DISCOVER, ask for the file
        for server in self.servers:
            try:
                #self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #self.sock.connect((server, PORTDATA))
                context = ssl.SSLContext()
                self.sock = context.wrap_socket(socket.socket(socket.AF_INET))
                self.sock.connect((server, PORTDATA))
                check = True
            except BaseException:
                if arguments['verbose']: print("[-] Error: connect: Error connecting to the server '{0}' on port '{1}'".format(server, PORTDATA))

            if check is True:
                if arguments['verbose']: print("[*] Connected to the server {0} on port {1}".format(server, PORTDATA))
                self.sock.send("HELLO".encode())
                response = self.sock.recv(4096)
                if arguments['verbose']: print("[*] Server response: '{0}'".format(response.decode()))

            # send HELLO
            # recv ACK

    def handle_broadcasts_ack(self):
        if arguments['verbose']: print("[*] Client: Starting to listen for ACK packets from servers on port '{0}'".format(PORTACK))
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.bind((interfaceWithInternetConnection["addr"], PORTACK))
        while self.running:
            (data, addr) = self.sock.recvfrom(1024)
            if data.decode() == "ACK":
                if arguments['verbose']: print("[+] Client: Appending server '{0}' to the servers list".format(addr[0]))
                self.servers.append(addr[0])
                self.lock.release()
            
    def stop(self):
        self.running = False
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.sendto(''.encode(), (interfaceWithInternetConnection["addr"], PORTACK))

class Server():
    def __init__(self):
        super().__init__()
        self.threads = []
        self.home = os.path.join(expanduser("~"), ".netdrop")
        self.certFile = os.path.join(self.home, "certificate.pem")
        self.keyFile = os.path.join(self.home, "key.pem")
        self.generateSelfSignedCertificate()

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
                    self.sockBroadcasts.sendto("ACK".encode(), (addr[0], PORTACK))
            except Exception as e:
                print("[-] Error: handle_broadcasts error: {0}".format(e.__repr__()))
    
    def handle_connections(self):
        #self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #self.sock.bind((interfaceWithInternetConnection["addr"], PORTDATA))
        #if arguments['verbose']: print("[*] Server: Starting to listen for DATA packets from clients on port '{0}'".format(PORTDATA))
        #self.sock.listen(4)
        #
        #while self.running:
        #    (conn, addr) = self.sock.accept()
        #    # https://carlo-hamalainen.net/2013/01/24/python-ssl-socket-echo-test-with-self-signed-certificate/
        #    #connstream = ssl.wrap_socket(conn, server_side=True, certfile=os.path.join(self.home, ".netdrop" ,"selfsigned.crt"), keyfile=os.path.join(self.home, ".netdrop" ,"private.key"), ssl.PROTOCOL_SSLv23)
        #    t = threading.Thread(target=self.handle_connection, args=(conn, addr))
        #    self.threads.append(t)
        #    t.start()
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.certFile, keyfile=self.keyFile)

        bindsocket = socket.socket()
        bindsocket.bind((interfaceWithInternetConnection["addr"], PORTDATA))
        bindsocket.listen(5)

        while True:
            newsocket, fromaddr = bindsocket.accept()
            connstream = context.wrap_socket(newsocket, server_side=True)
            try:
                t = threading.Thread(target=self.handle_connection, args=(connstream, fromaddr))
                self.threads.append(t)
                t.start()
            finally:
                connstream.shutdown(socket.SHUT_RDWR)
                connstream.close()
        
        # https://pythontic.com/ssl/sslsocket/introduction
        # Improve the above with the info of the link
    
    def handle_connection(self, conn, addr):
        while self.running:
            response = conn.recv(4096)
            print("[*] Client packet: '{0}'".format(response.decode()))
            conn.send("ACK".encode())
        
    def generateSelfSignedCertificate(self):
        # Write to files
        if not os.path.isdir(self.home):
            os.mkdir(self.home)
        
        if not os.path.isfile(self.keyFile) and not os.path.isfile(self.certFile):
            key = crypto.PKey()
            with open(self.keyFile, "wb") as f:
                key.generate_key(crypto.TYPE_RSA, 4096)
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            
            with open(self.certFile, "wb") as f:
                cert = crypto.X509()
                cert.get_subject().CN = '127.0.0.1'
                cert.get_subject().C = 'ES'
                cert.get_subject().ST = 'ES'
                cert.get_subject().L = 'ES'
                cert.get_subject().O = 'ES'
                cert.get_subject().OU = 'ES'
                cert.set_serial_number(1000)
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(315360000)
                cert.set_issuer(cert.get_subject())
                cert.set_pubkey(key)
                cert.sign(key, "sha256")
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

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
        netdrop.py -f <FILE/DIRECTORY> [OPTIONS]
DESCRIPTION
        Transfers a file or a directory between hosts of the same subnet.
        
        Mandatory arguments:
        -f FILE/DIRECTORY
                File or directory to transfer
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
            elif directory_exists(sys.argv[i+1]):
                arguments.update({"directory": sys.argv[i+1]})
                i += 2
            else:
                arguments.update({"new": sys.argv[i+1]})
                i += 2
        else:
            print("[-] Error: Not an argument nor an option: '" + sys.argv[i] + "'")
            i += 1
    
    # Check if file or directory where supplied
    if not "file" in arguments and not "directory" in arguments and not "new" in arguments:
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
    while True:
        if not input("[+] Press enter to stop the program\n"):  # i.e. enter key pressed
            break
    
    user.stop()