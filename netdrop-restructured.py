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


import os
import socket
import sys
import netifaces
import threading
import time
import signal
import hashlib
from Crypto import Random
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA


# Constants
portBroadcast = 30000
portSinglecast = 30001


# Global variables
arguments = { "verbose": False }
interfaceWithInternetConnection = ''
serversNetwork = []
serversLocal = []
random = None
RSAkey = None
public = None
private = None
tmpPub = None
myHashPublic = None


# Functions
def directory_exists(directory):
    if os.path.isdir('./'+directory):
        return True
    return False

def download():
    for server in serversNetwork:
        check = False
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect((server, portSinglecast))
            check = True
        except BaseException:
            print("[-] Error: Error connecting to {0}. Skipping".format(server))
            continue
        
        if check is True:
            print("[*] Connection successful with the server: {0}".format(server))
            server.send(public + ":" + myHashPublic)
            # Receive server public key,hash of public,eight byte and hash of eight byte
            fGet = server.recv(4072)
            split = fGet.split(":")
            toDecrypt = split[0]
            serverPublic = split[1]
            print("[*] Server's public key: {0}".format(serverPublic))
            decrypted = RSA.importKey(private).decrypt(eval(toDecrypt.replace("\r\n", '')))
            splittedDecrypt = decrypted.split(":")
            eightByte = splittedDecrypt[0]
            hashOfEight = splittedDecrypt[1]
            hashOfPublic = splittedDecrypt[2]
            print("[*] Client's eight byte key in hash: {0}".format(hashOfEight))

            # Hashing for checking
            sess = hashlib.md5(eightByte)
            session = sess.hexdigest()

            hashObj = hashlib.md5(serverPublic)
            server_public_hash = hashObj.hexdigest()
            print("[*] Matching server's public key & eight byte key")
            if server_public_hash == hashOfPublic and session == hashOfEight:
                # Encrypt back the eight byte key with the server public key and send it
                print("[+] Sending encrypted session key")
                serverPublic = RSA.importKey(serverPublic).encrypt(eightByte, None)
                server.send(str(serverPublic))
                # Creating 128 bits key with 16 bytes
                print("[*] Creating AES key")
                key_128 = eightByte + eightByte[::-1]
                AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
                # Receiving ready
                serverMsg = server.recv(2048)
                serverMsg = remove_padding(AESKey.decrypt(serverMsg))
                if serverMsg == "READY":
                    print("[*] Server is ready to communicate")
                    server.send(AESKey.encrypt(padding(arguments["new"])))
                    dataEncrypted = server.recv(2048)
                    dataDecrypted = remove_padding(AESKey.decrypt(dataEncrypted))
                    if dataDecrypted.decode() == "ACK":
                        msg = AESKey.encrypt(padding("ACK"))
                        server.send(msg)
                        with open(arguments["new"], 'wb') as f:
                            while dataEncrypted := server.recv(2048):
                                f.write(remove_padding(AESKey.decrypt(dataEncrypted)))
            else:
                print("[-] Server (Public key && Public key hash) || (Session key && Hash of Session key) doesn't match")

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

def padding(s):
    return s + ((16 - len(s) % 16) * '`')

def remove_padding(s):
    return s.replace('`','')

def send_file(client, key):
    if arguments["file"]:
        with open(arguments["file"], 'rb') as f:
            while dataDecrypted := f.read(2048):
                client.send(key.encrypt(dataDecrypted))
    elif arguments["directory"]:
        print("sending directory")

def stop_servers():
    for server in serversLocal:
        server.stop()

    sys.exit(0)

def upload(client, address):
    while True:
        print("[*] One client is trying to connect: {0}".format(client))
        # Get client public key and the hash of it
        clientPH = client.recv(2048)
        split = clientPH.split(":")
        tmpClientPublic = split[0]
        clientPublicHash = split[1]
        print("[*] Anonymous client's public key: {0}".format(tmpClientPublic))
        tmpClientPublic = tmpClientPublic.replace("\r\n", '')
        clientPublicHash = clientPublicHash.replace("\r\n", '')
        tmpHashObject = hashlib.md5(tmpClientPublic)
        tmpHash = tmpHashObject.hexdigest()

        if tmpHash == clientPublicHash:
            # sending public key,encrypted eight byte ,hash of eight byte and server public key hash
            print("[*] Anonymous client's public key and public key hash matched")
            clientPublic = RSA.importKey(tmpClientPublic)
            eightByte = os.urandom(8)
            sess = hashlib.md5(eightByte)
            session = sess.hexdigest()
            fSend = eightByte + ":" + session + ":" + myHashPublic
            fSend = clientPublic.encrypt(fSend, None)
            client.send(str(fSend) + ":" + public)

            clientPH = client.recv(2048)
            if clientPH != "":
                clientPH = RSA.importKey(private).decrypt(eval(clientPH.decode('utf-8')))
                print("[*] Matching session key")
                if clientPH == eightByte:
                    # creating 128 bits key with 16 bytes
                    print("[+] Creating AES key")
                    key_128 = eightByte + eightByte[::-1]
                    AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
                    clientMsg = AESKey.encrypt(padding("READY"))
                    client.send(clientMsg)

                    print("[*] Waiting for client's filename")
                    clientMsg = client.recv(2048)
                    # If the filename is correct
                    if remove_padding(AESKey.decrypt(clientMsg)) == arguments["file"] or remove_padding(AESKey.decrypt(clientMsg)) == arguments["directory"]:
                        print("filename correct")
                        client.send(AESKey.encrypt(padding("ACK")))
                        clientMsg = client.recv(2048)
                        if remove_padding(AESKey.decrypt(clientMsg)) == "ACK":
                            threading_client = threading.Thread(target=send_file,args=[client,AESKey])
                            threading_client.start()
                else:
                    print("\nSession key from client does not match", color="red", underline=True)
        else:
            print("\nPublic key and public hash doesn't match", color="red", underline=True)
            client.close()


# Classes
class ServerBroadcast(threading.Thread): # https://stackoverflow.com/questions/28201667/killing-or-stopping-an-active-thread
    def __init__(self):
        self.running = False
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.bind((interfaceWithInternetConnection["addr"], portBroadcast))
        super(ServerBroadcast, self).__init__()

    def start(self):
        self.running = True
        super(ServerBroadcast, self).start()

    def run(self):
        while self.running:
            (data, addr) = self.sock.recvfrom(1024)
            if arguments['verbose']: print("[+] Message: '{0}' from client: '{1}'".format(data.decode(), addr))
            if (data.decode() == "DISCOVER"):
                self.sock.sendto("ACK".encode(), (addr[0], portBroadcast))
                if arguments['verbose']: print("[*] ACK sent to client")
            if (data.decode() == "ACK"):
                serversNetwork.append(addr[0])
                if arguments['verbose']: print("[*] Got ACK from {0}, adding it to the servers list".format(addr[0]))

    def stop(self):
        self.running = False
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.sendto("".encode(), (interfaceWithInternetConnection["addr"], portBroadcast))

class ServerSinglecast(threading.Thread): # https://stackoverflow.com/questions/28201667/killing-or-stopping-an-active-thread
    def __init__(self):
        self.running = False
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sock.bind((interfaceWithInternetConnection["addr"], portSinglecast))
        super(ServerSinglecast, self).__init__()

    def start(self):
        self.running = True
        super(ServerSinglecast, self).start()

    def run(self):
        while self.running:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((interfaceWithInternetConnection["addr"], portSinglecast))
            server.listen(1)
            while True:
                client, address = server.accept()
                threading_accept = threading.Thread(target=upload, args=(client, address))
                threading_accept.start()

    def stop(self):
        self.running = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((interfaceWithInternetConnection["addr"], 30001))
        sock.send(''.encode())


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
    
    # Create RSA keys
    random = Random.new().read
    RSAkey = RSA.generate(1024, random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()
    tmpPub = hashlib.md5(public)
    myHashPublic = tmpPub.hexdigest()

    # Check if the user receives or sends
    if "new" in arguments:
        if arguments['verbose']: print("[*] Receiving mode")
        if arguments['verbose']: print("[+] Sending broadcast packet")
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.sendto("DISCOVER".encode(), (interfaceWithInternetConnection["broadcast"], portBroadcast))
        download()
    else:
        if arguments['verbose']: print("[*] Sending mode")

        signal.signal(signal.SIGINT, stop_servers)
        
        # Start the listening servers
        serverBroadcast = ServerBroadcast()
        serversLocal.append(serverBroadcast)
        serverBroadcast.start()
        serverSinglecast = ServerSinglecast()
        serversLocal.append(serverSinglecast)
        serverSinglecast.start()
        
    # Wait to finish the server execution
    while True:
        if not input("[+] Press enter to stop the program\n"):  # i.e. enter key pressed
            break
    
    stop_servers()
