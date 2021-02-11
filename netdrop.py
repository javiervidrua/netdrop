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

import socket
import ipaddress
import subprocess
import queue
from threading import Thread
import argparse
from xml.etree.ElementTree import fromstring
import asyncio
import websockets # https://websockets.readthedocs.io/en/stable/intro.html#installation
from multiprocessing import Process
import signal
from datetime import datetime
import time
import os
import re
import sys
import random


# Global variables
verbose = False
is_client = False # True = client, False = Server
threads = []


# Handles SIGINT signal
def keyboard_interrupt_handler(signal, frame):
    print("\n[*] KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signal))
    for t in threads:
        try:
            t.join()
        except:
            sys.exit(8)
    sys.exit(9)


# Returns a clean string
def clean_string(incoming_string):
    # If it starts with .\, we remove those chars
    if incoming_string[0:2] == ".\\":
        new_string = incoming_string[2:]
    else:
        new_string = incoming_string
    
    new_string = new_string.replace("!","")
    new_string = new_string.replace("@","")
    new_string = new_string.replace("#","")
    new_string = new_string.replace("$","")
    new_string = new_string.replace("%","")
    new_string = new_string.replace("^","")
    new_string = new_string.replace("&","and")
    new_string = new_string.replace("*","")
    new_string = new_string.replace("(","")
    new_string = new_string.replace(")","")
    new_string = new_string.replace("+","")
    new_string = new_string.replace("=","")
    new_string = new_string.replace("?","")
    new_string = new_string.replace("\'","")
    new_string = new_string.replace("\"","")
    new_string = new_string.replace("{","")
    new_string = new_string.replace("}","")
    new_string = new_string.replace("[","")
    new_string = new_string.replace("]","")
    new_string = new_string.replace("<","")
    new_string = new_string.replace(">","")
    new_string = new_string.replace("~","")
    new_string = new_string.replace("`","")
    new_string = new_string.replace(":","")
    new_string = new_string.replace(";","")
    new_string = new_string.replace("|","")
    new_string = new_string.replace("\\","")
    new_string = new_string.replace("/","")
    return new_string


# https://docs.python.org/3/library/ipaddress.html
# https://docs.python.org/3/howto/sockets.html
# Returns the interface of the local network of the machine in CIDR format (e.g 192.168.1.70/24)
def get_iface():
    # First, we get the IP of the host -> https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    if verbose: print('[v] get_iface: Getting the IP of the machine')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        err = s.connect(('192.255.255.255', 1)) # Does not even have to be reachable
        if not err:
            ip = s.getsockname()[0]
            if verbose: print('[v] get_iface: Got: ' + ip)
        else:
            err = s.connect(('172.255.255.255', 1))
            if not err:
                ip = s.getsockname()[0]
                if verbose: print('[v] get_iface: Got: ' + ip)
            else:
                err = s.connect(('10.255.255.255', 1))
                ip = s.getsockname()[0]
                if verbose: print('[v] get_iface: Got: ' + ip)
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
        print('[+] get_iface: Host\'s IP is ' + str(ip))
    
    # Second, we get the nics -> https://stackoverflow.com/questions/41420165/get-ipconfig-result-with-python-in-windows/41420850#41420850
    cmd = 'wmic.exe nicconfig where "IPEnabled  = True" get ipaddress,MACAddress,IPSubnet,DNSHostName,Caption,DefaultIPGateway /format:rawxml'
    xml_text = subprocess.check_output(cmd, creationflags=8)
    xml_root = fromstring(xml_text)

    nics = []
    keyslookup = {
        'DNSHostName' : 'hostname',
        'IPAddress' : 'ip',
        'IPSubnet' : '_mask',
        'Caption' : 'hardware',
        'MACAddress' : 'mac',
        'DefaultIPGateway' : 'gateway',
    }

    for nic in xml_root.findall("./RESULTS/CIM/INSTANCE") :
        # parse and store nic info
        n = {
            'hostname':'',
            'ip':[],
            '_mask':[],
            'hardware':'',
            'mac':'',
            'gateway':[],
        }
        for prop in nic :
            name = keyslookup[prop.attrib['NAME']]
            if prop.tag == 'PROPERTY':
                if len(prop):
                    for v in prop:
                        n[name] = v.text
            elif prop.tag == 'PROPERTY.ARRAY':
                for v in prop.findall("./VALUE.ARRAY/VALUE") :
                    n[name].append(v.text)
        nics.append(n)

        # creates python ipaddress objects from ips and masks
        for i in range(len(n['ip'])) :
            arg = '%s/%s'%(n['ip'][i],n['_mask'][i])
            if ':' in n['ip'][i] : n['ip'][i] = ipaddress.IPv6Interface(arg)
            else : n['ip'][i] = ipaddress.IPv4Interface(arg)
        del n['_mask']

    # Third, we find the nic with the IP of the host and the netmask
    for nic in nics:
        if nic['ip'] != None:
            for net in nic['ip']:
                if str(net).split('/')[0] == str(ip):
                    iface = net
                    break
    
    # Fourth, we create an object to obtain interface information
    ret = ipaddress.ip_interface(iface)
    print('[+] get_iface: Hosts network is ' + str(ret.network))
    return ret


# Creates a subprocess to ping the objective
def ping(ip):
    output = subprocess.Popen(['ping', '-n', '1', '-w', '1000', str(ip)], stdout=subprocess.PIPE).stdout.read() # Max 1 second delay
    if "100%" not in str(output): # There is no 100% loss rate -> host is alive
        return ip
    else:
        return None


# Scans the local network and returns a list of the hosts alive
def network_scanner_slow(ip, netmask): # 192.168.1.0, 24
    # Create the network
    net_ip = ipaddress.ip_network(str(str(ip) + '/' + str(netmask)))
    if verbose: print('[v] Scanning ' + str(net_ip) + '...')

    # Get all the hosts of the network
    hosts = list(net_ip.hosts())

    # Start scanning the network for hosts alive
    # SLOW WAY -> https://opentechguides.com/how-to/article/python/57/python-ping-subnet.html
    # Configure subprocess to hide the console window
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE

    # For each IP address in the subnet run the ping command with subprocess.popen interface
    online_hosts = []
    for i in range(len(hosts)):
        output = subprocess.Popen(['ping', '-n', '1', '-w', '250', str(hosts[i])], stdout=subprocess.PIPE, startupinfo=info).communicate()[0]
        if "100%" not in str(output):
            online_hosts.append(str(hosts[i]))
    
    return online_hosts


# Scans the local network and returns a list of the hosts alive
def network_scanner_fast(ip, netmask): # 192.168.1.0, 24
    # Create the network
    net_ip = ipaddress.ip_network(str(str(ip) + '/' + str(netmask)))
    if verbose: print('[v] Scanning ' + str(net_ip) + '...')

    # Get all the hosts of the network
    hosts = list(net_ip.hosts())

    # FAST WAY -> https://www.edureka.co/community/31966/how-to-get-the-return-value-from-a-thread-using-python
    online_hosts = []
    que = queue.Queue()
    for i in range(len(hosts)):
        t = Thread(target= lambda q, arg1: q.put(ping(arg1)), args=(que, str(hosts[i])))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    
    while not que.empty():
        result = que.get()
        if result != None:
            online_hosts.append(result)
    
    # Check the hosts that are running the service
    servers_available = []
    for host in online_hosts:
        if verbose: print('[v] network_scanner_fast: Checking the host ' + host)
        if asyncio.run(timeout(host)) == True:
            servers_available.append(host)
    
    return servers_available


# Timeout for discovering servers
async def timeout(server):
    ret = False
    try:
        await asyncio.wait_for(discover_server(server), timeout=0.25) # 0.25 seconds for the server to recv the send
    except asyncio.TimeoutError:
        ret = False
    else:
        ret = True
    finally:
        return ret # Stop the propagation of the Exception in case it occurs


# Discovers if a host is running the service
async def discover_server(server):
    uri = "ws://"+server+":8765"
    async with websockets.connect(uri) as websocket:
        if verbose: print('[v] discover_server: Sending DISCOVER to ' + str(server))
        await websocket.send('DISCOVER')


# Handles a file send
def client(server, f):
    try:
        asyncio.get_event_loop().run_until_complete(file_send(server, f))
    except Exception as e:
        if hasattr(e, 'message'):
            print('[-] client: Error sending the file in file_send: ' + str(e.message))
        else:
            print('[-] client: Error sending the file in file_send: ' + str(e))


# Sends a file to a server
async def file_send(server, f):
    uri = "ws://"+server+":8765"
    async with websockets.connect(uri) as websocket:
        # Send the name of the file
        if verbose: print('[v] file_send: Sending the filename')
        buff = str(f)
        await websocket.send(buff)
        # Listen for the NACK
        if verbose: print('[v] file_send: Waiting for the NACK')
        print('[+] file_send: Waiting for the server to accept the transmission')
        buff = await websocket.recv()
        try:
            assert buff == 'NACK'
        except AssertionError:
            print('[-] file_send: The server did not accept the file share, quitting...')
            exit(11)
        # Send the file (get the size and the starting time)
        size = round((os.path.getsize(f)/1024)/1024, 4)
        print('[+] send_file: File size is ' + str(size) + ' MB')
        start = time.time()
        print('[+] file_send: Sending the file ' + str(f))
        with open(f,'rb') as file:
            for line in file:
                await websocket.send(line)
        end = time.time()
        print('[*] file_send: Elapsed transmission time is ' + str(round(end - start, 4)) + ' seconds')
        print('[*] file_send: Transmission speed is ' + str(round(size / (end - start), 4)) + ' MB/s')
        # Send the FACK
        if verbose: print('[v] file_send: Sending the FACK and waiting for the EOT')
        buff = 'FACK'
        await websocket.send(buff)
        # Listen for the EOT
        buff = await websocket.recv()
        try:
            assert buff == 'EOT'
            if verbose: print('[v] file_send: Received EOT')
        except AssertionError:
            print('[-] file_send: The server did not respond with EOT, maybe the file transfer failed')
            return 12


# Handles a file download
async def file_download(websocket, path):
    # Wait for a connection

    buff = await websocket.recv()
    if buff != 'DISCOVER':
        filename = clean_string(str(buff))
        directory = os.path.join('.', 'netdrop-downloads')
        # Create the downloads directory if unexistent
        if not os.path.isdir(directory):
            os.makedirs(directory)
        # Check if file exists
        while os.path.isfile(os.path.join(directory, filename)): # While the filename already exists, generate a new one
            filename = str(random.randint(0,9)) + '-' + filename
        # Create the new filename inside the downloads directory
        write_file = os.path.join(directory, filename)

        # Ask the user for consentment
        print('[+] file_download: Received file "' + str(filename) + '" from ' + str(websocket.remote_address[0]) + ' on port ' + str(websocket.remote_address[1]))
        if 'yes' != input('[*] file_download: To allow the file transfer enter "yes": '):
            # Send EOT and quit
            if verbose: print('[v] file_download: Sending EOT to end the file transfer')
            buff = 'EOT'
            await websocket.send(buff)
        else:
            # Receive the file
            if verbose: print('[v] file_download: Sending NACK to start the file transfer')
            buff = 'NACK'
            await websocket.send(buff)

            # Listen for the file and the FACK
            if verbose: print('[v] file_download: Waiting for the file and the FACK')
            with open(write_file, "wb+") as file:
                buff = await websocket.recv()
                print('[+] file_download: The file transmission has started')
                start = time.time()
                while buff != 'FACK':
                    file.write(buff)
                    buff = await websocket.recv()
                end = time.time()
            try:
                size = round((os.path.getsize(write_file)/1024)/1024, 4)
                print('[*] file_download: Elapsed transmission time is ' + str(round(end - start, 4)) + ' seconds')
                print('[*] file_download: Transmission speed is ' + str(round(size / (end - start), 4)) + ' MB/s')
            except Exception as e:
                print('[-] file_download: Error while calculating time and speed of transmission')
                exit(13)
            
            # Sending the EOT
            if verbose: print('[v] file_download: File received, FACK received, sending EOT')
            buff = 'EOT'
            await websocket.send(buff)
            if verbose: print('[v] file_download: EOT sent')
            await websocket.wait_closed()
            print('[+] file_download: Done')
    else:
        if verbose: print('[v] file_download: DISCOVER received from ' + str(websocket.remote_address[0]))


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

    # Get the network info
    iface = get_iface()

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
            servers = network_scanner_fast(str(iface.network).split('/')[0], str(iface.network).split('/')[1])
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
            server = input("[*] Enter the IP of the end machine: ")
        # Create a process to send the file
        p = Process(target=client, args=(str(server), str(file),))
        p.start()
        p.join()
        if verbose: print('[v] netdrop: File sent')
    else:
        # Server
        is_client = False
        # Start the server
        print('[+] netdrop: Listening...')
        try:
            start_server = websockets.serve(file_download, str(iface.ip), 8765)
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