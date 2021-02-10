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


# Global variables
is_client = False # True = client, False = Server


# Handles SIGINT signal
def keyboard_interrupt_handler(signal, frame):
    print("\n[*] KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signal))
    exit(9)


# https://docs.python.org/3/library/ipaddress.html
# https://docs.python.org/3/howto/sockets.html
# Returns the interface of the local network of the machine in CIDR format (e.g 192.168.1.70/24)
def get_iface(verbose=False):
    # First, we get the IP of the host -> https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    if verbose: print('[v] Getting the IP of the machine')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        err = s.connect(('192.255.255.255', 1)) # Does not even have to be reachable
        if not err:
            ip = s.getsockname()[0]
            if verbose: print(' Got: ' + ip)
        else:
            err = s.connect(('172.255.255.255', 1))
            if not err:
                ip = s.getsockname()[0]
                if verbose: print(' Got: ' + ip)
            else:
                err = s.connect(('10.255.255.255', 1))
                ip = s.getsockname()[0]
                if verbose: print(' Got: ' + ip)
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
        print('[+] Host\'s IP: ' + str(ip))
    
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
    print('[+] Hosts network: ' + str(ret.network))
    return ret


# Creates a subprocess to ping the objective
def ping(ip):
    output = subprocess.Popen(['ping', '-n', '1', '-w', '1000', str(ip)], stdout=subprocess.PIPE).stdout.read() # Max 1 second delay
    if "100%" not in str(output): # There is no 100% loss rate -> host is alive
        return ip
    else:
        return None


# Scans the local network and returns a list of the hosts alive
def network_scanner_slow(ip, netmask, verbose=False): # 192.168.1.0, 24
    # Create the network
    net_ip = ipaddress.ip_network(str(str(ip) + '/' + str(netmask)))
    if verbose: print('[*] Scanning ' + str(net_ip) + '...')

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
def network_scanner_fast(ip, netmask, verbose=False): # 192.168.1.0, 24
    # Create the network
    net_ip = ipaddress.ip_network(str(str(ip) + '/' + str(netmask)))
    if verbose: print('[*] Scanning ' + str(net_ip) + '...')

    # Get all the hosts of the network
    hosts = list(net_ip.hosts())

    # FAST WAY -> https://www.edureka.co/community/31966/how-to-get-the-return-value-from-a-thread-using-python
    online_hosts = []
    threads = []
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
    
    return online_hosts


def main():
    # Register the signal handlers
    signal.signal(signal.SIGINT, keyboard_interrupt_handler)
        
    # Check the arguments
    my_description="""By default works in server mode, for client mode use -f argument""" # https://stackoverflow.com/questions/18106327/display-pydocs-description-as-part-of-argparse-help
    parser = argparse.ArgumentParser(prog='netdrop', description=my_description)
    parser.add_argument("-f", "--file", nargs='+', type=str, required=False, help="Client mode: Input file to share")
    args = parser.parse_args()
    files = args.file

    # Check if client or server
    if files:
        is_client = True
        # Client
        if is_client == True:
            # Check if the files exists and are readable
            for file in files:
                is_file_readable = os.path.isfile(file)
                if is_file_readable == False:
                    print('[-] netdrop: The input file ' + file + ' is not readable, quitting...')
                    exit(1)
            # Get the network info
            iface = get_iface()
            # Scan the network
            hosts = network_scanner_fast(str(iface.network).split('/')[0], str(iface.network).split('/')[1])
            print('[+] netdrop: Hosts found on the local network: ' + str(hosts))
            # Ask for a server (receiver of the file)
            server = ''
            myregex = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
            while not re.match(regex, server):
                server = input("[*] Enter the IP of the end machine: ")
            # Create process to send each file to the selected server
            # Ask for more files to send or exit (go to start of client: create function)
        # Server
    else:
        is_client = False
            # Wait for a connection
            # Ask the user for consentment
            # Receive the file

    return 0

if __name__ == "__main__":
    main()