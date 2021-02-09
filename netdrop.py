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


# Global variables
p_server = Process
p_client = Process


# Handles SIGINT signal
def keyboardInterruptHandler(signal, frame):
    print("KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signal))
    p_server.join()
    p_client.join()
    exit(0)


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


# Server and client functions https://stackoverflow.com/questions/44029765/python-socket-connection-between-windows-and-linux


# Server loop
async def server_loop(websocket, path):
    # Listen for the name of the file
    print('[+] server_loop: Waiting for the filename')
    buff = await websocket.recv()
    filename = str(datetime.now().time()).split('.')[1] + str(buff)
    file = open(filename, "wb+")

    # Send NACK
    print('[+] server_loop: Filename received, sending NACK')
    buff = 'NACK'
    await websocket.send(buff)

    # Listen for the file and the FACK
    print('[+] server_loop: Waiting for the file')
    buff = await websocket.recv()
    while buff != 'FACK':
        file.write(buff)
        buff = await websocket.recv()

    file.close()

    # Send EOT
    print('[+] server_loop: File received, FACK received, sending EOT')
    buff = 'EOT'
    await websocket.send(buff)


# Server
def server(ip):
    start_server = websockets.serve(server_loop, ip, 8765)

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()


# Client loop
async def client_loop(ip, filename):
    uri = "ws://"+ip+":8765"
    async with websockets.connect(uri) as websocket:
        # Send the name of the file
        print('[+] client_loop: Sending the filename')
        buff = str(filename)
        await websocket.send(buff)

        # Listen for the NACK
        print('[+] client_loop: Waiting for the NACK')
        buff = await websocket.recv()
        assert buff == 'NACK'

        # Send the file
        print('[+] client_loop: Sending the file')
        with open(filename,'rb') as file:
            for line in file:
                await websocket.send(line)

        # Send the FACK
        print('[+] client_loop: Sending the FACK')
        buff = 'FACK'
        await websocket.send(buff)

        # Listen for the EOT
        buff = await websocket.recv()
        assert buff == 'EOT'
        print('[+] client_loop: Received EOT')


# Client
def client(ip, filename):
    asyncio.get_event_loop().run_until_complete(client_loop(ip, filename))


def main():
    # Register the SIGINT handler
    signal.signal(signal.SIGINT, keyboardInterruptHandler)

    # Check the arguments with argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", required=False, help="Input file to share")
    args = vars(ap.parse_args())
    filename = args['file']
    print(str(filename))

    # If args are good, start working
    print('[*] netdrop: Starting...')

    # Get the network info
    iface = get_iface()

    # Scan the network
    hosts = network_scanner_fast(str(iface.network).split('/')[0], str(iface.network).split('/')[1])
    print(str(hosts))

    # Open a server thread (receiving files)
    global p_server
    p_server = Process(target=server, args=(str(iface.ip),))
    p_server.start()

    # Open a client thread (sending files)
    objective = input("[*] Enter the IP of the end machine: ")
    global p_client
    p_client = Process(target=client, args=(str(objective), str(filename),))
    p_client.start()


if __name__ == "__main__":
    main()