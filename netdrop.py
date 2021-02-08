import socket
import ipaddress
import subprocess
import queue
from threading import Thread

# Returns the IP of the machine
def get_ip(verbose=False):
    if verbose: print('[v] Getting the IP of the machine...', end='')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        err = s.connect(('192.255.255.255', 1)) # Does not even have to be reachable
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
        print('[*] IP: ' + str(ip))
    
    return ip

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
    # SLOW WAY https://opentechguides.com/how-to/article/python/57/python-ping-subnet.html
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

    # FAST WAY https://www.edureka.co/community/31966/how-to-get-the-return-value-from-a-thread-using-python
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

# To test if the functions work properly
def test():
    ip = '192.168.1.0'
    netmask = '24'
    print('[*] Calling network_scanner with: ' + ip + ', ' + netmask )
    hosts = network_scanner_fast(ip, netmask)
    print("[*] List of detected hosts: " + str(hosts))

def main():
    print('[*] netdrop: Starting...')
    # Check the arguments
    # Scan the network
    # Open a server thread (receiving files)
    # Open a client thread (sending files)
    test()

if __name__ == "__main__":
    main()
