

import asyncio
import ipaddress
import queue
import subprocess
from threading import Thread

import websockets

from .network import ping

# Global variables
verbose = False
threads = []



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

# Don't need this
#    for t in threads:
#        t.join()
#        threads.remove(t)

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


# Function for SIGINT signal
def join_threads():
	for t in threads:
		try:
			t.join()
		except:
			return False

	return True
