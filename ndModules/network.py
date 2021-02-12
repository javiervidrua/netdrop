

import ipaddress
import socket
import subprocess
from xml.etree.ElementTree import fromstring

# Global variables
verbose = False



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
		if verbose: print('[v] get_iface: Host\'s IP is ' + str(ip))

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
	if verbose: print('[v] get_iface: Hosts network is ' + str(ret.network))
	return ret


# Creates a subprocess to ping the objective
def ping(ip):
	output = subprocess.Popen(['ping', '-n', '1', '-w', '1000', str(ip)], stdout=subprocess.PIPE).stdout.read() # Max 1 second delay
	if "100%" not in str(output): # There is no 100% loss rate -> host is alive
		return ip
	else:
		return None
