import os
import random
import time
import websockets
from .generalutils import clean_string


# Global variables
verbose = False


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
		print('[+] netdrop: Waiting for the server to accept the transmission')
		buff = await websocket.recv()
		try:
			assert buff == 'NACK'
		except AssertionError:
			print('[-] file_send: The server did not accept the file share, quitting...')
			exit(11)
		# Send the file (get the size and the starting time)
		size = round((os.path.getsize(f)/1024)/1024, 4)
		if verbose: print('[+] file_send: File size is ' + str(size) + ' MB')
		start = time.time()
		print('[+] netdrop: Sending ' + str(f) + ' to ' + str(server))
		try:
			with open(f,'rb') as file:
				for line in file:
					await websocket.send(line)
			end = time.time()
			print('[+] netdrop: Took ' + str(round(end - start, 4)) + ' seconds at ' + str(round(size / (end - start), 4)) + 'MB/s')
		except Exception as e:
			print('[-] file_send: Error during file transmission')
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
		if verbose: print('[v] file_download: Received file "' + str(filename) + '" from ' + str(websocket.remote_address[0]) + ' on port ' + str(websocket.remote_address[1]))
		if 'yes' != input('[*] netdrop: To download the file ' + str(filename) + ' from the IP ' + str(websocket.remote_address[0]) + ' enter "yes": '):
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
				print('[+] netdrop: The file transmission has started')
				start = time.time()
				while buff != 'FACK':
					file.write(buff)
					buff = await websocket.recv()
				end = time.time()
			try:
				size = round((os.path.getsize(write_file)/1024)/1024, 4)
				print('[+] netdrop: Took ' + str(round(end - start, 4)) + ' seconds at ' + str(round(size / (end - start), 4)) + 'MB/s')
			except Exception as e:
				print('[-] file_download: Error while calculating time and speed of transmission')
				exit(13)

			# Sending the EOT
			if verbose: print('[v] file_download: File received, FACK received, sending EOT')
			buff = 'EOT'
			await websocket.send(buff)
			if verbose: print('[v] file_download: EOT sent')
			await websocket.wait_closed()
			print('[+] netdrop: Transmission done')
	else:
		if verbose: print('[v] file_download: DISCOVER received from ' + str(websocket.remote_address[0]))