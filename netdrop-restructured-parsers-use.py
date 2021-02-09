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


# Handles SIGINT signal
def keyboardInterruptHandler(signal, frame):
    print("KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signal))
    exit(0)


def main():
    # Register the signal handlers
    signal.signal(signal.SIGINT, keyboardInterruptHandler)
    
    parser = argparse.ArgumentParser(prog='netdrop')
    parser.add_argument('--foo', action='store_true', help='foo help')
    subparsers = parser.add_subparsers('Help for subcomands')

    parser_client = subparsers.add_parser('client', help='Client mode')
    parser_client.add_argument('-f', '--file', required=True, help='Input file to share')

    parser_server = subparsers.add_parser('server', help='Server mode')



    # Check the arguments
    ap = argparse.ArgumentParser()
    # Server or client, but not both at the same time
    exclusive_group = ap.add_mutually_exclusive_group()
    exclusive_group.add_argument("server", help='Server mode', nargs='?')
    exclusive_group.add_argument("client", help='Client mode', nargs='?')
    subparsers = exclusive_group.ad
    ap.add_argument("-f", "--file", required=False, help="Input file to share")

    args = vars(ap.parse_args())

    filename = args['file']

    print(args['file'])
    print(args['server'])

    # Check if client or server
        # Client
            # Check if file exists and is readable
            # Scan the network
            # Ask for a server (receiver of the file)
            # Create process to send the file to the selected server
            # Ask for more files to send or exit (go to start of client: create function)
        # Server
            # Wait for a connection
            # Ask the user for consentment
            # Receive the file
    return 0

if __name__ == "__main__":
    main()