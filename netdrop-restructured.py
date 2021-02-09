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


# Global variables
is_client = False # True = client, False = Server


# Handles SIGINT signal
def keyboard_interrupt_handler(signal, frame):
    print("KeyboardInterrupt (ID: {}) has been caught. Cleaning up...".format(signal))
    exit(0)


def main():
    # Register the signal handlers
    signal.signal(signal.SIGINT, keyboard_interrupt_handler)
        
    # Check the arguments
    my_description="""By default works in server mode, for client mode use -f argument""" # https://stackoverflow.com/questions/18106327/display-pydocs-description-as-part-of-argparse-help
    parser = argparse.ArgumentParser(prog='netdrop', description=my_description)
    parser.add_argument("-f", "--file", required=False, help="Client mode: Input file to share")
    args = vars(parser.parse_args())
    filename = args['file']

    # Check if client or server
    if filename != None:
        is_client = True
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