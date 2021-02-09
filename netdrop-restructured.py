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

    # Check the arguments
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