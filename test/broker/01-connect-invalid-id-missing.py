#!/usr/bin/env python

# Test whether a CONNECT with a zero length client id results in the correct CONNACK packet.

import subprocess
import socket
import time

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import ecld_test

rc = 1
keepalive = 10
connect_packet = ecld_test.gen_connect(None, keepalive=keepalive)

cmd = ['../../src/eecloud', '-p', '1888']
broker = ecld_test.start_broker(filename=os.path.basename(__file__), cmd=cmd)

try:
    sock = ecld_test.do_client_connect(connect_packet, "")
    sock.close()
    rc = 0
finally:
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

exit(rc)
