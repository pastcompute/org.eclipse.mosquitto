#!/usr/bin/env python

# Test whether a UNSUBSCRIBE to a topic with QoS 0 results in the correct UNSUBACK packet.
# This doesn't assume a subscription exists.

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
mid = 53
keepalive = 60
connect_packet = ecld_test.gen_connect("unsubscribe-qos0-test", keepalive=keepalive)
connack_packet = ecld_test.gen_connack(rc=0)

unsubscribe_packet = ecld_test.gen_unsubscribe(mid, "qos0/test")
unsuback_packet = ecld_test.gen_unsuback(mid)

cmd = ['../../src/eecloud', '-p', '1888']
broker = ecld_test.start_broker(filename=os.path.basename(__file__), cmd=cmd)

try:
    sock = ecld_test.do_client_connect(connect_packet, connack_packet)
    sock.send(unsubscribe_packet)

    if ecld_test.expect_packet(sock, "unsuback", unsuback_packet):
        rc = 0

    sock.close()
finally:
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

exit(rc)

