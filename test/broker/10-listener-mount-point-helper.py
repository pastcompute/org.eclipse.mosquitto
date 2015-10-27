#!/usr/bin/env python

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
keepalive = 60
connect_packet = ecld_test.gen_connect("test-helper", keepalive=keepalive)
connack_packet = ecld_test.gen_connack(rc=0)

publish_packet = ecld_test.gen_publish("test", qos=0, payload="mount point")

sock = ecld_test.do_client_connect(connect_packet, connack_packet, port=1889, connack_error="helper connack")
sock.send(publish_packet)
rc = 0
sock.close()
    
exit(rc)

