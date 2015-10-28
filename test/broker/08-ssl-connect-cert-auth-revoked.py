#!/usr/bin/env python

import subprocess
import socket
import ssl
import sys
import time

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import ecld_test

rc = 1
keepalive = 10
connect_packet = ecld_test.gen_connect("connect-revoked-test", keepalive=keepalive)
connack_packet = ecld_test.gen_connack(rc=0)

broker = ecld_test.start_broker(filename=os.path.basename(__file__), port=1889)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock = ssl.wrap_socket(sock, ca_certs="../ssl/test-root-ca.crt", certfile="../ssl/client-revoked.crt", keyfile="../ssl/client-revoked.key", cert_reqs=ssl.CERT_REQUIRED)
    ssock.settimeout(20)
    try:
        ssock.connect(("localhost", 1888))
    except ssl.SSLError as err:
        if err.errno == 1 and "certificate revoked" in err.strerror:
            rc = 0
        else:
            broker.terminate()
            print(err.strerror)
            raise ValueError(err.errno)

finally:
    time.sleep(0.5)
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

exit(rc)

