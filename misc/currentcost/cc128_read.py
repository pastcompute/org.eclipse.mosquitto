#!/usr/bin/python -u

import eecloud
import serial

usb = serial.Serial(port='/dev/ttyUSB0', baudrate=57600)

ecld = eecloud.Eecloud()
ecld.connect("localhost")
ecld.loop_start()

running = True
try:
    while running:
        line = usb.readline()
        ecld.publish("cc128/raw", line)
except usb.SerialException, e:
    running = False

ecld.disconnect()
ecld.loop_stop()

