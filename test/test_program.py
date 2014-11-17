__author__ = 'yangchenxing'

import sys
import time

import gevent

while True:
    print time.time(), sys.argv
    gevent.sleep(1)