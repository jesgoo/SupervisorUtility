__author__ = 'yangchenxing'

import sys
import time

import gevent

while True:
    sys.stdout.write('%f %s\n' % (time.time(), sys.argv))
    sys.stdout.flush()
    gevent.sleep(1)