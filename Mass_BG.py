#!/usr/bin/python2.7
# By: Scav-engeR
import threading
import sys, os, re, time, socket
from Queue import *
from sys import stdout

if len(sys.argv) < 6 :
        print "Usage: python "+sys.argv[0]+" <list> <threads> <banner> <port> <output file>"
        sys.exit()

ips = open(sys.argv[1], "r").readlines()
threads = int(sys.argv[2])
banner = sys.argv[3]
port = int(sys.argv[4])
output_file = sys.argv[5]
queue = Queue()
queue_count = 0

for ip in ips:
        queue_count += 1
        stdout.write("\r[%d] Added to queue" % queue_count)
        stdout.flush()
        queue.put(ip)
print "\n"

class router(threading.Thread):
        def __init__ (self, ip):
                threading.Thread.__init__(self)
                self.ip = str(ip).rstrip('\n')
        def run(self):
                try:
                        tn = socket.socket()
                        tn.settimeout(8)
                        tn.connect((self.ip, port))
                        banner = tn.recv(1024)
                        if b in banner:
                                output_file.write(ip+"\n")
                except Exception:
                        tn.close()

def readUntil(tn, string, timeout=8):
        buf = ''
        start_time = time.time()
        while time.time() - start_time < timeout:
                buf += tn.recv(1024)
                time.sleep(0.01)
                if string in buf: return buf
        raise Exception('TIMEOUT!')

def worker():
        try:
                while True:
                        try:
                                IP = queue.get()
                                thread = router(IP)
                                thread.start()
                                queue.task_done()
                                time.sleep(0.2)
                        except:
                                pass
        except:
                pass

for l in xrange(threads):
        try:
                t = threading.Thread(target=worker)
                t.start()
                time.sleep(0.01)
        except:
                pass
