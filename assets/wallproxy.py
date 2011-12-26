#!/usr/bin/env python

import sys, os

# do the UNIX double-fork magic, see Stevens' "Advanced   
# Programming in the UNIX Environment" for details (ISBN 0201563177)  
try:   
    pid = os.fork()   
    if pid > 0:  
        # exit first parent  
        sys.exit(0)   
except OSError, e:   
    print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror)   
    sys.exit(1)  
# decouple from parent environment  
os.chdir("/")   
os.setsid()   
os.umask(0)   
# do second fork  
try:   
    pid = os.fork()   
    if pid > 0:
        sys.exit(0)   
except OSError, e:   
    print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror)   
    sys.exit(1)

pid = str(os.getpid())
f = open('/data/data/org.gaeproxy/python.pid','a')
f.write(" ")
f.write(pid)
f.close()
dir = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.append(os.path.join(dir, 'src.zip'))
del sys, os, dir
import ProxyServer
ProxyServer.main()
