#!/usr/bin/env python

import sys, os
pid = str(os.getpid())
f = open('/data/data/org.gaeproxy/python.pid','w')
f.write(pid)
f.close()
dir = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.append(os.path.join(dir, 'src.zip'))
del sys, os, dir
import ProxyServer
ProxyServer.main()
