#!/system/bin/sh

export PYTHONPATH=/data/data/org.gaeproxy/python:/data/data/org.gaeproxy/python/lib/python2.6:/data/data/org.gaeproxy/python/lib/python2.6/lib-dynload:/data/data/org.gaeproxy/python/lib:/sdcard/python-extras
export LD_LIBRARY_PATH=/data/data/org.gaeproxy/python/lib
export PYTHONHOME=$PYTHONHOME:/data/data/org.gaeproxy/python
export TEMP=/sdcard/python-extras

echo "" > /data/data/org.gaeproxy/python.pid
chmod 777 /data/data/org.gaeproxy/python.pid

case $1 in

 goagent)
 
 echo " 

[listen]
ip = 127.0.0.1
port = $3
visible = 1
debug = INFO	

[hosts]
# NOTE: Only effect on https

[gae]
host = $2
password = $6
path = /$5
prefer = http
http_timeout = 5
http_step = 8
https_timeout = 8
https_step = 16
http = $4
https = $4

"> /data/data/org.gaeproxy/proxy.ini
 
 
/data/data/org.gaeproxy/python/bin/python /data/data/org.gaeproxy/goagent.py

;;

 gappproxy)
 
/data/data/org.gaeproxy/python/bin/python /data/data/org.gaeproxy/gappproxy.py

;;

 wallproxy)
 
 echo "
server['listen'] = ('127.0.0.1', $3)
server['log_file'] = None 

gaeproxy = [{
    'url': '$2',
    'key': '$4',
    'crypto':'XOR--0',
    'max_threads':5
}]

plugins['plugins.gaeproxy'] = 'gaeproxy'

def find_http_handler(method, url, headers):
    if method not in ('GET', 'HEAD', 'PUT', 'POST', 'DELETE'):
        return rawproxy[0]
    if 80<=url.port<=90 or 440<=url.port<=450 or url.port>=1024:
        return gaeproxy
    return None

fakehttps = None
plugins['plugins.fakehttps'] = 'fakehttps'

def find_sock_handler(reqtype, ip, port, cmd):
    if reqtype == 'https': return fakehttps
    return None

def check_client(ip, reqtype, args):
    return True
 " > /data/data/org.gaeproxy/proxy.conf
 /data/data/org.gaeproxy/python/bin/python /data/data/org.gaeproxy/wallproxy.py
 
 ;;
 
 esac