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
http = 203.208.46.1|203.208.46.2|203.208.46.3|203.208.46.4|203.208.46.5|203.208.46.6|203.208.46.7|203.208.46.8|203.208.46.62|203.208.46.65|203.208.46.66|203.208.46.67|203.208.46.68|203.208.46.69|203.208.46.70|203.208.46.71|203.208.46.72|203.208.46.80|203.208.46.81|203.208.46.82|203.208.46.85|203.208.46.86|203.208.46.87|203.208.46.88|203.208.46.89|203.208.46.90|203.208.46.91|203.208.46.92|203.208.46.93|203.208.46.94|203.208.46.95|203.208.46.96|203.208.46.97|203.208.46.98|203.208.46.99|203.208.46.100|203.208.46.101|203.208.46.102|203.208.46.103|203.208.46.126|203.208.46.160|203.208.46.161|203.208.46.162|203.208.46.163|203.208.46.164|203.208.46.165|203.208.46.166|203.208.46.167|203.208.46.168|203.208.46.169|203.208.46.170|203.208.46.171|203.208.46.172|203.208.46.173|203.208.46.174|203.208.46.175|203.208.46.176|203.208.46.177|203.208.46.178|203.208.46.181|203.208.46.182|203.208.46.183|203.208.46.184|203.208.46.185|203.208.46.186|203.208.46.187|203.208.46.188|203.208.46.189|203.208.46.190|203.208.46.191|203.208.46.192|203.208.46.193|203.208.46.194|203.208.46.195|203.208.46.196|203.208.46.197|203.208.46.198|203.208.46.199|203.208.46.200|203.208.46.201|203.208.46.202|203.208.46.203|203.208.46.204|203.208.46.205|203.208.46.206|203.208.46.207|203.208.46.208|203.208.46.209|203.208.46.210|203.208.46.213|203.208.46.214|203.208.46.215|203.208.46.216|203.208.46.217|203.208.46.218|203.208.46.219|203.208.46.220|203.208.46.221|203.208.46.222|203.208.46.223|203.208.46.224|203.208.46.225|203.208.46.226|203.208.46.227|203.208.46.228|203.208.46.229|203.208.46.230|203.208.46.231|203.208.46.232|203.208.46.233|203.208.46.234|203.208.46.235|203.208.46.236|203.208.46.237|203.208.46.238|203.208.46.239|203.208.46.240|203.208.46.241|203.208.46.242|203.208.46.245|203.208.46.246|203.208.46.247|203.208.46.248|203.208.46.249|203.208.46.250|203.208.46.251|203.208.46.252|203.208.46.253|203.208.46.254
https = 203.208.46.1|203.208.46.2|203.208.46.3|203.208.46.4|203.208.46.5|203.208.46.6|203.208.46.7|203.208.46.8

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