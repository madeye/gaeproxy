#!/system/bin/sh

DIR=/data/data/org.gaeproxy

PYTHONPATH=${1}/python-extras
PYTHONPATH=${PYTHONPATH}:${DIR}/python/lib/python2.6/lib-dynload
export PYTHONPATH
export TEMP=${1}/python-extras
export PYTHONHOME=${DIR}/python
export LD_LIBRARY_PATH=${DIR}/python/lib

case $2 in

 goagent)
 
 echo " 

[listen]
ip = 127.0.0.1
port = $4
visible = 1

[gae]
enable = 1
appid = $3
password = $7
path = /$6
debuglevel = 0

[php]
enable = 0
ip = 127.0.0.1
port = 8088
fetchserver = http://scan.org/fetch.php

[proxy]
enable = 0
host = 10.64.1.63
port = 8080
username = domain\username
password = 123456

[google]
mode = http
appspot = hk
hosts = hk
sites = .googleusercontent.com|.googleapis.com|.google-analytics.com|.googlecode.com|.appspot.com|.android.com|.googlegroups.com|.android.clients.google.com
forcehttps = groups.google.com|code.google.com|mail.google.com|docs.google.com|profiles.google.com|developer.android.com
withgae = plus.google.com|reader.googleusercontent.com|music.google.com|plusone.google.com
cn = 203.208.46.1|203.208.46.2|203.208.46.3|203.208.46.4|203.208.46.5|203.208.46.6|203.208.46.7|203.208.46.8
hk = $5|209.85.175.32|209.85.175.33|209.85.175.37|209.85.175.34|209.85.175.35|209.85.175.40|209.85.175.41|209.85.175.63|209.85.175.51|209.85.175.69|209.85.175.76|209.85.175.77|209.85.175.46|209.85.175.45|209.85.175.93|209.85.175.91|209.85.175.102|209.85.175.98|209.85.175.114|209.85.175.118|209.85.175.129|209.85.175.75|209.85.175.101|209.85.175.139|209.85.175.113|209.85.175.138|209.85.175.136|209.85.175.190|209.85.175.251|209.85.143.99|209.85.169.147|209.85.173.105|209.85.175.104|209.85.195.104|209.85.227.103|209.85.227.99|209.85.229.104|209.85.229.105|209.85.229.147|209.85.229.99|66.102.13.105|72.14.204.103|72.14.204.105|72.14.204.99|74.125.157.104|74.125.157.99|74.125.224.80|74.125.225.48|74.125.225.83|74.125.232.242|74.125.235.144|74.125.235.20|74.125.235.4|74.125.235.50|74.125.235.51|74.125.237.18|74.125.237.52|74.125.39.103|74.125.39.104|74.125.39.105|74.125.39.106|74.125.39.147|74.125.39.99|74.125.43.105|74.125.65.147|74.125.71.105|74.125.71.99|74.125.73.99|74.125.79.104|74.125.79.99
ipv6 = 2404:6800:8005::6a|2404:6800:8005::62|2404:6800:8005::2c

[fetchmax]
local =
server =

[autorange]
hosts = .youtube.com|.googlevideo.com|av.vimeo.com|.mediafire.com|.filesonic.com|.filesonic.jp|smile-*.nicovideo.jp|video.*.fbcdn.net
endswith = .7z|.zip|.rar|.bz2|.tar|.wmv|.avi
maxsize = 1048576

[useragent]
enable = 0
string = Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)

[love]
enable = 0
timestamp =
tip = \u8bf7\u5173\u6ce8\u5317\u4eac\u5931\u5b66\u513f\u7ae5~~

[hosts]
www.253874.com = 76.73.90.170

"> /data/data/org.gaeproxy/proxy.ini
 
 
$DIR/python-cl $DIR/goagent.py

;;

 gappproxy)
 
$DIR/python-cl $DIR/gappproxy.py

;;

 wallproxy)
 
 echo "
server['listen'] = ('127.0.0.1', $4)
server['log_file'] = None 

hosts = '''
$5  .appspot.com
$5 www.youtube.com
'''

plugins['plugins.hosts'] = 'hosts'

gaeproxy = [{
    'url': '$3',
    'key': '$6',
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
 
 $DIR/python-cl $DIR/wallproxy.py
 
 ;;
 
 esac