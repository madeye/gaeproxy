#!/system/bin/sh

DIR=/data/data/org.gaeproxy

PYTHONPATH=${1}/python-extras
PYTHONPATH=${PYTHONPATH}:${DIR}/python/lib/python2.6/lib-dynload
export PYTHONPATH
export TEMP=${1}/python-extras
export PYTHONHOME=${DIR}/python
export LD_LIBRARY_PATH=${DIR}/python/lib

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
profile = google_cn
mulconn = 1

[paas]
enable = 0
password = 123456
listen = 127.0.0.1:8088
fetchserver = http://demophus.app.com/

[proxy]
enable = 0
host = 10.64.1.63
port = 8080
username = username
password = 123456

[google_cn]
mode = http
hosts = $5|203.208.46.1|203.208.46.2|203.208.46.3|203.208.46.4|203.208.46.5|203.208.46.6|203.208.46.7|203.208.46.8
sites = .google.com|.googleusercontent.com|.googleapis.com|.google-analytics.com|.googlecode.com|.google.com.hk|.appspot.com|.android.com|.googlegroups.com
forcehttps = groups.google.com|code.google.com|mail.google.com|docs.google.com|profiles.google.com|developer.android.com
withgae = plus.google.com|plusone.google.com|reader.googleusercontent.com|music.google.com|apis.google.com

[google_hk]
mode = http
hosts = www.google.com|mail.google.com|www.google.com.hk|www.google.com.tw
sites = .google.com|.googleusercontent.com|.googleapis.com|.google-analytics.com|.googlecode.com|.google.com.hk|.googlegroups.com
forcehttps = groups.google.com|code.google.com|mail.google.com|docs.google.com|profiles.google.com|developer.android.com
withgae = www.google.com.hk

[google_ipv6]
mode = http
hosts = 2404:6800:8005::2f|2a00:1450:8006::30|2404:6800:8005::84
sites = .google.com|.googleusercontent.com|.googleapis.com|.google-analytics.com|.googlecode.com|.google.com.hk|.googlegroups.com
forcehttps = groups.google.com|code.google.com|mail.google.com|docs.google.com|profiles.google.com|developer.android.com
withgae = 

[fetchmax]
local = 
server = 

[autorange]
hosts = .youtube.com|.atm.youku.com|.googlevideo.com|av.vimeo.com|smile-*.nicovideo.jp|video.*.fbcdn.net|s*.last.fm|x*.last.fm
maxsize = 1048576
waitsize = 524288
bufsize = 8192

[pac]
enable = 0
ip = 127.0.0.1
port = 8089
file = goagent.pac
update = 0
remote = http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
timeout = 16
direct = .253874.com|.cnn.com

[useragent]
enable = 0
string = Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543a Safari/419.3

[love]
enable = 1
timestamp = 1339122685
tip = \u8bf7\u5173\u6ce8\u5317\u4eac\u5931\u5b66\u513f\u7ae5~~

[hosts]
www.253874.com = 

"> /data/data/org.gaeproxy/proxy.ini
 
 
$DIR/python-cl $DIR/goagent.py
