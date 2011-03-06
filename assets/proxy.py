#! /usr/bin/env python
# coding=utf-8
#############################################################################
#                                                                           #
#   File: proxy.py                                                          #
#                                                                           #
#   Copyright (C) 2008-2010 Du XiaoGang <dugang.2008@gmail.com>             #
#                                                                           #
#   Home: http://gappproxy.googlecode.com                                   #
#                                                                           #
#   This file is part of GAppProxy.                                         #
#                                                                           #
#   GAppProxy is free software: you can redistribute it and/or modify       #
#   it under the terms of the GNU General Public License as                 #
#   published by the Free Software Foundation, either version 3 of the      #
#   License, or (at your option) any later version.                         #
#                                                                           #
#   GAppProxy is distributed in the hope that it will be useful,            #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#   GNU General Public License for more details.                            #
#                                                                           #
#   You should have received a copy of the GNU General Public License       #
#   along with GAppProxy.  If not, see <http://www.gnu.org/licenses/>.      #
#                                                                           #
#############################################################################

import BaseHTTPServer, SocketServer, urllib, urllib2, urlparse, zlib, socket, os, common, sys, errno, base64, re
try:
    import ssl
    ssl_enabled = True
except:
    ssl_enabled = False

# global varibles
listen_port = common.DEF_LISTEN_PORT
local_proxy = common.DEF_LOCAL_PROXY
fetch_server = common.DEF_FETCH_SERVER
google_proxy = {}

class LocalProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    PostDataLimit = 0x100000

    def do_CONNECT(self):
        if not ssl_enabled:
            self.send_error(501, "Local proxy error, HTTPS needs Python2.6 or later.")
            self.connection.close()
            return

        # for ssl proxy
        (https_host, _, https_port) = self.path.partition(":")
        if https_port != "" and https_port != "443":
            self.send_error(501, "Local proxy error, Only port 443 is allowed for https.")
            self.connection.close()
            return

        # continue
        self.wfile.write("HTTP/1.1 200 OK\r\n")
        self.wfile.write("\r\n")
        ssl_sock = ssl.SSLSocket(self.connection, server_side=True, certfile=common.DEF_CERT_FILE, keyfile=common.DEF_KEY_FILE)

        # rewrite request line, url to abs
        first_line = ""
        while True:
            chr = ssl_sock.read(1)
            # EOF?
            if chr == "":
                # bad request
                ssl_sock.close()
                self.connection.close()
                return
            # newline(\r\n)?
            if chr == "\r":
                chr = ssl_sock.read(1)
                if chr == "\n":
                    # got
                    break
                else:
                    # bad request
                    ssl_sock.close()
                    self.connection.close()
                    return
            # newline(\n)?
            if chr == "\n":
                # got
                break
            first_line += chr
        # got path, rewrite
        (method, path, ver) = first_line.split()
        if path.startswith("/"):
            path = "https://%s" % https_host + path

        # connect to local proxy server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", listen_port))
        sock.send("%s %s %s\r\n" % (method, path, ver))

        # forward https request
        ssl_sock.settimeout(1)
        while True:
            try:
                data = ssl_sock.read(8192)
            except ssl.SSLError, e:
                if str(e).lower().find("timed out") == -1:
                    # error
                    sock.close()
                    ssl_sock.close()
                    self.connection.close()
                    return
                # timeout
                break
            if data != "":
                sock.send(data)
            else:
                # EOF
                break
        ssl_sock.setblocking(True)

        # simply forward response
        while True:
            data = sock.recv(8192)
            if data != "":
                ssl_sock.write(data)
            else:
                # EOF
                break

        # clean
        sock.close()
        ssl_sock.shutdown(socket.SHUT_WR)
        ssl_sock.close()
        self.connection.close()
   
    def do_METHOD(self):
        # check http method and post data
        method = self.command
        if method == "GET" or method == "HEAD":
            # no post data
            post_data_len = 0
        elif method == "POST":
            # get length of post data
            post_data_len = 0
            for header in self.headers:
                if header.lower() == "content-length":
                    post_data_len = int(self.headers[header])
                    break
            # exceed limit?
            if post_data_len > self.PostDataLimit:
                self.send_error(413, "Local proxy error, Sorry, Google's limit, file size up to 1MB.")
                self.connection.close()
                return
        else:
            # unsupported method
            self.send_error(501, "Local proxy error, Method not allowed.")
            self.connection.close()
            return

        # get post data
        post_data = ""
        if post_data_len > 0:
            post_data = self.rfile.read(post_data_len)
            if len(post_data) != post_data_len:
                # bad request
                self.send_error(400, "Local proxy error, Post data length error.")
                self.connection.close()
                return

        # do path check
        (scm, netloc, path, params, query, _) = urlparse.urlparse(self.path)
        if (scm.lower() != "http" and scm.lower() != "https") or not netloc:
            self.send_error(501, "Local proxy error, Unsupported scheme(ftp for example).")
            self.connection.close()
            return
        # create new path
        path = urlparse.urlunparse((scm, netloc, path, params, query, ""))

        # remove disallowed header
        dhs = []
        for header in self.headers:
            hl = header.lower()
            if hl == "if-range":
                dhs.append(header)
            elif hl == "range":
                dhs.append(header)
        for dh in dhs:
            del self.headers[dh]
        # create request for GAppProxy
        params = urllib.urlencode({"method": method,
                                   "encoded_path": base64.b64encode(path),
                                   "headers": base64.b64encode(str(self.headers)),
                                   "postdata": base64.b64encode(post_data),
                                   "version": common.VERSION})
        # accept-encoding: identity, *;q=0
        # connection: close
        request = urllib2.Request(fetch_server)
        request.add_header("Accept-Encoding", "identity, *;q=0")
        request.add_header("Connection", "close")
        # create new opener
        if local_proxy != "":
            proxy_handler = urllib2.ProxyHandler({"http": local_proxy})
        else:
            proxy_handler = urllib2.ProxyHandler(google_proxy)
        opener = urllib2.build_opener(proxy_handler)
        # set the opener as the default opener
        urllib2.install_opener(opener)
        try:
            resp = urllib2.urlopen(request, params)
        except urllib2.HTTPError, e:
            if e.code == 404:
                self.send_error(404, "Local proxy error, Fetchserver not found at the URL you specified, please check it.")
            elif e.code == 502:
                self.send_error(502, "Local proxy error, Transmission error, or the fetchserver is too busy.")
            else:
                self.send_error(e.code)
            self.connection.close()
            return
        except urllib2.URLError, e:
            if local_proxy == "":
                shallWeNeedGoogleProxy()
            self.connection.close()
            return

        # parse resp
        # for status line
        line = resp.readline()
        words = line.split()
        status = int(words[1])
        reason = " ".join(words[2:])

        # for large response
        if status == 592 and method == "GET":
            self.processLargeResponse(path)
            self.connection.close()
            return

        # normal response
        try:
            self.send_response(status, reason)
        except socket.error, (err, _):
            # Connection/Webpage closed before proxy return
            if err == errno.EPIPE or err == 10053: # *nix, Windows
                return
            else:
                raise

        # for headers
        text_content = True
        while True:
            line = resp.readline().strip()
            # end header?
            if line == "":
                break
            # header
            (name, _, value) = line.partition(":")
            name = name.strip()
            value = value.strip()
            # ignore Accept-Ranges
            if name.lower() == "accept-ranges":
                continue
            self.send_header(name, value)
            # check Content-Type
            if name.lower() == "content-type":
                if value.lower().find("text") == -1:
                    # not text
                    text_content = False
        self.send_header("Accept-Ranges", "none")
        self.end_headers()

        # for page
        if text_content:
            data = resp.read()
            if len(data) > 0:
                self.wfile.write(zlib.decompress(data))
        else:
            self.wfile.write(resp.read())
        self.connection.close()

    do_GET = do_METHOD
    do_HEAD = do_METHOD
    do_POST = do_METHOD

    def processLargeResponse(self, path):
        cur_pos = 0
        part_length = 0x100000 # 1m initial, at least 64k
        first_part = True
        content_length = 0
        text_content = True
        allowed_failed = 10

        while allowed_failed > 0:
            next_pos = 0
            self.headers["Range"] = "bytes=%d-%d" % (cur_pos, cur_pos + part_length - 1)
            # create request for GAppProxy
            params = urllib.urlencode({"method": "GET",
                                       "encoded_path": base64.b64encode(path),
                                       "headers": base64.b64encode(str(self.headers)),
                                       "postdata": base64.b64encode(""),
                                       "version": common.VERSION})
            # accept-encoding: identity, *;q=0
            # connection: close
            request = urllib2.Request(fetch_server)
            request.add_header("Accept-Encoding", "identity, *;q=0")
            request.add_header("Connection", "close")
            # create new opener
            if local_proxy != "":
                proxy_handler = urllib2.ProxyHandler({"http": local_proxy})
            else:
                proxy_handler = urllib2.ProxyHandler(google_proxy)
            opener = urllib2.build_opener(proxy_handler)
            # set the opener as the default opener
            urllib2.install_opener(opener)
            resp = urllib2.urlopen(request, params)

            # parse resp
            # for status line
            line = resp.readline()
            words = line.split()
            status = int(words[1])
            # not range response?
            if status != 206:
                # reduce part_length and try again
                if part_length > 65536:
                    part_length /= 2
                allowed_failed -= 1
                continue

            # for headers
            if first_part:
                self.send_response(200, "OK")
                while True:
                    line = resp.readline().strip()
                    # end header?
                    if line == "":
                        break
                    # header
                    (name, _, value) = line.partition(":")
                    name = name.strip()
                    value = value.strip()
                    # get total length from Content-Range
                    nl = name.lower()
                    if nl == "content-range":
                        m = re.match(r"bytes[ \t]+([0-9]+)-([0-9]+)/([0-9]+)", value)
                        if not m or int(m.group(1)) != cur_pos:
                            # Content-Range error, fatal error
                            return
                        next_pos = int(m.group(2)) + 1
                        content_length = int(m.group(3))
                        continue
                    # ignore Content-Length
                    elif nl == "content-length":
                        continue
                    # ignore Accept-Ranges
                    elif nl == "accept-ranges":
                        continue
                    self.send_header(name, value)
                    # check Content-Type
                    if nl == "content-type":
                        if value.lower().find("text") == -1:
                            # not text
                            text_content = False
                if content_length == 0:
                    # no Content-Length, fatal error
                    return
                self.send_header("Content-Length", content_length)
                self.send_header("Accept-Ranges", "none")
                self.end_headers()
                first_part = False
            else:
                while True:
                    line = resp.readline().strip()
                    # end header?
                    if line == "":
                        break
                    # header
                    (name, _, value) = line.partition(":")
                    name = name.strip()
                    value = value.strip()
                    # get total length from Content-Range
                    if name.lower() == "content-range":
                        m = re.match(r"bytes[ \t]+([0-9]+)-([0-9]+)/([0-9]+)", value)
                        if not m or int(m.group(1)) != cur_pos:
                            # Content-Range error, fatal error
                            return
                        next_pos = int(m.group(2)) + 1
                        continue

            # for body
            if text_content:
                data = resp.read()
                if len(data) > 0:
                    self.wfile.write(zlib.decompress(data))
            else:
                self.wfile.write(resp.read())

            # next part?
            if next_pos == content_length:
                return
            cur_pos = next_pos

class ThreadingHTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    pass

def shallWeNeedGoogleProxy():
    global google_proxy

    # send http request directly
    #request = urllib2.Request(common.LOAD_BALANCE)
    #try:
        # avoid wait too long at startup, timeout argument need py2.6 or later.
    #    if sys.hexversion >= 0x20600f0:
    #        resp = urllib2.urlopen(request, timeout=3)
    #    else:
    #        resp = urllib2.urlopen(request)
    #    resp.read()
    #except:
    google_proxy = {"http": common.GOOGLE_PROXY}

def getAvailableFetchServer():
    request = urllib2.Request(common.LOAD_BALANCE)
    if local_proxy != "":
        proxy_handler = urllib2.ProxyHandler({"http": local_proxy})
    else:
        proxy_handler = urllib2.ProxyHandler(google_proxy)
    opener = urllib2.build_opener(proxy_handler)
    urllib2.install_opener(opener)
    try:
        resp = urllib2.urlopen(request)
        return resp.read().strip()
    except:
        return ""

def parseConf(confFile):
    global listen_port, local_proxy, fetch_server

    # read config file
    try:
        fp = open(confFile, "r")
    except IOError:
        # use default parameters
        return
    # parse user defined parameters
    while True:
        line = fp.readline()
        if line == "":
            # end
            break
        # parse line
        line = line.strip()
        if line == "":
            # empty line
            continue
        if line.startswith("#"):
            # comments
            continue
        (name, sep, value) = line.partition("=")
        if sep == "=":
            name = name.strip().lower()
            value = value.strip()
            if name == "listen_port":
                listen_port = int(value)
            elif name == "local_proxy":
                local_proxy = value
            elif name == "fetch_server":
                fetch_server = value
    fp.close()

if __name__ == "__main__":
    parseConf(common.DEF_CONF_FILE)
    socket.setdefaulttimeout(10)

    if local_proxy == "":
        shallWeNeedGoogleProxy()

    #if fetch_server == "":
    #    fetch_server = getAvailableFetchServer()
    if fetch_server == "":
        raise common.GAppProxyError("Invalid response from load balance server.")
    
    
        
    pid = str(os.getpid())
    f = open('/data/data/org.gaeproxy/python.pid','w')
    f.write(pid)
    f.close()

    print "--------------------------------------------"
    print "HTTPS Enabled: %s" % (ssl_enabled and "YES" or "NO")
    print "Direct Fetch : %s" % (google_proxy and "NO" or "YES")
    print "Listen Addr  : 127.0.0.1:%d" % listen_port
    print "Local Proxy  : %s" % local_proxy
    print "Fetch Server : %s" % fetch_server
    print "PID          : %s" % pid
    print "--------------------------------------------"
    httpd = ThreadingHTTPServer(("127.0.0.1", listen_port), LocalProxyHandler)
    httpd.serve_forever()
    
    
    
