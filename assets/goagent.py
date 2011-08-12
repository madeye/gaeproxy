#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

##import psyco
##psyco.full()
##import gevent.monkey
##gevent.monkey.patch_all()

import sys, os, re, time
import errno, zlib, struct, binascii
import logging
import httplib, urllib2, urlparse, socket, select
import BaseHTTPServer, SocketServer
import ConfigParser
import ssl
import ctypes
import random
try:
    import OpenSSL.crypto
    openssl_enabled = True
except ImportError:
    openssl_enabled = False
    
pid = str(os.getpid())
f = open('/data/data/org.gaeproxy/python.pid','w')
f.write(pid)
f.close()

__version__ = 'beta'
__author__ =  'phus.lu@gmail.com'

def random_choice(seq):
    return seq[int(ord(os.urandom(1))/256.0*len(seq))]

def random_shuffle(seq):
    from os import urandom
    for i in xrange(len(seq)-1, 1, -1):
        j = int(ord(urandom(1))/256.0 * (i+1))
        seq[i], seq[j] = seq[j], seq[i]

class Common(object):
    '''global config module, based on GappProxy 2.0.0'''
    FILENAME = '/data/data/org.gaeproxy/proxy.ini'
    ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')

    def __init__(self):
        '''read config from proxy.ini'''
        self.config = ConfigParser.ConfigParser()
        self.config.read(Common.FILENAME)
        self.LISTEN_IP         = self.config.get('listen', 'ip')
        self.LISTEN_PORT       = self.config.getint('listen', 'port')
        self.LISTEN_VISIBLE    = self.config.getint('listen', 'visible')
        self.LISTEN_DEBUG      = self.config.get('listen', 'debug')
        logging.basicConfig(level=getattr(logging, self.LISTEN_DEBUG), format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%d/%b/%Y %H:%M:%S]')
        self.HOSTS               = self.config.items('hosts')
        self.GAE_HOST            = self.config.get('gae', 'host')
        self.GAE_PASSWORD        = self.config.get('gae', 'password').strip()
        self.GAE_HOSTS           = self.GAE_HOST.split('|')
        self.GAE_PATH            = self.config.get('gae', 'path')
        self.GAE_PREFER          = self.config.get('gae', 'prefer')
        self.GAE_HTTP            = self.config.get('gae', 'http').split('|')
        self.GAE_HTTP_TIMEOUT    = self.config.getint('gae', 'http_timeout')
        self.GAE_HTTP_STEP       = self.config.getint('gae', 'http_step')
        self.GAE_HTTPS           = self.config.get('gae', 'https').split('|')
        self.GAE_HTTPS_TIMEOUT   = self.config.getint('gae', 'https_timeout')
        self.GAE_HTTPS_STEP      = self.config.getint('gae', 'https_step')
        self.GAE_PROXY           = dict(re.match(r'^(\w+)://(\S+)$', proxy.strip()).group(1, 2) for proxy in self.config.get('gae', 'proxy').split('|')) if self.config.has_option('gae', 'proxy') else {}
        self.GAE_BINDHOSTS       = dict((host, random_choice(self.GAE_HOSTS)) for host in self.config.get('gae', 'bindhosts').split('|')) if self.config.has_option('gae', 'bindhosts') else {}

    def select_gaehost(self, url):
        gaehost = None
        if len(self.GAE_HOSTS) == 1:
            return self.GAE_HOSTS[0]
        if self.GAE_BINDHOSTS:
            gaehost = self.GAE_BINDHOSTS.get(urlparse.urlsplit(url)[1])
        gaehost = gaehost or random_choice(self.GAE_HOSTS)
        return gaehost

common = Common()

class MultiplexConnection(object):
    '''random tcp connection class'''
    def __init__(self, hosts, port, timeout, step, shuffle=0):
        self.socket = None
        self._sockets = set([])
        if shuffle:
            random_shuffle(hosts)
        self.connect(hosts, port, timeout, step)
    def connect(self, hosts, port, timeout, step):
        if step == 1:
            return self.connect1(hosts, port, timeout, step)
        else:
            return self.connect2(hosts, port, timeout, step)
    def connect1(self, hosts, port, timeout, step):
        for host in hosts:
            logging.debug("MultiplexConnection single step connect hosts: (%r, %r)", hosts, port)
            try:
                sock_family = socket.AF_INET if '.' in host else socket.AF_INET6
                logging.debug('MultiplexConnection connect_ex (%r, %r)', host, port)
                sock = socket.socket(sock_family, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                self.socket = sock
                break
            except socket.error, e:
                logging.warning('MultiplexConnection Cannot Connect to hosts %s:%s', host, port)
        else:
            raise RuntimeError(r'MultiplexConnection Cannot Connect to hostslist %s:%s', hosts, port)
    def connect2(self, hosts, port, timeout, step):
        hostslist = [hosts[i:i+step] for i in xrange(0,len(hosts),step)]
        for hosts in hostslist:
            logging.debug("MultiplexConnection multi step connect hosts: (%r, %r)", hosts, port)
            socks = []
            for host in hosts:
                sock_family = socket.AF_INET if '.' in host else socket.AF_INET6
                sock = socket.socket(sock_family, socket.SOCK_STREAM)
                sock.setblocking(0)
                logging.debug('MultiplexConnection connect_ex (%r, %r)', host, port)
                err = sock.connect_ex((host, port))
                self._sockets.add(sock)
                socks.append(sock)
            (_, outs, _) = select.select([], socks, [], timeout)
            if outs:
                self.socket = outs[0]
                self.socket.setblocking(1)
                self._sockets.remove(self.socket)
                break
            else:
                logging.warning('MultiplexConnection Cannot Connect to hosts %s:%s', hosts, port)
        else:
            raise RuntimeError(r'MultiplexConnection Cannot Connect to hostslist %s:%s', hostslist, port)
    def close(self):
        for soc in self._sockets:
            try:
                soc.close()
            except:
                pass

_socket_create_connection = socket.create_connection
def socket_create_connection(address, timeout=10, source_address=None):
    host, port = address
    logging.debug('socket_create_connection connect (%r, %r)', host, port)
    if host.endswith('.appspot.com'):
        msg = "socket_create_connection returns an empty list"
        try:
            if common.GAE_PREFER == 'http':
                hosts, timeout, step, shuffle = common.GAE_HTTP, common.GAE_HTTP_TIMEOUT, common.GAE_HTTP_STEP, 1
            else:
                hosts, timeout, step, shuffle = common.GAE_HTTPS, common.GAE_HTTPS_TIMEOUT, common.GAE_HTTPS_STEP, 1
            logging.debug("socket_create_connection connect hostslist: (%r, %r)", hosts, port)
            conn = MultiplexConnection(hosts[:], port, timeout, step, shuffle)
            conn.close()
            sock = conn.socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            return sock
        except socket.error, msg:
            logging.error('socket_create_connection connect fail: (%r, %r)', hosts, port)
            conn.close()
            sock = None
        if not sock:
            raise socket.error, msg
    else:
        return _socket_create_connection(address, timeout)
socket.create_connection = socket_create_connection

_httplib_HTTPConnection_putrequest = httplib.HTTPConnection.putrequest
def httplib_HTTPConnection_putrequest(self, method, url, skip_host=0, skip_accept_encoding=1):
    return _httplib_HTTPConnection_putrequest(self, method, url, skip_host, skip_accept_encoding)
httplib.HTTPConnection.putrequest = httplib_HTTPConnection_putrequest

class RootCA(object):
    '''RootCA module, based on WallProxy 0.4.0'''

    BASEDIR = os.path.dirname(__file__)

    def __init__(self):
        try:
            self.checkCA()
        except:
            pass

    def readFile(self, filename):
        try:
            f = open(filename, 'rb')
            c = f.read()
            f.close()
            return c
        except IOError:
            return None

    def writeFile(self, filename, content):
        f = open(filename, 'wb')
        f.write(str(content))
        f.close()

    def createKeyPair(self, type=None, bits=1024):
        if type is None:
            type = OpenSSL.crypto.TYPE_RSA
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(type, bits)
        return pkey

    def createCertRequest(self, pkey, digest='sha1', **subj):
        req = OpenSSL.crypto.X509Req()
        subject = req.get_subject()
        for k,v in subj.iteritems():
            setattr(subject, k, v)
        req.set_pubkey(pkey)
        req.sign(pkey, digest)
        return req

    def createCertificate(self, req, (issuerKey, issuerCert), serial, (notBefore, notAfter), digest='sha1'):
        cert = OpenSSL.crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(issuerKey, digest)
        return cert

    def loadPEM(self, pem, type):
        handlers = ('load_privatekey', 'load_certificate_request', 'load_certificate')
        return getattr(OpenSSL.crypto, handlers[type])(OpenSSL.crypto.FILETYPE_PEM, pem)

    def dumpPEM(self, obj, type):
        handlers = ('dump_privatekey', 'dump_certificate_request', 'dump_certificate')
        return getattr(OpenSSL.crypto, handlers[type])(OpenSSL.crypto.FILETYPE_PEM, obj)

    def makeCA(self):
        pkey = self.createKeyPair(bits=2048)
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': 'GoAgent',
                'organizationalUnitName': 'GoAgent Root', 'commonName': 'GoAgent CA'}
        req = self.createCertRequest(pkey, **subj)
        cert = self.createCertificate(req, (pkey, req), 0, (0, 60*60*24*7305))  #20 years
        return (self.dumpPEM(pkey, 0), self.dumpPEM(cert, 2))

    def makeCert(self, host, (cakey, cacrt), serial):
        pkey = self.createKeyPair()
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': host,
                'organizationalUnitName': 'GoAgent Branch', 'commonName': host}
        req = self.createCertRequest(pkey, **subj)
        cert = self.createCertificate(req, (cakey, cacrt), serial, (0, 60*60*24*7305))
        return (self.dumpPEM(pkey, 0), self.dumpPEM(cert, 2))

    def getCertificate(self, host):
        keyFile = '/sdcard/cert/ca.key'
        crtFile = '/sdcard/cert/ca.crt'
        return (keyFile, crtFile)

    def checkCA(self):
        #Check CA file
        cakeyFile = '/sdcard/cert/ca.key'
        cacrtFile = '/sdcard/cert/ca.crt'
        serialFile = '/sdcard/cert/serial'
        cakey = self.readFile(cakeyFile)
        cacrt = self.readFile(cacrtFile)
        self.SERIAL = self.readFile(serialFile)
        self.SERIAL = int(self.SERIAL)
        self.CA = (self.loadPEM(cakey, 0), self.loadPEM(cacrt, 2))

rootca = RootCA()

def gae_encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(str(v))) for k, v in dic.iteritems())

def gae_decode_data(qs):
    return dict((k, binascii.a2b_hex(v)) for k, v in (x.split('=') for x in qs.split('&')))

def build_opener():
    opener = urllib2.build_opener(urllib2.ProxyHandler(common.GAE_PROXY))
    opener.addheaders = []
    return opener

class GaeProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    partSize = 1024000
    fetchTimeout = 5
    FR_Headers = ('', 'host', 'vary', 'via', 'x-forwarded-for', 'proxy-authorization', 'proxy-connection', 'upgrade', 'keep-alive')
    opener = build_opener()

    def _fetch(self, url, method, headers, payload):
        errors = []
        params = {'url':url, 'method':method, 'headers':headers, 'payload':payload}
        if common.GAE_PASSWORD:
            params['password'] = common.GAE_PASSWORD
        params = gae_encode_data(params)
        params = zlib.compress(params, 9)
        for i in range(1, 4):
            try:
                gaehost = common.select_gaehost(url)
                fetchserver = '%s://%s%s' % (common.GAE_PREFER, gaehost, common.GAE_PATH)
                logging.debug('GaeProxyHandler fetch %r from %r', url, fetchserver)
                request = urllib2.Request(fetchserver, params)
                request.add_header('Content-Type', 'application/octet-stream')
                response = self.__class__.opener.open(request)
                data = response.read()
                response.close()
            except urllib2.HTTPError, e:
                # www.google.cn:80 is down, switch to https
                if e.code == 502 or e.code == 504:
                    common.GAE_PREFER = 'https'
                errors.append('%d: %s' % (e.code, httplib.responses.get(e.code, 'Unknown HTTPError')))
                continue
            except urllib2.URLError, e:
                if e.reason[0] in (11004, 10051, 10054, 10060, 'timed out'):
                    # it seems that google.cn is reseted, switch to https
                    if e.reason[0] == 10054:
                        common.GAE_PREFER = 'https'
                errors.append(str(e))
                continue
            except Exception, e:
                errors.append(repr(e))
                continue

            try:
                if data[0] == '0':
                    raw_data = data[1:]
                elif data[0] == '1':
                    raw_data = zlib.decompress(data[1:])
                else:
                    raise ValueError('Data format not match(%s)' % url)
                data = {}
                data['code'], hlen, clen = struct.unpack('>3I', raw_data[:12])
                if len(raw_data) != 12+hlen+clen:
                    raise ValueError('Data length not match')
                data['content'] = raw_data[12+hlen:]
                if data['code'] == 555:     #Urlfetch Failed
                    raise ValueError(data['content'])
                data['headers'] = gae_decode_data(raw_data[12:12+hlen])
                return (0, data)
            except Exception, e:
                errors.append(str(e))
        return (-1, errors)

    def _RangeFetch(self, m, data):
        m = map(int, m.groups())
        start = m[0]
        end = m[2] - 1
        if 'range' in self.headers:
            req_range = re.search(r'(\d+)?-(\d+)?', self.headers['range'])
            if req_range:
                req_range = [u and int(u) for u in req_range.groups()]
                if req_range[0] is None:
                    if req_range[1] is not None:
                        if m[1]-m[0]+1==req_range[1] and m[1]+1==m[2]:
                            return False
                        if m[2] >= req_range[1]:
                            start = m[2] - req_range[1]
                else:
                    start = req_range[0]
                    if req_range[1] is not None:
                        if m[0]==req_range[0] and m[1]==req_range[1]:
                            return False
                        if end > req_range[1]:
                            end = req_range[1]
            data['headers']['content-range'] = 'bytes %d-%d/%d' % (start, end, m[2])
        elif start == 0:
            data['code'] = 200
            del data['headers']['content-range']
        data['headers']['content-length'] = end-start+1
        partSize = self.__class__.partSize
        self.send_response(data['code'])
        for k,v in data['headers'].iteritems():
            self.send_header(k.title(), v)
        self.end_headers()
        if start == m[0]:
            self.wfile.write(data['content'])
            start = m[1] + 1
            partSize = len(data['content'])
        failed = 0
        logging.info('>>>>>>>>>>>>>>> Range Fetch started')
        while start <= end:
            self.headers['Range'] = 'bytes=%d-%d' % (start, start + partSize - 1)
            retval, data = self._fetch(self.path, self.command, self.headers, '')
            if retval != 0:
                time.sleep(4)
                continue
            m = re.search(r'bytes\s+(\d+)-(\d+)/(\d+)', data['headers'].get('content-range',''))
            if not m or int(m.group(1))!=start:
                if failed >= 1:
                    break
                failed += 1
                continue
            start = int(m.group(2)) + 1
            logging.info('>>>>>>>>>>>>>>> %s %d' % (data['headers']['content-range'], end))
            failed = 0
            self.wfile.write(data['content'])
        logging.info('>>>>>>>>>>>>>>> Range Fetch ended')
        self.connection.close()
        return True

    def do_METHOD(self):
        if self.path.startswith('/'):
            host = self.headers['host']
            if host.endswith(':80'):
                host = host[:-3]
            self.path = 'http://%s%s' % (host , self.path)

        payload_len = int(self.headers.get('content-length', 0))
        if payload_len > 0:
            payload = self.rfile.read(payload_len)
        else:
            payload = ''

        for k in self.__class__.FR_Headers:
            try:
                del self.headers[k]
            except KeyError:
                pass

        retval, data = self._fetch(self.path, self.command, self.headers, payload)
        try:
            if retval == -1:
                return self.end_error(502, str(data))
            if data['code']==206 and self.command=='GET':
                m = re.search(r'bytes\s+(\d+)-(\d+)/(\d+)', data['headers'].get('content-range',''))
                if m and self._RangeFetch(m, data):
                    return
            self.send_response(data['code'])
            for k,v in data['headers'].iteritems():
                self.send_header(k.title(), v)
            self.end_headers()
            self.wfile.write(data['content'])
        except socket.error, (err, _):
            # Connection closed before proxy return
            if err == errno.EPIPE or err == 10053:
                return
        self.connection.close()

    do_GET = do_METHOD
    do_POST = do_METHOD
    do_PUT = do_METHOD
    do_DELETE = do_METHOD

class PhpProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    pass

class ConnectProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(':')
        # I very very want to use suffix tree in this loop
        # https://hkn.eecs.berkeley.edu/~dyoo/python/suffix_trees/
        # BUT, sometimes this script is running in Linux/MAC...
        for hostpat, hosts in common.HOSTS:
            if host.endswith(hostpat):
                return self._direct(host, port, hosts, timeout=4, step=4)
        else:
            return self._forward()

    def _direct(self, host, port, hosts, timeout, step):
        DIRECT_KEEPLIVE = 60
        DIRECT_TICK = 2
        try:
            port  = int(port)
            if hosts:
                hosts = hosts.split('|')
            else:
                hosts = [x[-1][0] for x in socket.getaddrinfo(host, port)]
            self.log_message('ConnectProxyHandler MultiplexConnection to %s with %d hosts' % (self.path, len(hosts)))
            conn = MultiplexConnection(hosts, port, timeout, step)
            if conn.socket is None:
                return self.send_error(502, 'Cannot Connect to %s:%s' % (hosts, port))
            self.log_request(200)
            self.wfile.write('%s 200 Connection established\r\n' % self.protocol_version)
            self.wfile.write('Proxy-agent: %s\r\n\r\n' % self.version_string())

            socs = [self.connection, conn.socket]
            count = DIRECT_KEEPLIVE // DIRECT_TICK
            while 1:
                count -= 1
                (ins, _, errors) = select.select(socs, [], socs, DIRECT_TICK)
                if errors:
                    break
                if ins:
                    for soc in ins:
                        data = soc.recv(8192)
                        if data:
                            if soc is self.connection:
                                conn.socket.send(data)
                                # if packets lost in 10 secs, maybe ssl connection was dropped by GFW
                                count = 5
                            else:
                                self.connection.send(data)
                                count = DIRECT_KEEPLIVE // DIRECT_TICK
                if count == 0:
                    break
        except:
            logging.exception('Connect._direct Error')
            self.send_error(502, 'Connect._direct Error')
        finally:
            try:
                self.connection.close()
            except:
                pass
            try:
                conn.socket.close()
                conn.close()
            except:
                pass

    def _forward(self):
        # for ssl proxy
        host, _, port = self.path.rpartition(':')
        keyFile, crtFile = rootca.getCertificate(host)
        self.send_response(200)
        self.end_headers()
        try:
            ssl_sock = ssl.wrap_socket(self.connection, keyFile, crtFile, True)
        except ssl.SSLError, e:
            logging.exception('SSLError: %s', e)
            return

        # rewrite request line, url to abs
        first_line = ''
        while True:
            data = ssl_sock.read()
            # EOF?
            if data == '':
                # bad request
                ssl_sock.close()
                self.connection.close()
                return
            # newline(\r\n)?
            first_line += data
            if '\n' in first_line:
                first_line, data = first_line.split('\n', 1)
                first_line = first_line.rstrip('\r')
                break
        # got path, rewrite
        method, path, ver = first_line.split()
        if path.startswith('/'):
            path = 'https://%s%s' % (host if port=='443' else self.path, path)
        # connect to local proxy server
        listen_ip = {'0.0.0.0':'127.0.0.1','::':'::1'}.get(common.LISTEN_IP, common.LISTEN_IP)
        listen_port = common.LISTEN_PORT
        sock = socket.socket(LocalProxyServer.address_family, socket.SOCK_STREAM)
        sock.connect((listen_ip, listen_port))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32*1024)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.send('%s %s %s\r\n%s' % (method, path, ver, data))

        # forward https request
        ssl_sock.settimeout(1)
        while True:
            try:
                data = ssl_sock.read(8192)
            except ssl.SSLError, e:
                if str(e).lower().find('timed out') == -1:
                    # error
                    sock.close()
                    ssl_sock.close()
                    self.connection.close()
                    return
                # timeout
                break
            if data != '':
                sock.send(data)
            else:
                # EOF
                break

        ssl_sock.setblocking(True)
        # simply forward response
        while True:
            data = sock.recv(8192)
            if data != '':
                ssl_sock.write(data)
            else:
                # EOF
                break
        # clean
        sock.close()
        ssl_sock.shutdown(socket.SHUT_WR)
        ssl_sock.close()
        self.connection.close()

class LocalProxyHandler(ConnectProxyHandler, GaeProxyHandler):

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

    def send_response(self, code, message=None):
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = 'GoAgent Notify'
        if self.request_version != 'HTTP/0.9':
            self.wfile.write('%s %d %s\r\n' % (self.protocol_version, code, message))

    def end_error(self, code, message=None, data=None):
        if not data:
            self.send_error(code, message)
        else:
            self.send_response(code, message)
            self.wfile.write(data)
        self.connection.close()

##    def setup(self):
##        self.connection = self.request
##        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
##        self.rfile = self.connection.makefile('rb', self.rbufsize)
##        self.wfile = self.connection.makefile('wb', self.wbufsize)

    def finish(self):
        try:
            self.wfile.close()
            self.rfile.close()
        except socket.error, (err, _):
            # Connection closed by browser
            if err == errno.EPIPE or err == 10053:
                msg = 'Software caused connection abort'
                self.log_message('socket.error: [%s] %r', err, msg)
            else:
                raise

    do_CONNECT = ConnectProxyHandler.do_CONNECT
    do_GET     = GaeProxyHandler.do_GET
    do_POST    = GaeProxyHandler.do_POST
    do_PUT     = GaeProxyHandler.do_PUT
    do_DELETE  = GaeProxyHandler.do_DELETE

class LocalProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    address_family = {True:socket.AF_INET6, False:socket.AF_INET}[':' in common.LISTEN_IP]
    daemon_threads = True

if __name__ == '__main__':
    '''show current config'''
    print '--------------------------------------------'
    print 'OpenSSL Mode : %s' % {True:'Enabled', False:'Disabled'}[openssl_enabled]
    print 'Listen Addr  : %s:%d' % (common.LISTEN_IP, common.LISTEN_PORT)
    if common.GAE_PROXY:
        print 'Local Proxy  : %s' % common.GAE_PROXY
    print 'GAE Mode     : %s' % common.GAE_PREFER
    print 'GAE Servers  : %s' % common.GAE_HOST
    if common.GAE_BINDHOSTS:
        print 'GAE BindHost : %s' % common.GAE_BINDHOSTS
    print '--------------------------------------------'
    if os.name == 'nt' and not common.LISTEN_VISIBLE:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    httpd = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), LocalProxyHandler)
    httpd.serve_forever()
