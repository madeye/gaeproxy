#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by Hust Moon <www.ehust@gmail.com>
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>
#      Hewig Xu       <hewigovens@gmail.com>
#      Ayanamist Yang <ayanamist@gmail.com>
#      Max Lv         <max.c.lv@gmail.com>
#      AlsoTang       <alsotang@gmail.com>
#      Yonsm          <YonsmGuo@gmail.com>

__version__ = '2.0.13'
__config__  = 'proxy.ini'

import sys
import os

try:
    import gevent
    import gevent.queue
    import gevent.monkey
    import gevent.coros
    import gevent.server
    import gevent.pool
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    if os.name == 'nt':
        sys.stderr.write('WARNING: python-gevent not installed. `http://code.google.com/p/gevent/downloads/list`\n')
    else:
        sys.stderr.write('WARNING: python-gevent not installed. `curl -k -L http://git.io/I9B7RQ|sh`\n')
    import Queue
    import thread
    import threading
    import SocketServer

    def GeventImport(name):
        import sys
        sys.modules[name] = type(sys)(name)
        return sys.modules[name]
    def GeventSpawn(target, *args, **kwargs):
        return thread.start_new_thread(target, args, kwargs)
    def GeventSpawnLater(seconds, target, *args, **kwargs):
        def wrap(*args, **kwargs):
            import time
            time.sleep(seconds)
            return target(*args, **kwargs)
        return thread.start_new_thread(wrap, args, kwargs)
    class GeventServerStreamServer(SocketServer.ThreadingTCPServer):
        allow_reuse_address = True
        def finish_request(self, request, client_address):
            self.RequestHandlerClass(request, client_address)
    class GeventPoolPool(object):
        def __init__(self, size):
            self._lock = threading.Semaphore(size)
        def __target_wrapper(self, target, args, kwargs):
            t = threading.Thread(target=target, args=args, kwargs=kwargs)
            try:
                t.start()
                t.join()
            except Exception as e:
                logging.error('threading.Thread target=%r error:%s', target, e)
            finally:
                self._lock.release()
        def spawn(self, target, *args, **kwargs):
            self._lock.acquire()
            return thread.start_new_thread(self.__target_wrapper, (target, args, kwargs))

    gevent        = GeventImport('gevent')
    gevent.queue  = GeventImport('gevent.queue')
    gevent.coros  = GeventImport('gevent.coros')
    gevent.server = GeventImport('gevent.server')
    gevent.pool   = GeventImport('gevent.pool')

    gevent.queue.Queue         = Queue.Queue
    gevent.coros.Semaphore     = threading.Semaphore
    gevent.spawn               = GeventSpawn
    gevent.spawn_later         = GeventSpawnLater
    gevent.server.StreamServer = GeventServerStreamServer
    gevent.pool.Pool           = GeventPoolPool

    del GeventImport, GeventSpawn, GeventSpawnLater, GeventServerStreamServer, GeventPoolPool

import collections
import errno
import time
import cStringIO
import struct
import re
import zlib
import random
import httplib
import base64
import urlparse
import socket
import ssl
import select
import traceback
import hashlib
import fnmatch
import logging
import ConfigParser
import SocketServer
import thread
import urllib2
import threading
try:
    import ctypes
except ImportError:
    ctypes = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import sqlite3
except ImportError:
    sqlite3 = None
    
class DNSCacheUtil(object):
    '''DNSCache module, integrated with GAEProxy'''

    cache = {"127.0.0.1": 'localhost'}

    @staticmethod
    def getHost(address):

        if DNSCacheUtil.cache.has_key(address):
            return DNSCacheUtil.cache[address]

        host = "www.google.com"

        if sqlite3 is not None:
            try:
                conn = sqlite3.connect('/data/data/org.gaeproxy/databases/dnscache.db')
            except Exception:
                logging.exception('DNSCacheUtil.initConn failed')
                conn = None

        if conn is not None:
            try:
                c = conn.cursor()
                c.execute("select request from dnsresponse where address = '%s'"
                        % address)
                row = c.fetchone()
                if row is not None:
                    host = row[0]
                    DNSCacheUtil.cache[address] = host
                c.close()
                conn.close()
            except Exception:
                logging.exception('DNSCacheUtil.getHost failed: %s', address)

        return host

class CertUtil(object):
    """CertUtil module, based on mitmproxy"""

    ca_lock = threading.Lock()

    @staticmethod
    def create_ca():
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = 'GoAgent'
        subj.organizationalUnitName = 'GoAgent Root'
        subj.commonName = 'GoAgent'
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA'),
            OpenSSL.crypto.X509Extension(b'extendedKeyUsage', True,
                b'serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca),
            ])
        ca.sign(key, 'sha1')
        return key, ca

    @staticmethod
    def dump_ca(keyfile='CA.key', certfile='CA.crt'):
        key, ca = CertUtil.create_ca()
        with open(keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))

    @staticmethod
    def _get_cert(commonname, certdir='certs', ca_keyfile='CA.key', ca_certfile='CA.crt', sans = []):
        with open(ca_keyfile, 'rb') as fp:
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, fp.read())
        with open(ca_certfile, 'rb') as fp:
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())

        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationalUnitName = 'GoAgent Branch'
        if commonname[0] == '.':
            subj.commonName = '*' + commonname
            subj.organizationName = '*' + commonname
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            subj.commonName = commonname
            subj.organizationName = commonname
            sans = [commonname] + [x for x in sans if x != commonname]
        req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha1')

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        try:
            cert.set_serial_number(int(hashlib.md5(commonname).hexdigest(), 16))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time()*1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        if commonname[0] == '.':
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            sans = [commonname] + [x for x in sans if x != commonname]
        cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, 'sha1')

        keyfile  = os.path.join(certdir, commonname + '.key')
        with open(keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        certfile = os.path.join(certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))

        return keyfile, certfile

    @staticmethod
    def get_cert(commonname, certdir='certs', ca_keyfile='CA.key', ca_certfile='CA.crt', sans = []):
        if len(commonname) >= 32 and commonname.count('.') >= 2:
            commonname = re.sub(r'^[^\.]+', '', commonname)
        keyfile  = os.path.join(certdir, commonname + '.key')
        certfile = os.path.join(certdir, commonname + '.crt')
        if os.path.exists(certfile):
            return keyfile, certfile
        elif OpenSSL is None:
            return ca_keyfile, ca_certfile
        else:
            with CertUtil.ca_lock:
                if os.path.exists(certfile):
                    return keyfile, certfile
                return CertUtil._get_cert(commonname, certdir, ca_keyfile, ca_certfile, sans)

    @staticmethod
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CA.key')
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.name == 'nt':
                os.system('certmgr.exe -del -n "GoAgent CA" -c -s -r localMachine Root')
            [os.remove(os.path.join('certs', x)) for x in os.listdir('certs')]
            CertUtil.dump_ca('CA.key', 'CA.crt')
            #Check CA imported
        cmd = {
            'win32'  : r'cd /d "%s" && certmgr.exe -add CA.crt -c -s -r localMachine Root >NUL' % os.path.dirname(capath),
            }.get(sys.platform)
        if cmd and os.system(cmd) != 0:
            logging.warning('GoAgent install trusted root CA certificate failed, Please run goagent by administrator/root.')
            #Check Certs Dir
        certdir = os.path.join(os.path.dirname(__file__), 'certs')
        if not os.path.exists(certdir):
            os.makedirs(certdir)

class Http(object):
    """Http Request Class"""

    MessageClass = dict
    protocol_version = 'HTTP/1.1'
    skip_headers = frozenset(['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'Keep-Alive'])

    def __init__(self, min_window=3, max_window=64, max_retry=2, max_timeout=30, proxy_uri=''):
        self.min_window = min_window
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.window = min_window
        self.window_ack = 0
        self.timeout = max_timeout // 2
        self.dns = collections.defaultdict(set)
        self.crlf = 0
        if proxy_uri:
            scheme, netloc = urlparse.urlparse(proxy_uri)[:2]
            if '@' in netloc:
                self.proxy = re.search(r'([^:]+):([^@]+)@(.+):(\d+)', netloc).group(1,2,3,4)
            else:
                self.proxy = (None, None) + (re.match('(.+):(\d+)', netloc).group(1,2))
        else:
            self.proxy = ''

    def dns_resolve(self, host, dnsserver='', ipv4_only=True):
        iplist = self.dns[host]
        if not iplist:
            iplist = self.dns[host] = self.dns.default_factory([])
            if not dnsserver:
                ips = [x[-1][0] for x in socket.getaddrinfo(host, 80)]
            else:
                #resolver = gevent.resolver_ares.Resolver(servers=[dnsserver], tcp_port=53)
                #ips = [x[-1][0] for x in resolver.getaddrinfo(host, 80)]
                index = os.urandom(2)
                hoststr = ''.join(chr(len(x))+x for x in host.split('.'))
                data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (index, hoststr)
                data = struct.pack('!H', len(data)) + data
                address_family = socket.AF_INET6 if ':' in dnsserver else socket.AF_INET
                sock = None
                try:
                    sock = socket.socket(family=address_family)
                    sock.connect((dnsserver, 53))
                    sock.sendall(data)
                    rfile = sock.makefile('rb')
                    size = struct.unpack('!H', rfile.read(2))[0]
                    data = rfile.read(size)
                    ips = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xC0.\x00\x01\x00\x01.{6}(.{4})', data)]
                except Exception, e:
                    raise
                finally:
                    if sock:
                        sock.close()
            if ipv4_only:
                ips = [ip for ip in ips if re.match(r'\d+.\d+.\d+.\d+', ip)]
            iplist.update(ips)
        return iplist

    def create_connection(self, (host, port), timeout=None, source_address=None):
        logging.debug('Http.create_connection connect (%r, %r)', host, port)
        for i in xrange(self.max_retry):
            try:
                iplist = self.dns_resolve(host)
                window = self.window
                ips = iplist if len(iplist) <= window else random.sample(iplist, int(window))
                sock  = None
                socks = []
                for ip in ips:
                    sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
                    sock.setblocking(0)
                    sock.connect_ex((ip, port))
                    socks.append(sock)
                _, outs, _ = select.select([], socks, [], self.timeout)
                if outs:
                    sock = outs.pop(0)
                    sock.setblocking(1)
                    if window > self.min_window:
                        self.window_ack += 1
                        if self.window_ack > 10:
                            self.window_ack = 0
                            self.window = window - 1
                            logging.info('Http.create_connection to (%s, %r) successed, switch window=%r', iplist, port, self.window)
                    socks.remove(sock)
                    #any(self._socket_queue.put(x) for x in socks)
                    if socks:
                        gevent.spawn_later(1, lambda ss:any(x.close() for x in ss), socks)
                    return sock
                else:
                    self.window = int(round(1.5 * self.window))
                    if self.window > self.max_window:
                        self.window = self.max_window
                    if self.min_window <= len(iplist) < self.window:
                        self.window = len(iplist)
                    self.window_ack = 0
                    logging.error('Http.create_connection to (%s, %r) failed, switch window=%r', ips, port, self.window)
            except Exception as e:
                logging.error('%s', e)

    def create_connection_withproxy(self, (host, port), timeout=None, source_address=None, proxy=None):
        logging.debug('Http.create_connection_withproxy connect (%r, %r)', host, port)
        username, password, proxyhost, proxyport = proxy
        try:
            proxyip = self.dns_resolve(proxyhost)
            sock = socket.socket(socket.AF_INET if ':' not in proxyip else socket.AF_INET6)
            sock.connect((proxyip, proxyport))
            hostname = random.sample(self.dns[host] or [host], 1)[0]
            request_data = 'CONNECT %s:%s\r\n' % (hostname, port)
            if username and password:
                request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode('%s:%s' % (username, password))
            request_data += '\r\n'
            sock.sendall(request_data)
            data = ''
            while not data.endswith('\r\n\r\n'):
                data += sock.recv(1)
            return sock
        except socket.error as e:
            logging.error('Http.create_connection_withproxy error %s', e)

    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, trans=''):
        try:
            timecount = timeout
            while 1:
                timecount -= tick
                if timecount <= 0:
                    break
                (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
                if errors:
                    break
                if ins:
                    for sock in ins:
                        data = sock.recv(bufsize)
                        if trans:
                            data = data.translate(trans)
                        if data:
                            if sock is local:
                                remote.sendall(data)
                                timecount = maxping or timeout
                            else:
                                local.sendall(data)
                                timecount = maxpong or timeout
                        else:
                            return
        except socket.error as e:
            if e[0] not in (10053, 10054, errno.EPIPE):
                raise
        finally:
            local.close()
            remote.close()

    def parse_request(self, rfile, bufsize=8192):
        line = rfile.readline(bufsize)
        if not line:
            raise socket.error('empty line')
        method, path, version = line.split(' ', 2)
        headers = self.MessageClass()
        while 1:
            line = rfile.readline(bufsize)
            if not line or line == '\r\n':
                break
            keyword, _, value = line.partition(':')
            keyword = keyword.title()
            value = value.strip()
            headers[keyword] = value
        return method, path, version, headers

    def _request(self, sock, method, path, protocol_version, headers, data, bufsize=8192, crlf=0):
        skip_headers = self.skip_headers

        request_data = '\r\n' * (crlf or self.crlf)
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems() if k not in skip_headers)
        if self.proxy:
            username, password, _, _ = self.proxy
            request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode('%s:%s' % (username, password))
        request_data += '\r\n' if not data else '\r\n'+data
        wfile = sock.makefile('wb', 0)
        wfile.write(request_data)

        rfile = sock.makefile('rb', -1)

        response_line = rfile.readline(bufsize)
        if not response_line:
            raise socket.error('empty line')
        version, code, _ = response_line.split(' ', 2)
        code = int(code)

        headers = {}
        content_length = 0
        connection = ''
        transfer_encoding = ''
        while 1:
            line = rfile.readline(bufsize)
            if not line or line == '\r\n':
                break
            keyword, _, value = line.partition(':')
            keyword = keyword.title()
            headers[keyword] = value.strip()
        return code, headers, rfile

    def request(self, method, url, data=None, headers={}, fullurl=False, bufsize=8192, crlf=0):
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
        if not re.search(r':\d+$', netloc):
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query

        if 'Host' not in headers:
            headers['Host'] = host

        for i in xrange(self.max_retry):
            sock = None
            try:
                if not self.proxy:
                    sock = self.create_connection((host, port), self.timeout)
                else:
                    sock = self.create_connection_withproxy((host, port), port, self.timeout, None, proxy=self.proxy)
                if sock:
                    if scheme == 'https':
                        sock = ssl.wrap_socket(sock)
                    code, headers, rfile = self._request(sock, method, path, self.protocol_version, headers, data, bufsize=bufsize, crlf=crlf)
                    return code, headers, rfile
            except Exception as e:
                logging.debug('Http.request "%s %s" failed:%s', method, url, e)
                if sock:
                    sock.close()
                continue

    def copy_response(self, code, headers, write=None):
        need_return = False
        if write is None:
            output = cStringIO.StringIO()
            write = output.write
            need_return = True
        if 'Set-Cookie' in headers:
            headers['Set-Cookie'] = re.sub(', ([^ =]+(?:=|$))', '\\r\\nSet-Cookie: \\1', headers['Set-Cookie'])
        write('HTTP/1.1 %s\r\n%s\r\n' % (code, ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems() if k != 'Transfer-Encoding')))
        if need_return:
            return output.getvalue()

    def copy_body(self, rfile, headers, content_length=0, bufsize=8192, write=None):
        need_return = False
        if write is None:
            output = cStringIO.StringIO()
            write = output.write
            need_return = True
        content_length = int(headers.get('Content-Length', content_length))
        if content_length:
            left = content_length
            while left > 0:
                data = rfile.read(min(left, bufsize))
                if not data:
                    break
                left -= len(data)
                write(data)
        elif headers.get('Connection', '').lower() == 'close':
            while 1:
                data = rfile.read(bufsize)
                if not data:
                    break
                write(data)
        elif headers.get('Transfer-Encoding', '').lower() == 'chunked':
            while 1:
                line = rfile.readline(bufsize)
                if not line:
                    break
                if line == '\r\n':
                    continue
                count = int(line , 16)
                if count == 0:
                    break
                else:
                    write(rfile.read(count))
        else:
            pass
        if need_return:
            return output.getvalue()

class Common(object):
    """Global Config Object"""

    def __init__(self):
        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        # GAEProxy Patch
        self.CONFIG.read('/data/data/org.gaeproxy/proxy.ini')

        self.LISTEN_IP            = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT          = self.CONFIG.getint('listen', 'port')
        self.LISTEN_VISIBLE       = self.CONFIG.getint('listen', 'visible')
        self.LISTEN_DEBUGINFO     = self.CONFIG.getint('listen', 'debuginfo') if self.CONFIG.has_option('listen', 'debuginfo') else 0

        self.GAE_APPIDS           = self.CONFIG.get('gae', 'appid').replace('.appspot.com', '').split('|')
        self.GAE_PASSWORD         = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH             = self.CONFIG.get('gae', 'path')
        self.GAE_PROFILE          = self.CONFIG.get('gae', 'profile')
        self.GAE_MULCONN          = self.CONFIG.getint('gae', 'mulconn')

        self.PAAS_ENABLE           = self.CONFIG.getint('paas', 'enable')
        self.PAAS_LISTEN           = self.CONFIG.get('paas', 'listen')
        self.PAAS_PASSWORD         = self.CONFIG.get('paas', 'password') if self.CONFIG.has_option('paas', 'password') else ''
        self.PAAS_FETCHSERVER      = self.CONFIG.get('paas', 'fetchserver')

        if self.CONFIG.has_section('socks5'):
            self.SOCKS5_ENABLE           = self.CONFIG.getint('socks5', 'enable')
            self.SOCKS5_LISTEN           = self.CONFIG.get('socks5', 'listen')
            self.SOCKS5_PASSWORD         = self.CONFIG.get('socks5', 'password') if self.CONFIG.has_option('socks5', 'password') else ''
            self.SOCKS5_FETCHSERVER      = self.CONFIG.get('socks5', 'fetchserver')
        else:
            self.SOCKS5_ENABLE           = 0

        if self.CONFIG.has_section('pac'):
            # XXX, cowork with GoAgentX
            self.PAC_ENABLE           = self.CONFIG.getint('pac','enable')
            self.PAC_IP               = self.CONFIG.get('pac','ip')
            self.PAC_PORT             = self.CONFIG.getint('pac','port')
            self.PAC_FILE             = self.CONFIG.get('pac','file').lstrip('/')
            self.PAC_GFWLIST          = self.CONFIG.get('pac', 'gfwlist')
        else:
            self.PAC_ENABLE           = 0

        self.PROXY_ENABLE         = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_HOST           = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT           = self.CONFIG.getint('proxy', 'port')
        self.PROXY_USERNAME       = self.CONFIG.get('proxy', 'username')
        self.PROXY_PASSWROD       = self.CONFIG.get('proxy', 'password')

        if self.PROXY_ENABLE:
            if self.PROXY_USERNAME:
                self.proxy_uri = 'http://%s:%s@%s:%d' % (self.PROXY_USERNAME, self.PROXY_PASSWROD, self.PROXY_HOST, self.PROXY_PORT)
            else:
                self.proxy_uri = 'http://%s:%s' % (self.PROXY_HOST, self.PROXY_PORT)
        else:
            self.proxy_uri = ''

        self.GOOGLE_MODE          = self.CONFIG.get(self.GAE_PROFILE, 'mode')
        self.GOOGLE_HOSTS         = tuple(self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|'))
        self.GOOGLE_SITES         = tuple(self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|'))
        self.GOOGLE_FORCEHTTPS    = frozenset(self.CONFIG.get(self.GAE_PROFILE, 'forcehttps').split('|'))
        self.GOOGLE_WITHGAE       = frozenset(self.CONFIG.get(self.GAE_PROFILE, 'withgae').split('|'))

        self.AUTORANGE_HOSTS      = tuple(self.CONFIG.get('autorange', 'hosts').split('|'))
        self.AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in self.AUTORANGE_HOSTS)
        self.AUTORANGE_MAXSIZE    = self.CONFIG.getint('autorange', 'maxsize')
        self.AUTORANGE_WAITSIZE   = self.CONFIG.getint('autorange', 'waitsize')
        self.AUTORANGE_BUFSIZE    = self.CONFIG.getint('autorange', 'bufsize')
        self.AUTORANGE_THREADS    = self.CONFIG.getint('autorange', 'threads')

        self.FETCHMAX_LOCAL       = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER      = self.CONFIG.get('fetchmax', 'server')

        if self.CONFIG.has_section('crlf'):
            # XXX, cowork with GoAgentX
            self.CRLF_ENABLE          = self.CONFIG.getint('crlf', 'enable')
            self.CRLF_DNSSERVER       = self.CONFIG.get('crlf', 'dns')
            self.CRLF_SITES           = tuple(self.CONFIG.get('crlf', 'sites').split('|'))
        else:
            self.CRLF_ENABLE          = 0

        self.USERAGENT_ENABLE     = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING     = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE          = self.CONFIG.getint('love','enable')
        self.LOVE_TIMESTAMP       = self.CONFIG.get('love', 'timestamp')
        self.LOVE_TIP             = [re.sub(r'(?i)\\u([0-9a-f]{4})', lambda m:unichr(int(m.group(1),16)), x) for x in self.CONFIG.get('love','tip').split('|')]

        self.HOSTS                = dict((k, tuple(v.split('|')) if v else tuple()) for k, v in self.CONFIG.items('hosts'))

        self.build_gae_fetchserver()

    def build_gae_fetchserver(self):
        """rebuild gae fetch server config"""
        if self.PROXY_ENABLE:
            self.GOOGLE_MODE = 'https'
        # append '?' to url, it can avoid china telicom/unicom AD
        self.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (self.GOOGLE_MODE, self.GAE_APPIDS[0], self.GAE_PATH)

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version    : %s (python/%s gevent/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], getattr(gevent, '__version__', None), (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP,self.LISTEN_PORT)
        info += 'Local Proxy        : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug INFO         : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += 'GAE Mode           : %s\n' % self.GOOGLE_MODE
        info += 'GAE Profile        : %s\n' % self.GAE_PROFILE
        info += 'GAE APPID          : %s\n' % '|'.join(self.GAE_APPIDS)
        if common.PAAS_ENABLE:
            info += 'PAAS Listen        : %s\n' % common.PAAS_LISTEN
            info += 'PAAS FetchServer   : %s\n' % common.PAAS_FETCHSERVER
        if common.SOCKS5_ENABLE:
            info += 'SOCKS5 Listen      : %s\n' % common.SOCKS5_LISTEN
            info += 'SOCKS5 FetchServer : %s\n' % common.SOCKS5_FETCHSERVER
        if common.PAC_ENABLE:
            info += 'Pac Server         : http://%s:%d/%s\n' % (self.PAC_IP,self.PAC_PORT,self.PAC_FILE)
        if common.CRLF_ENABLE:
            #http://www.acunetix.com/websitesecurity/crlf-injection.htm
            info += 'CRLF Injection     : %s\n' % '|'.join(self.CRLF_SITES)
        info += '------------------------------------------------------\n'
        return info

common = Common()
http   = Http(proxy_uri=common.proxy_uri)

def encode_request(headers, **kwargs):
    if hasattr(headers, 'items'):
        headers = headers.items()
    data = ''.join('%s: %s\r\n' % (k, v) for k, v in headers) + ''.join('X-Goa-%s: %s\r\n' % (k.title(), v) for k, v in kwargs.iteritems())
    return base64.b64encode(zlib.compress(data)).rstrip()

def decode_request(request):
    data     = zlib.decompress(base64.b64decode(request))
    headers  = {}
    kwargs   = {}
    for line in data.splitlines():
        keyword, _, value = line.partition(':')
        if keyword.startswith('X-Goa-'):
            kwargs[keyword[6:].lower()] = value.strip()
        else:
            headers[keyword.title()] = value.strip()
    return headers, kwargs

def pack_request(method, url, headers, payload, fetchserver, **kwargs):
    content_length = int(headers.get('Content-Length',0))
    request_kwargs = {'method':method, 'url':url}
    request_kwargs.update(kwargs)
    request_headers = {'Host':urlparse.urlparse(fetchserver).netloc, 'Cookie':encode_request(headers, **request_kwargs), 'Content-Length':str(content_length)}
    if not isinstance(payload, str):
        payload = payload.read(content_length)
    return 'POST', request_headers, payload

class RangeFetch(object):
    """Range Fetch Class"""

    maxsize   = 1024*1024*4
    bufsize   = 8192
    waitsize  = 1024*512
    threads   = 1
    retry     = 8

    def __init__(self, sock, response_code, response_headers, response_rfile, method, url, headers, payload, fetchservers, password, maxsize=0, bufsize=0, waitsize=0, threads=0):
        self.response_code = response_code
        self.response_headers = response_headers
        self.response_rfile = response_rfile
        self.method = method
        self.url = url
        self.headers = headers
        self.payload = payload
        self.fetchservers = fetchservers
        self.password = password

        if maxsize:
            self.maxsize = maxsize
        if bufsize:
            self.bufsize = bufsize
        if waitsize:
            self.waitsize = waitsize
        if threads:
            self.threads = threads

        self._sock = sock
        self._stopped = None

    def fetch(self):
        response_headers = self.response_headers
        response_rfile   = self.response_rfile
        content_range    = response_headers['Content-Range']
        content_length   = response_headers['Content-Length']
        start, end, length = map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
        if start == 0:
            response_status = 200
            response_headers['Content-Length'] = str(length)
        else:
            response_status = 206
            if not self.headers.get('Range'):
                response_headers['Content-Range']  = 'bytes %s-%s/%s' % (start, length-1, length)
                response_headers['Content-Length'] = str(length-start)

        logging.info('>>>>>>>>>>>>>>> Range Fetch started(%r) %d-%d', self.url, start, end)
        self._sock.sendall('HTTP/1.1 %s\r\n%s\r\n' % (response_status, ''.join('%s: %s\r\n' % (k.title(),v) for k,v in response_headers.iteritems())))

        queues = [gevent.queue.Queue() for _ in range(end+1, length, self.maxsize)]
        gevent.spawn_later(0.5, self._poolfetch, min(len(queues), self.threads), queues, end, length, self.maxsize)

        try:
            left = end-start+1
            while 1:
                data = response_rfile.read(min(self.bufsize, left))
                if not data:
                    response_rfile.close()
                    break
                else:
                    self._sock.sendall(data)
                    left -= len(data)
            while queues:
                queue = queues.pop(0)
                while 1:
                    data = queue.get()
                    if data is StopIteration:
                        break
                    self._sock.sendall(data)
            logging.info('>>>>>>>>>>>>>>> Range Fetch ended(%r)', urlparse.urlparse(self.url).netloc)
        except socket.error as e:
            self._stopped = True
            if e[0] not in (10053, errno.EPIPE):
                logging.exception('Range Fetch socket.error: %s', e)
                raise

    def _poolfetch(self, size, queues, end, length, maxsize):
        pool = gevent.pool.Pool(size)
        for queue, partial_start in zip(queues, range(end+1, length, maxsize)):
            pool.spawn(self._fetch, queue, partial_start, min(length, partial_start+maxsize-1))

    def _fetch(self, queue, start, end):
        try:
            if self._stopped:
                queue.put(StopIteration)
                return
            headers = self.headers.copy()
            headers['Range'] = 'bytes=%d-%d' % (start, end)
            headers['Connection'] = 'close'
            for i in xrange(self.retry):
                fetchserver = random.choice(self.fetchservers)
                request_method, request_headers, request_payload = pack_request(self.method, self.url, headers, self.payload, fetchserver, password=self.password)
                response = http.request(request_method, fetchserver, request_payload, request_headers)
                if not response:
                    logging.warning('Range Fetch %r %s failed(%s)', self.url, headers['Range'], response)
                    time.sleep(5)
                    continue
                response_code, response_headers, response_rfile = response
                if 'Set-Cookie' not in response_headers:
                    logging.warning('Range Fetch %r %s return %s', self.url, headers['Range'], response_code)
                    time.sleep(5)
                    continue
                response_headers, response_kwargs = decode_request(response_headers['Set-Cookie'])
                response_code = int(response_kwargs['status'])
                if 200 <= response_code < 300:
                    break
                elif 300 <= response_code < 400:
                    self.url = response_headers['Location']
                    logging.info('Range Fetch Redirect(%r)', self.url)
                    response_rfile.close()
                    continue
                else:
                    logging.error('Range Fetch %r return %s', self.url, response_code)
                    response_rfile.close()
                    time.sleep(5)
                    continue

            content_range = response_headers.get('Content-Range')
            if not content_range:
                logging.error('Range Fetch "%s %s" failed: response_kwargs=%s response_headers=%s', self.method, self.url, response_kwargs, response_headers)
                return
            content_length = int(response_headers['Content-Length'])
            logging.info('>>>>>>>>>>>>>>> [thread %s] %s %s', thread.get_ident(), content_length, content_range)

            left = content_length
            while 1:
                data = response_rfile.read(min(self.bufsize, left))
                if not data:
                    response_rfile.close()
                    queue.put(StopIteration)
                    break
                else:
                    queue.put(data)
                    left -= len(data)
        except Exception as e:
            logging.exception('_fetch error:%s', e)
            raise

def gaeproxy_handler(sock, address, ls={'setuplock':gevent.coros.Semaphore()}):
    rfile = sock.makefile('rb', 8192)
    try:
        method, path, version, headers = http.parse_request(rfile)
    except socket.error as e:
        if e[0] in ('empty line', 10053, errno.EPIPE):
            return rfile.close()
        raise

    if 'setup' not in ls:
        http.dns.update(common.HOSTS)
        fetchhosts = ['%s.appspot.com' % x for x in common.GAE_APPIDS]
        if common.GAE_PROFILE == 'google_ipv6':
            for fetchhost in fetchhosts:
                http.dns[fetchhost] = http.dns.default_factory(common.GOOGLE_HOSTS)
        elif not common.PROXY_ENABLE:
            logging.info('resolve common.GOOGLE_HOSTS domian=%r to iplist', common.GOOGLE_HOSTS)
            if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                with ls['setuplock']:
                    if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                        google_ipmap = dict((g, [x[-1][0] for x in socket.getaddrinfo(g, 80) if re.match(r'\d+\.\d+\.\d+\.\d+', x[-1][0])]) for g in common.GOOGLE_HOSTS)
                        need_resolve_remote = [x for x in google_ipmap if not re.match(r'\d+\.\d+\.\d+\.\d+', x) and len(google_ipmap[x]) <= 1]
                        try:
                            for g in need_resolve_remote:
                                logging.info('resolve remote domian=%r to iplist', g)
                                google_ipmap[g] = list(http.dns_resolve(g, common.CRLF_DNSSERVER))
                                logging.info('resolve remote domian=%r to iplist=%s', g, google_ipmap[g])
                        except socket.error as e:
                            logging.exception('resolve remote domain=%r failed: %s', need_resolve_remote, e)
                        common.GOOGLE_HOSTS = tuple(set(sum(google_ipmap.values(), [])))
                        if len(common.GOOGLE_HOSTS) == 0:
                            logging.error('resolve %s domian return empty! please use ip list to replace domain list!', common.GAE_PROFILE)
                            sys.exit(-1)
            for fetchhost in fetchhosts:
                http.dns[fetchhost] = http.dns.default_factory(common.GOOGLE_HOSTS)
            logging.info('resolve common.GOOGLE_HOSTS domian to iplist=%r', common.GOOGLE_HOSTS)
        ls['setup'] = True

    if common.USERAGENT_ENABLE:
        headers['User-Agent'] = common.USERAGENT_STRING

    remote_addr, remote_port = address

    __realsock = None
    __realrfile = None
    if method == 'CONNECT':
        host, _, port = path.rpartition(':')
        # GAEProxy Patch
        p = "(?:\d{1,3}\.){3}\d{1,3}"
        if re.match(p, host) is not None:
            host = DNSCacheUtil.getHost(host)
        port = int(port)
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            logging.info('%s:%s "%s %s:%d HTTP/1.1" - -' % (remote_addr, remote_port, method, host, port))
            http_headers = ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems())
            if not common.PROXY_ENABLE:
                if host not in http.dns:
                    http.dns[host] = http.dns.default_factory(common.GOOGLE_HOSTS)
                remote = http.create_connection((host, port), 8)
            else:
                remote = socket.create_connection((host, int(port)))
                remote.send('CONNECT %s:%s\r\n%s\r\n' % (host, port, http_headers))
            if not remote:
                logging.error('Connect remote host(%r) failed', host)
                return
            sock.send('HTTP/1.1 200 OK\r\n\r\n')
            http.forward_socket(sock, remote)
            return
        else:
            keyfile, certfile = CertUtil.get_cert(host)
            logging.info('%s:%s "%s %s:%d HTTP/1.1" - -' % (remote_addr, remote_port, method, host, port))
            sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
            __realsock = sock
            __realrfile = rfile
            try:
                sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True)
            except Exception as e:
                logging.exception('ssl.wrap_socket(__realsock=%r) failed: %s', __realsock, e)
                sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
            rfile = sock.makefile('rb', 8192)
            try:
                method, path, version, headers = http.parse_request(rfile)
            except socket.error as e:
                if e[0] in ('empty line', 10053, errno.EPIPE):
                    return rfile.close()
                raise
            if path[0] == '/' and host:
                path = 'https://%s%s' % (headers['Host'], path)

    host = headers.get('Host', '')
    if path[0] == '/' and host:
        path = 'http://%s%s' % (host, path)

    need_direct = False
    need_crlf   = 0
    if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
        if host in common.GOOGLE_FORCEHTTPS:
            sock.sendall('HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % path.replace('http://', 'https://'))
            return
        else:
            if host not in http.dns:
                http.dns[host] = http.dns.default_factory(common.GOOGLE_HOSTS)
            need_crlf   = 1
            need_direct = True
    elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
        if host not in http.dns:
            logging.info('crlf dns_resolve(host=%r, dnsservers=%r)', host, common.CRLF_DNSSERVER)
            http.dns[host] = set(http.dns_resolve(host, common.CRLF_DNSSERVER))
            logging.info('crlf dns_resolve(host=%r) return %s', host, list(http.dns[host]))
        need_crlf = 1
        need_direct = True

    if need_direct:
        try:
            logging.info('%s:%s "%s %s HTTP/1.1" - -' % (remote_addr, remote_port, method, path))
            content_length = int(headers.get('Content-Length', 0))
            payload = rfile.read(content_length) if content_length else None
            response = http.request(method, path, payload, headers, crlf=need_crlf)
            if not response:
                logging.warning('http.request "%s %s") return %r', method, path, response)
                return
            response_code, response_headers, response_rfile = response
            wfile = sock.makefile('wb', 0)
            http.copy_response(response_code, response_headers, write=wfile.write)
            http.copy_body(response_rfile, response_headers, write=wfile.write)
            response_rfile.close()
        except socket.error as e:
            if e[0] not in (10053, errno.EPIPE):
                raise
        except Exception as e:
            logging.warn('gaeproxy_handler direct(%s) Error', host)
            raise
        finally:
            rfile.close()
            sock.close()
            if __realrfile:
                __realrfile.close()
            if __realsock:
                __realsock.shutdown(socket.SHUT_WR)
                __realsock.close()
    else:
        if 'Range' in headers:
            m = re.search('bytes=(\d+)-', headers['Range'])
            start = int(m.group(1) if m else 0)
            headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            logging.info('autorange range=%r match url=%r', headers['Range'], path)
        elif host.endswith(common.AUTORANGE_HOSTS_TAIL):
            try:
                pattern = (p for p in common.AUTORANGE_HOSTS if host.endswith(p) or fnmatch.fnmatch(host, p)).next()
                logging.debug('autorange pattern=%r match url=%r', pattern, path)
                m = re.search('bytes=(\d+)-', headers.get('Range', ''))
                start = int(m.group(1) if m else 0)
                headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            except StopIteration:
                pass
        try:
            request_method, request_headers, request_payload = pack_request(method, path, headers, rfile, common.GAE_FETCHSERVER, password=common.GAE_PASSWORD, fetchmaxsize=common.AUTORANGE_MAXSIZE)
            try:
                code, response_headers, response_rfile = http.request(request_method, common.GAE_FETCHSERVER, data=request_payload or None, headers=request_headers, crlf=need_crlf)
            except socket.error as e:
                if e[0] in (11004, 10051, 10054, 10060, 'timed out', 'empty line'):
                    # connection reset or timeout, switch to https
                    common.GOOGLE_MODE = 'https'
                    common.build_gae_fetchserver()
                else:
                    raise

            # gateway error, switch to https mode
            if code in (400, 504) or (code==502 and common.GAE_PROFILE=='google_cn'):
                common.GOOGLE_MODE = 'https'
                common.build_gae_fetchserver()
            # appid over qouta, switch to next appid
            if code == 503:
                common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                common.build_gae_fetchserver()
                http.dns[urlparse.urlparse(common.GAE_FETCHSERVER).netloc] = common.GOOGLE_HOSTS
            # bad request, disable CRLF injection
            if code in (400, 405):
                http.crlf = 0

            wfile = sock.makefile('wb', 0)

            if 'Set-Cookie' not in response_headers:
                logging.info('%s:%s "%s %s HTTP/1.1" %s -' % (remote_addr, remote_port, method, path, code))
                http.copy_response(code, response_headers, write=wfile.write)
                http.copy_body(response_rfile, response_headers, write=wfile.write)
                response_rfile.close()
                return

            response_headers, response_kwargs = decode_request(response_headers['Set-Cookie'])
            code = int(response_kwargs['status'])
            logging.info('%s:%s "%s %s HTTP/1.1" %s -' % (remote_addr, remote_port, method, path, code))

            if code == 206:
                fetchservers = [re.sub(r'//\w+\.appspot\.com', '//%s.appspot.com' % x, common.GAE_FETCHSERVER) for x in common.GAE_APPIDS]
                rangefetch = RangeFetch(sock, code, response_headers, response_rfile, method, path, headers, request_payload, fetchservers, common.GAE_PASSWORD, maxsize=common.AUTORANGE_MAXSIZE, bufsize=common.AUTORANGE_BUFSIZE, waitsize=common.AUTORANGE_WAITSIZE, threads=common.AUTORANGE_THREADS)
                return rangefetch.fetch()
            http.copy_response(code, response_headers, write=wfile.write)
            http.copy_body(response_rfile, response_headers, write=wfile.write)
            response_rfile.close()
        except socket.error as e:
            # Connection closed before proxy return
            if e[0] not in (10053, errno.EPIPE):
                raise
        finally:
            rfile.close()
            sock.close()
            if __realrfile:
                __realrfile.close()
            if __realsock:
                __realsock.close()

def paasproxy_handler(sock, address, ls={'setuplock':gevent.coros.Semaphore()}):
    rfile = sock.makefile('rb', 8192)
    try:
        method, path, version, headers = http.parse_request(rfile)
    except socket.error as e:
        if e[0] in ('empty line', 10053, errno.EPIPE):
            return rfile.close()
        raise

    if 'setup' not in ls:
        if not common.PROXY_ENABLE:
            fetchhost = re.sub(r':\d+$', '', urlparse.urlparse(common.PAAS_FETCHSERVER).netloc)
            logging.info('resolve common.PAAS_FETCHSERVER domian=%r to iplist', fetchhost)
            with ls['setuplock']:
                fethhost_iplist = [x[-1][0] for x in socket.getaddrinfo(fetchhost, 80)]
                if len(fethhost_iplist) == 0:
                    logging.error('resolve %s domian return empty! please use ip list to replace domain list!', common.GAE_PROFILE)
                    sys.exit(-1)
                http.dns[fetchhost] = set(fethhost_iplist)
                logging.info('resolve common.PAAS_FETCHSERVER domian to iplist=%r', fethhost_iplist)
        ls['setup'] = True

    if common.USERAGENT_ENABLE:
        headers['User-Agent'] = common.USERAGENT_STRING

    remote_addr, remote_port = address

    __realsock = None
    __realrfile = None
    if method == 'CONNECT':
        host, _, port = path.rpartition(':')
        # GAEProxy Patch
        p = "(?:\d{1,3}\.){3}\d{1,3}"
        if re.match(p, host) is not None:
            host = DNSCacheUtil.getHost(host)
        port = int(port)
        keyfile, certfile = CertUtil.get_cert(host)
        logging.info('%s:%s "%s:%d HTTP/1.1" - -' % (address[0], address[1], host, port))
        sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
        __realsock = sock
        __realrfile = rfile
        try:
            sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True)
        except Exception as e:
            logging.exception('ssl.wrap_socket(__realsock=%r) failed: %s', __realsock, e)
            __realrfile.close()
            __realsock.close()
            return
        rfile = sock.makefile('rb', 8192)
        try:
            method, path, version, headers = http.parse_request(rfile)
        except socket.error as e:
            if e[0] in ('empty line', 10053, errno.EPIPE):
                return rfile.close()
            raise
        if path[0] == '/' and host:
            path = 'https://%s%s' % (headers['Host'], path)

    host = headers.get('Host', '')
    if path[0] == '/' and host:
        path = 'http://%s%s' % (host, path)

    try:
        request_method, request_headers, request_payload = pack_request(method, path, headers, rfile, common.PAAS_FETCHSERVER, password=common.PAAS_PASSWORD)
        try:
            code, response_headers, response_rfile = http.request(request_method, common.PAAS_FETCHSERVER, data=request_payload or None, headers=request_headers)
            logging.info('%s:%s "%s %s HTTP/1.1" %s -' % (remote_addr, remote_port, method, path, code))
        except socket.error as e:
            if e.reason[0] not in (11004, 10051, 10060, 'timed out', 10054):
                raise
        except Exception as e:
            logging.exception('error: %s', e)
            raise

        if code in (400, 405):
            http.crlf = 0

        wfile = sock.makefile('wb', 0)
        http.copy_response(code, response_headers, write=wfile.write)
        http.copy_body(response_rfile, response_headers, write=wfile.write)
        response_rfile.close()

    except socket.error as e:
        # Connection closed before proxy return
        if e[0] not in (10053, errno.EPIPE):
            raise
    finally:
        rfile.close()
        sock.close()
        if __realrfile:
            __realrfile.close()
        if __realsock:
            __realsock.close()

def socks5proxy_handler(sock, address, ls={'setuplock':gevent.coros.Semaphore()}):
    if 'setup' not in ls:
        if not common.PROXY_ENABLE:
            fetchhost = re.sub(r':\d+$', '', urlparse.urlparse(common.SOCKS5_FETCHSERVER).netloc)
            logging.info('resolve common.SOCKS5_FETCHSERVER domian=%r to iplist', fetchhost)
            with ls['setuplock']:
                fethhost_iplist = [x[-1][0] for x in socket.getaddrinfo(fetchhost, 80)]
                if len(fethhost_iplist) == 0:
                    logging.error('resolve %s domian return empty! please use ip list to replace domain list!', fetchhost)
                    sys.exit(-1)
                ls['dns'] = collections.defaultdict(list)
                ls['dns'][fetchhost] = list(set(fethhost_iplist))
                logging.info('resolve common.PAAS_SOCKS5SERVER domian to iplist=%r', fethhost_iplist)
        ls['setup'] = True

    remote_addr, remote_port = address
    logging.info('%s:%s "GET %s SOCKS/5" - -' % (remote_addr, remote_port, common.SOCKS5_FETCHSERVER))
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(common.SOCKS5_FETCHSERVER)
    if re.search(r':\d+$', netloc):
        host, _, port = netloc.rpartition(':')
        port = int(port)
    else:
        host = netloc
        port = {'https':443,'http':80}.get(scheme, 80)
    if host in ls['dns']:
        host = random.choice(ls['dns'][host])
    remote = socket.create_connection((host, port))
    if scheme == 'https':
        remote = ssl.wrap_socket(remote)
    remote.sendall('GET /? HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\n\r\n' % host)
    transtable = ''.join(chr(x%256) for x in xrange(-128, 128))
    http.forward_socket(sock, remote, trans=transtable)

class Autoproxy2Pac(object):
    """Autoproxy to Pac Class, based on https://github.com/iamamac/autoproxy2pac"""
    PROXY_ADDRESS = 'PROXY 127.0.0.1:8087'

    TEMPLATE = '''\
    /* Proxy Auto-Config file generated by autoproxy2pac */
    function FindProxyForURL(url, host) {
        var PROXY   = "%s";
        //-- AUTO-GENERATED RULES, DO NOT MODIFY!
        {{jsrule}}
        //-- END OF AUTO-GENERATED RULES
        return "DIRECT";
        }
    ''' % PROXY_ADDRESS

    def __init__(self, url, proxy, base64_encoding=True):
        self.url = url
        self.proxy = proxy
        self.base64_encoding = base64_encoding
    def _fetch_rulelist(self):
        proxies = {'http':self.proxy,'https':self.proxy} if self.proxy else None
        opener = urllib2.build_opener(urllib2.ProxyHandler(proxies) if proxies else None)
        response = opener.open(self.url)
        content  = response.read()
        response.close()
        if self.base64_encoding:
            content = base64.b64decode(content)
        return content
    def _rule2js(self, ruleList):
        jsCode = []
        # The syntax of the list is based on Adblock Plus filter rules (http://adblockplus.org/en/filters)
        #   Filter options (those parts start with "$") is not supported
        # AutoProxy Add-on for Firefox has a Javascript implementation
        #   http://github.com/lovelywcm/autoproxy/blob/master/chrome/content/filterClasses.js
        for line in ruleList.splitlines()[1:]:
            # Ignore the first line ([AutoProxy x.x]), empty lines and comments
            if line and not line.startswith("!"):
                useProxy = True
                # Exceptions
                if line.startswith("@@"):
                    line = line[2:]
                    useProxy = False
                # Regular expressions
                if line.startswith("/") and line.endswith("/"):
                    jsRegexp = line[1:-1]
                # Other cases
                else:
                    # Remove multiple wildcards
                    jsRegexp = re.sub(r"\*+", r"*", line)
                    # Remove anchors following separator placeholder
                    jsRegexp = re.sub(r"\^\|$", r"^", jsRegexp, 1)
                    # Escape special symbols
                    jsRegexp = re.sub(r"(\W)", r"\\\1", jsRegexp)
                    # Replace wildcards by .*
                    jsRegexp = re.sub(r"\\\*", r".*", jsRegexp)
                    # Process separator placeholders
                    jsRegexp = re.sub(r"\\\^", r"(?:[^\w\-.%\u0080-\uFFFF]|$)", jsRegexp)
                    # Process extended anchor at expression start
                    jsRegexp = re.sub(r"^\\\|\\\|", r"^[\w\-]+:\/+(?!\/)(?:[^\/]+\.)?", jsRegexp, 1)
                    # Process anchor at expression start
                    jsRegexp = re.sub(r"^\\\|", "^", jsRegexp, 1)
                    # Process anchor at expression end
                    jsRegexp = re.sub(r"\\\|$", "$", jsRegexp, 1)
                    # Remove leading wildcards
                    jsRegexp = re.sub(r"^(\.\*)", "", jsRegexp, 1)
                    # Remove trailing wildcards
                    jsRegexp = re.sub(r"(\.\*)$", "", jsRegexp, 1)
                    if jsRegexp == "":
                        jsRegexp = ".*"
                        logging.warning("There is one rule that matches all URL, which is highly *NOT* recommended: %s", line)
                jsLine = '  if(/%s/i.test(url)) return "%s";' % (jsRegexp, self.PROXY_ADDRESS if useProxy else 'DIRECT')
                if useProxy:
                    jsCode.append(jsLine)
                else:
                    jsCode.insert(0, jsLine)
        return '\n'.join(jsCode)
    def generate_pac(self):
        rulelist = self._fetch_rulelist()
        jsrule   = self._rule2js(rulelist)
        kwargs   = dict(jsrule=jsrule)
        content  = self.TEMPLATE
        for keyword, value in kwargs.items():
            content = content.replace('{{%s}}'%keyword, value)
        return content
    @classmethod
    def update_filename(cls, filename, url, proxy):
        logging.info('pacserver: pac filename=%r is expired, begin update', filename)
        autoproxy = cls(url, proxy)
        content = autoproxy.generate_pac()
        logging.info('pacserver: gfwlist=%r downoaded and parsed.', common.PAC_GFWLIST)
        with open(filename, 'wb') as fp:
            fp.write(content)
        logging.info('pacserver: pac filename=%r updated', filename)

def pacserver_handler(sock, address, ls={'setuplock':gevent.coros.Semaphore()}):
    rfile = sock.makefile('rb', 8192)
    try:
        method, path, version, headers = http.parse_request(rfile)
    except socket.error as e:
        if e[0] in ('empty line', 10053, errno.EPIPE):
            return rfile.close()
        raise

    if 'setup' not in ls:
        with ls['setuplock']:
            if 'setup' not in ls:
                filename = os.path.join('.', common.PAC_FILE)
                if not os.path.exists(filename) or time.time() - os.path.getmtime(filename) > 86400:
                    gevent.spawn_later(0.5, Autoproxy2Pac.update_filename, filename, common.PAC_GFWLIST, '%s:%s'%(common.LISTEN_IP, common.LISTEN_PORT))
                ls['setup'] = True

    remote_addr, remote_port = address
    wfile = sock.makefile('wb', 0)
    filename = os.path.join(os.path.dirname(__file__), common.PAC_FILE)
    if path != '/'+common.PAC_FILE or not os.path.isfile(filename):
        wfile.write('HTTP/1.1 404\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n404 Not Found')
        wfile.close()
        logging.info('%s:%s "%s %s HTTP/1.1" 404 -' % (remote_addr, remote_port, method, path))
        return
    with open(filename, 'rb') as fp:
        data = fp.read()
        wfile.write('HTTP/1.1 200\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nConnection: close\r\n\r\n')
        logging.info('%s:%s "%s %s HTTP/1.1" 200 -' % (remote_addr, remote_port, method, path))
        wfile.write(data)
        wfile.close()
    sock.close()

def pre_start():
    if common.GAE_APPIDS[0] == 'goagent' and not common.CRLF_ENABLE:
        logging.critical('please edit %s to add your appid to [gae] !', __config__)
        sys.exit(-1)
    if ctypes and os.name == 'nt':
        ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)
        if not common.LOVE_TIMESTAMP.strip():
            sys.stdout.write('Double click addto-startup.vbs could add goagent to autorun programs. :)\n')
        if not common.LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        if common.LOVE_ENABLE:
            if common.LOVE_TIMESTAMP.strip():
                common.LOVE_TIMESTAMP = int(common.LOVE_TIMESTAMP)
            else:
                common.LOVE_TIMESTAMP = int(time.time())
                with open(__config__, 'w') as fp:
                    common.CONFIG.set('love', 'timestamp', int(time.time()))
                    common.CONFIG.write(fp)
            if time.time() - common.LOVE_TIMESTAMP > 86400 and random.randint(1,10) > 5:
                title = ctypes.create_unicode_buffer(1024)
                ctypes.windll.kernel32.GetConsoleTitleW(ctypes.byref(title), len(title)-1)
                ctypes.windll.kernel32.SetConsoleTitleW(u'%s %s' % (title.value, random.choice(common.LOVE_TIP)))
                with open(__config__, 'w') as fp:
                    common.CONFIG.set('love', 'timestamp', int(time.time()))
                    common.CONFIG.write(fp)

def main():

    # GAEProxy Patch
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

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    logging.basicConfig(level=logging.DEBUG if common.LISTEN_DEBUGINFO else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    CertUtil.check_ca()
    pre_start()
    sys.stdout.write(common.info())
    
    # GAEProxy Patch
    pid = str(os.getpid())
    f = open('/data/data/org.gaeproxy/python.pid','a')
    f.write(" ")
    f.write(pid)
    f.close()

    if common.SOCKS5_ENABLE:
        host, port = common.SOCKS5_LISTEN.split(':')
        server = gevent.server.StreamServer((host, int(port)), socks5proxy_handler)
        gevent.spawn(server.serve_forever)

    if common.PAC_ENABLE:
        server = gevent.server.StreamServer((common.PAC_IP, common.PAC_PORT), pacserver_handler)
        gevent.spawn(server.serve_forever)

    if common.PAAS_ENABLE:
        host, port = common.PAAS_LISTEN.split(':')
        server = gevent.server.StreamServer((host, int(port)), paasproxy_handler)
        server.serve_forever()
    else:
        server = gevent.server.StreamServer((common.LISTEN_IP, common.LISTEN_PORT), gaeproxy_handler)
        server.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
