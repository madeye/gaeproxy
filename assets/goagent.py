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
#      Ming Bai       <mbbill@gmail.com>

__version__ = '2.1.9'
__config__  = 'proxy.ini'
__bufsize__ = 1024*1024

import sys
import os

try:
    import gevent
    import gevent.queue
    import gevent.monkey
    import gevent.coros
    import gevent.server
    import gevent.pool
    import gevent.event
    import gevent.timeout
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
    class GeventServerDatagramServer(SocketServer.ThreadingUDPServer):
        allow_reuse_address = True
        def __init__(self, server_address, *args, **kwargs):
            SocketServer.ThreadingUDPServer.__init__(self, server_address, GeventServerDatagramServer.RequestHandlerClass, *args, **kwargs)
            self._writelock = threading.Semaphore()
        def sendto(self, *args):
            self._writelock.acquire()
            try:
                self.socket.sendto(*args)
            finally:
                self._writelock.release()
        @staticmethod
        def RequestHandlerClass((data, server_socket), client_addr, server):
            return server.handle(data, client_addr)
        def handle(self, data, address):
            raise NotImplemented()
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

    gevent.queue.Queue           = Queue.Queue
    gevent.queue.Empty           = Queue.Empty
    gevent.coros.Semaphore       = threading.Semaphore
    gevent.getcurrent            = threading.currentThread
    gevent.spawn                 = GeventSpawn
    gevent.spawn_later           = GeventSpawnLater
    gevent.server.StreamServer   = GeventServerStreamServer
    gevent.server.DatagramServer = GeventServerDatagramServer
    gevent.pool.Pool             = GeventPoolPool

    del GeventImport, GeventSpawn, GeventSpawnLater, GeventServerStreamServer, GeventServerDatagramServer, GeventPoolPool

try:
    import logging
except ImportError:
    class SimpleLogging(object):
        CRITICAL = 50
        FATAL = CRITICAL
        ERROR = 40
        WARNING = 30
        WARN = WARNING
        INFO = 20
        DEBUG = 10
        NOTSET = 0
        def __init__(self, *args, **kwargs):
            self.level = SimpleLogging.INFO
            if self.level > SimpleLogging.DEBUG:
                self.debug = self.dummy
            self.__write = sys.stdout.write
        @classmethod
        def getLogger(cls, *args, **kwargs):
            return cls(*args, **kwargs)
        def basicConfig(self, *args, **kwargs):
            self.level = kwargs.get('level', SimpleLogging.INFO)
            if self.level > SimpleLogging.DEBUG:
                self.debug = self.dummy
        def log(self, level, fmt, *args, **kwargs):
            self.__write('%s - - [%s] %s\n' % (level, time.ctime()[4:-5], fmt%args))
        def dummy(self, *args, **kwargs):
            pass
        def debug(self, fmt, *args, **kwargs):
            self.log('DEBUG', fmt, *args, **kwargs)
        def info(self, fmt, *args, **kwargs):
            self.log('INFO', fmt, *args)
        def warning(self, fmt, *args, **kwargs):
            self.log('WARNING', fmt, *args, **kwargs)
        def warn(self, fmt, *args, **kwargs):
            self.log('WARNING', fmt, *args, **kwargs)
        def error(self, fmt, *args, **kwargs):
            self.log('ERROR', fmt, *args, **kwargs)
        def exception(self, fmt, *args, **kwargs):
            self.log('ERROR', fmt, *args, **kwargs)
            traceback.print_exc(file=sys.stderr)
        def critical(self, fmt, *args, **kwargs):
            self.log('CRITICAL', fmt, *args, **kwargs)
    logging = SimpleLogging()
    del SimpleLogging

try:
    import ctypes
except ImportError:
    ctypes = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

import collections
import errno
import time
import cStringIO
import struct
import re
import zlib
import random
import base64
import urlparse
import socket
import ssl
import select
import traceback
import hashlib
import fnmatch
import ConfigParser
import httplib
import urllib2
import threading
try:
    import sqlite3
except ImportError:
    sqlite3 = None
    

class CertUtil(object):
    """CertUtil module, based on mitmproxy"""

    ca_lock = threading.Lock()

    @staticmethod
    def create_ca():
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(3)
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
        cert.set_version(3)
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
            index = commonname.find('.')
            extensive = commonname if index == -1 else '*' + commonname[index:]
            sans = [extensive] + [x for x in sans if x != extensive]
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
    skip_headers = frozenset(['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations'])
    dns_blacklist = set(['4.36.66.178', '8.7.198.45', '37.61.54.158', '46.82.174.68', '59.24.3.173', '64.33.88.161', '64.33.99.47', '64.66.163.251', '65.104.202.252', '65.160.219.113', '66.45.252.237', '72.14.205.104', '72.14.205.99', '78.16.49.15', '93.46.8.89', '128.121.126.139', '159.106.121.75', '169.132.13.103', '192.67.198.6', '202.106.1.2', '202.181.7.85', '203.161.230.171', '207.12.88.98', '208.56.31.43', '209.145.54.50', '209.220.30.174', '209.36.73.33', '211.94.66.147', '213.169.251.35', '216.221.188.182', '216.234.179.13'])

    def __init__(self, min_window=4, max_window=64, max_retry=2, max_timeout=30, proxy_uri=''):
        self.min_window = min_window
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.window = 20
        self.window_ack = 0
        self.http_ipr = collections.defaultdict(lambda:5)
        self.https_ipr = collections.defaultdict(lambda:10)
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

    @staticmethod
    def dns_remote_resolve(qname, dnsserver, timeout=None, blacklist=set(), max_retry=2, max_wait=2):
        for i in xrange(max_retry):
            index = os.urandom(2)
            host = ''.join(chr(len(x))+x for x in qname.split('.'))
            data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (index, host)
            address_family = socket.AF_INET6 if ':' in dnsserver else socket.AF_INET
            sock = None
            try:
                sock = socket.socket(family=address_family, type=socket.SOCK_DGRAM)
                if isinstance(timeout, (int, long)):
                    sock.settimeout(timeout)
                sock.sendto(data, (dnsserver, 53))
                for i in xrange(max_wait):
                    data = sock.recv(512)
                    iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x)<=255 for x in s)]
                    iplist = [x for x in iplist if x not in blacklist]
                    if iplist:
                        return iplist
            except socket.error as e:
                if e[0] in (10060, 'timed out'):
                    continue
            except Exception, e:
                raise
            finally:
                if sock:
                    sock.close()

    def dns_resolve(self, host, dnsserver='', ipv4_only=True):
        iplist = self.dns[host]
        if not iplist:
            iplist = self.dns[host] = self.dns.default_factory([])
            if not dnsserver:
                ips = socket.gethostbyname_ex(host)[-1]
            else:
                ips = self.__class__.dns_remote_resolve(host, dnsserver, timeout=2, blacklist=self.dns_blacklist)
            if ipv4_only:
                ips = [ip for ip in ips if re.match(r'\d+.\d+.\d+.\d+', ip)]
            iplist.update(ips)
        return iplist

    def create_connection(self, (host, port), timeout=None, source_address=None, _pool=collections.defaultdict(set), _poolkey=None):
        def _create_connection((ip, port), timeout, queue):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
                if isinstance(timeout, (int, long)):
                    sock.settimeout(timeout)
                start_time = time.time()
                sock.connect((ip, port))
                self.http_ipr[ip] = time.time() - start_time
            except socket.error as e:
                self.http_ipr[ip] = self.http_ipr.default_factory()+random.random()
                if sock:
                    sock.close()
                    sock = None
            finally:
                queue.put(sock)
        def _close_connection(poolkey, count, queue):
            for i in xrange(count):
                sock = queue.get()
                if sock:
                    #sock.close()
                    _pool[poolkey].add((sock, time.time()))
        poolkey = _poolkey(host, port) if callable(_poolkey) else _poolkey if _poolkey else '%s:%s' % (host, port)
        logging.debug('Http.create_connection connect (%r, %r) as poolkey=%r', host, port, poolkey)
        sock = None
        if poolkey in _pool:
            while _pool[poolkey]:
                sock, mtime = _pool[poolkey].pop()
                if time.time() - mtime > 20:
                    sock.close()
                else:
                    break
            if sock:
                logging.debug('Http.create_connection reuse %s for (%r, %r) as poolkey=%r', sock, host, port, poolkey)
                return sock
        iplist = self.dns_resolve(host)
        for i in xrange(self.max_retry):
            window = self.window
            ips = sorted(iplist, key=lambda x:(self.http_ipr[x], random.random()))[:min(len(iplist), int(window)+i)]
            print ips
            queue = gevent.queue.Queue()
            start_time = time.time()
            for ip in ips:
                gevent.spawn(_create_connection, (ip, port), timeout, queue)
            for i in xrange(len(ips)):
                sock = queue.get()
                if sock:
                    gevent.spawn(_close_connection, poolkey, len(ips)-i-1, queue)
                    if window > self.min_window:
                        self.window_ack += 1
                        if self.window_ack > 10:
                            self.window_ack = 0
                            self.window = window - 1
                            logging.info('Http.create_connection to %s, port=%r successed, switch window=%r', ips, port, self.window)
                    return sock
            else:
                logging.warning('Http.create_connection to %s, port=%r return None, try again.', ips, port)
        else:
            self.window = int(round(1.5 * self.window))
            if self.window > self.max_window:
                self.window = self.max_window
            if self.min_window <= len(iplist) < self.window:
                self.window = len(iplist)
            self.window_ack = 0
            logging.error('Http.create_connection to %s, port=%r failed, switch window=%r', iplist, port, self.window)

    def create_ssl_connection(self, (host, port), timeout=None, source_address=None, _pool=collections.defaultdict(set), _poolkey=None):
        def _create_ssl_connection((ip, port), timeout, queue):
            sock = None
            ssl_sock = None
            try:
                sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 60*1024)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 60*1024)
                if isinstance(timeout, (int, long)):
                    sock.settimeout(timeout)
                ssl_sock = ssl.wrap_socket(sock)
                start_time = time.time()
                ssl_sock.connect((ip, port))
                self.https_ipr[ip] = time.time() - start_time
                ssl_sock.sock = sock
                ssl_sock.mtime = time.time()
            except socket.error as e:
                self.https_ipr[ip] = self.https_ipr.default_factory()+random.random()
                if ssl_sock:
                    ssl_sock.close()
                    ssl_sock = None
                if sock:
                    sock.close()
                    sock = None
            finally:
                queue.put(ssl_sock)
        def _close_ssl_connection(poolkey, count, queue):
            for i in xrange(count):
                sock = None
                ssl_sock = queue.get()
                if ssl_sock:
                    _pool[poolkey].add(ssl_sock)
        poolkey = _poolkey(host, port) if callable(_poolkey) else _poolkey if _poolkey else '%s:%s' % (host, port)
        logging.debug('Http.create_ssl_connection connect (%r, %r) as poolkey=%r', host, port, poolkey)
        ssl_sock = None
        if poolkey in _pool:
            while _pool[poolkey]:
                if len(_pool[poolkey]) < 5 and random.random() < 0.5:
                    break
                ssl_sock = _pool[poolkey].pop()
                if time.time() - ssl_sock.mtime > 20:
                    sock = ssl_sock.sock
                    del ssl_sock.sock
                    ssl_sock.close()
                    sock.close()
                else:
                    break
            if ssl_sock and hasattr(ssl_sock, 'sock'):
                logging.debug('Http.create_ssl_connection reuse %s for (%r, %r) as poolkey=%r', ssl_sock, host, port, poolkey)
                return ssl_sock
        iplist = self.dns_resolve(host)
        for i in xrange(self.max_retry):
            window = self.window
            ips = sorted(iplist, key=lambda x:(self.https_ipr[x], random.random()))[:min(len(iplist), int(window)+i)]
            print ips
            queue = gevent.queue.Queue()
            start_time = time.time()
            for ip in ips:
                gevent.spawn(_create_ssl_connection, (ip, port), timeout, queue)
            for i in xrange(len(ips)):
                ssl_sock = queue.get()
                if ssl_sock:
                    gevent.spawn(_close_ssl_connection, poolkey, len(ips)-i-1, queue)
                    if window > self.min_window:
                        self.window_ack += 1
                        if self.window_ack > 10:
                            self.window_ack = 0
                            self.window = window - 1
                            logging.info('Http.create_ssl_connection to %s, port=%r successed, switch window=%r', ips, port, self.window)
                    return ssl_sock
            else:
                logging.warning('Http.create_ssl_connection to %s, port=%r return None, try again.', ips, port)
        else:
            self.window = int(round(1.5 * self.window))
            if self.window > self.max_window:
                self.window = self.max_window
            if self.min_window <= len(iplist) < self.window:
                self.window = len(iplist)
            self.window_ack = 0
            logging.error('Http.create_ssl_connection to %s, port=%r failed, switch window=%r', iplist, port, self.window)

    def create_connection_withproxy(self, (host, port), timeout=None, source_address=None, proxy=None):
        assert isinstance(proxy, (list, tuple, ))
        logging.debug('Http.create_connection_withproxy connect (%r, %r)', host, port)
        username, password, proxyhost, proxyport = proxy
        try:
            try:
                self.dns_resolve(host)
            except socket.error:
                pass
            sock = socket.create_connection((proxyhost, int(proxyport)))
            hostname = random.choice(list(self.dns.get(host)) or [host])
            request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
            if username and password:
                request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode('%s:%s' % (username, password)).strip()
            request_data += '\r\n'
            sock.sendall(request_data)
            buf = ''
            while 1:
                data = sock.recv(1)
                if not data:
                    sock.close()
                    raise socket.error(10054, 'connection reset by proxy')
                buf += data
                if buf.endswith('\r\n\r\n'):
                    break
            return sock
        except socket.error as e:
            logging.error('Http.create_connection_withproxy error %s', e)

    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=__bufsize__, maxping=None, maxpong=None, bitmask=None):
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
                        if bitmask:
                            data = ''.join(chr(ord(x)^bitmask) for x in data)
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
            if e[0] not in (10053, 10054, 10057, errno.EPIPE):
                raise
        finally:
            local.close()
            remote.close()

    def parse_request(self, rfile, bufsize=__bufsize__):
        line = rfile.readline(bufsize)
        if not line:
            raise EOFError('empty line')
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
        return method, path, version.strip(), headers

    def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=__bufsize__, crlf=None, return_sock=None):
        skip_headers = self.skip_headers
        need_crlf = http.crlf
        if crlf:
            need_crlf = 1
        if need_crlf:
            request_data = 'GET /%s HTTP/1.1\r\n\r\n' % random.randint(1, sys.maxint)
            request_data += '\r' * random.randint(1,10) + '\r\n' + '\r' * random.randint(1,10)
        else:
            request_data = ''
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems() if k not in skip_headers)
        if self.proxy:
            username, password, _, _ = self.proxy
            request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode('%s:%s' % (username, password))
        request_data += '\r\n'

        if not payload:
            sock.sendall(request_data)
        else:
            if isinstance(payload, basestring):
                request_data += payload
                sock.sendall(request_data)
            elif hasattr(payload, 'read'):
                sock.sendall(request_data)
                while 1:
                    data = payload.read(bufsize)
                    if not data:
                        break
                    sock.sendall(data)
            else:
                raise TypeError('http.request(payload) must be a string or buffer, not %r' % type(payload))

        bufsize = 0 if return_sock else __bufsize__
        rfile = sock.makefile('rb', bufsize)

        if need_crlf:
            response_line = rfile.readline()
            version, code, _ = response_line.split(' ', 2)
            response_headers = {}
            while 1:
                line = rfile.readline()
                if not line or line == '\r\n':
                    break
                keyword, _, value = line.partition(':')
                keyword = keyword.title()
                response_headers[keyword] = value.strip()
            unused_content = self.copy_body(rfile, response_headers)

        if return_sock:
            if need_crlf:
                rfile.bufsize = bufsize
            return sock

        response_line = rfile.readline(bufsize)
        while response_line == '\r\n':
            response_line = rfile.readline()
            if not response_line:
                raise EOFError('empty line')
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

    def request(self, method, url, payload=None, headers={}, fullurl=False, bufsize=__bufsize__, crlf=None, return_sock=None, _poolkey=None):
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
            ssl_sock = None
            try:
                if not self.proxy:
                    if scheme == 'https':
                        ssl_sock = self.create_ssl_connection((host, port), self.timeout, _poolkey=_poolkey)
                        sock = ssl_sock.sock
                        del ssl_sock.sock
                    else:
                        sock = self.create_connection((host, port), self.timeout)
                else:
                    sock = self.create_connection_withproxy((host, port), port, self.timeout, proxy=self.proxy)
                    path = url
                    #crlf = self.crlf = 0
                    if scheme == 'https':
                        sock = ssl.wrap_socket(sock)
                if sock:
                    if scheme == 'https':
                        crlf = 0
                    return self._request(ssl_sock or sock, method, path, self.protocol_version, headers, payload, bufsize=bufsize, crlf=crlf, return_sock=return_sock)
            except Exception as e:
                logging.debug('Http.request "%s %s" failed:%s', method, url, e)
                if ssl_sock:
                    ssl_sock.close()
                if sock:
                    sock.close()
                if i == self.max_retry - 1:
                    raise
                else:
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

    def copy_body(self, rfile, headers, content_length=0, bufsize=__bufsize__, write=None):
        need_return = False
        if write is None:
            output = cStringIO.StringIO()
            write = output.write
            need_return = True
        content_length = int(headers.get('Content-Length', content_length))

        if headers.get('Transfer-Encoding', '').lower() == 'chunked':
            while 1:
                line = rfile.readline(bufsize)
                if not line:
                    break
                if line == '\r\n':
                    continue
                if ';' in line:
                    line, _ = line.split(';', 1)
                count = int(line , 16)
                if count == 0:
                    break
                else:
                    write(rfile.read(count))
        elif content_length:
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
        self.GAE_CRLF             = self.CONFIG.getint('gae', 'crlf')

        self.PAAS_ENABLE           = self.CONFIG.getint('paas', 'enable')
        self.PAAS_LISTEN           = self.CONFIG.get('paas', 'listen')
        self.PAAS_ISPHP            = self.CONFIG.getint('paas', 'isphp')
        self.PAAS_PASSWORD         = self.CONFIG.get('paas', 'password') if self.CONFIG.has_option('paas', 'password') else ''
        self.PAAS_FETCHSERVER      = self.CONFIG.get('paas', 'fetchserver')

        if self.CONFIG.has_section('dns'):
            self.DNS_ENABLE = self.CONFIG.getint('dns', 'enable')
            self.DNS_LISTEN = self.CONFIG.get('dns', 'listen')
            self.DNS_REMOTE = self.CONFIG.get('dns', 'remote')
            self.DNS_CACHESIZE = self.CONFIG.getint('dns', 'cachesize')
            self.DNS_TIMEOUT   = self.CONFIG.getint('dns', 'timeout')
        else:
            self.DNS_ENABLE = 0

        if self.CONFIG.has_section('socks5'):
            self.SOCKS5_ENABLE           = self.CONFIG.getint('socks5', 'enable')
            self.SOCKS5_LISTEN           = self.CONFIG.get('socks5', 'listen')
            self.SOCKS5_PASSWORD         = self.CONFIG.get('socks5', 'password')
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
        self.GOOGLE_HOSTS         = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|') if x)
        self.GOOGLE_SITES         = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|') if x)
        self.GOOGLE_FORCEHTTPS    = tuple('http://'+x for x in self.CONFIG.get(self.GAE_PROFILE, 'forcehttps').split('|') if x)
        self.GOOGLE_WITHGAE       = set(x for x in self.CONFIG.get(self.GAE_PROFILE, 'withgae').split('|') if x)

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
        self.LOVE_TIP             = self.CONFIG.get('love','tip').decode('unicode-escape').split('|')

        self.HOSTS                = dict((k, tuple(v.split('|')) if v else tuple()) for k, v in self.CONFIG.items('hosts'))

        if self.PROXY_ENABLE:
            self.GOOGLE_MODE = 'https'
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
        if common.DNS_ENABLE:
            info += 'DNS Listen        : %s\n' % common.DNS_LISTEN
            info += 'DNS Remote        : %s\n' % common.DNS_REMOTE
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

def gae_urlfetch(method, url, headers, payload, fetchserver, **kwargs):
    # deflate = lambda x:zlib.compress(x)[2:-4]
    if payload:
        if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers['Content-Encoding'] = 'deflate'
        headers['Content-Length'] = str(len(payload))
    skip_headers = http.skip_headers
    metadata = 'G-Method:%s\nG-Url:%s\n%s\n%s\n' % (method, url, '\n'.join('G-%s:%s'%(k,v) for k,v in kwargs.iteritems() if v), '\n'.join('%s:%s'%(k,v) for k,v in headers.iteritems() if k not in skip_headers))
    metadata = zlib.compress(metadata)[2:-4]
    gae_payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, payload)
    app_code, headers, rfile = http.request('POST', fetchserver, gae_payload, {'Content-Length':len(gae_payload)}, crlf=common.GAE_CRLF, _poolkey='__google__')
    if app_code != 200:
        if app_code in (400, 405):
            # filter by some firewall
            common.GAE_CRLF = 0
        return app_code, app_code, headers, rfile
    data = rfile.read(4)
    if len(data) < 4:
        return app_code, 502, headers, cStringIO.StringIO('connection aborted. too short leadtype data=%r' % data)
    code, headers_length = struct.unpack('!hh', data)
    data = rfile.read(headers_length)
    if len(data) < headers_length:
        return app_code, 502, headers, cStringIO.StringIO('connection aborted. too short headers data=%r' % data)
    headers = dict(x.split(':', 1) for x in zlib.decompress(data, -15).splitlines())
    return app_code, code, headers, rfile

def gae_hosts_updater(sleeptime, threads):
    def check_ssl_ip(ip, peercert_keyword='.google.com'):
        logging.debug('gae_hosts_updater check_ssl_ip %r', ip)
        try:
            with gevent.timeout.Timeout(3):
                sock = socket.create_connection((ip, 443))
                ssl_sock = ssl.wrap_socket(sock)
                peercert = ssl_sock.getpeercert(True)
                if peercert_keyword in peer_cert:
                    return ip
        except gevent.timeout.Timeout as e:
            pass
        except Exception as e:
            pass
    iplist = sum((socket.gethostbyname_ex(x)[-1] for x in common.CONFIG.get(common.GAE_PROFILE, 'hosts').split('|')), [])
    iprange = random.choice(list(set(x.rsplit('.', 1)[0] for x in iplist)))
    ips = ['%s.%d' % (iprange, i) for i in xrange(1, 256)]
    print ips
    pool = gevent.pool.Pool(threads)
    greenlets = [pool.spawn(check_ssl_ip, ip, '.google.com') for ip in ips]
    iplist = [x.get() for x in greenlets if x.get()]
    print iplist

class RangeFetch(object):
    """Range Fetch Class"""

    maxsize   = 1024*1024*4
    bufsize   = 8192
    waitsize  = 1024*512
    threads   = 1
    retry     = 8
    urlfetch  = staticmethod(gae_urlfetch)

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
        gevent.spawn_later(0.1, self._poolfetch, min(len(queues), self.threads), queues, end, length, self.maxsize)

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
                app_code, code, response_headers, response_rfile = self.urlfetch(self.method, self.url, headers, self.payload, fetchserver, password=self.password)
                if app_code != 200:
                    logging.warning('Range Fetch %r %s return %s', self.url, headers['Range'], app_code)
                    time.sleep(5)
                    continue
                if 200 <= code < 300:
                    break
                elif 300 <= code < 400:
                    self.url = response_headers['Location']
                    logging.info('Range Fetch Redirect(%r)', self.url)
                    response_rfile.close()
                    continue
                else:
                    logging.error('Range Fetch %r return %s', self.url, code)
                    response_rfile.close()
                    time.sleep(5)
                    continue

            content_range = response_headers.get('Content-Range')
            if not content_range:
                logging.error('Range Fetch "%s %s" failed: response_headers=%s', self.method, self.url, response_headers)
                return
            content_length = int(response_headers['Content-Length'])
            logging.info('>>>>>>>>>>>>>>> [thread %s] %s %s', id(gevent.getcurrent()), content_length, content_range)

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

def gaeproxy_handler(sock, address, hls={'setuplock':gevent.coros.Semaphore()}):
    rfile = sock.makefile('rb', __bufsize__)
    try:
        method, path, version, headers = http.parse_request(rfile)
    except (EOFError, socket.error) as e:
        if e[0] in ('empty line', 10053, errno.EPIPE):
            return rfile.close()
        raise

    """setup gaeproxy_handler, init domain/iplist map"""
    if 'setup' not in hls:
        http.dns.update(common.HOSTS)
        fetchhosts = ['%s.appspot.com' % x for x in common.GAE_APPIDS]
        if common.GAE_PROFILE == 'google_ipv6':
            for fetchhost in fetchhosts:
                http.dns[fetchhost] = http.dns.default_factory(common.GOOGLE_HOSTS)
        elif not common.PROXY_ENABLE:
            logging.info('resolve common.GOOGLE_HOSTS domain=%r to iplist', common.GOOGLE_HOSTS)
            if common.GAE_PROFILE == 'google_cn':
                with hls['setuplock']:
                    if common.GAE_PROFILE == 'google_cn':
                        hosts = ('www.google.co.jp', 'www.google.com.tw')
                        iplist = []
                        for host in hosts:
                            try:
                                iplist += socket.gethostbyname_ex(host)[-1]
                            except socket.error as e:
                                logging.error('socket.gethostbyname_ex(host=%r) failed:%s', host, e)
                        prefix = re.sub(r'\d+\.\d+$', '', common.GOOGLE_HOSTS[0])
                        iplist = [x for x in iplist if x.startswith(prefix) and re.match(r'\d+\.\d+\.\d+\.\d+', x)]
                        if iplist:
                            common.GOOGLE_HOSTS = set(iplist)
                        else:
                            # seems google_cn is down, should switch to google_hk?
                            need_switch = False
                            for host in random.sample(list(common.GOOGLE_HOSTS), min(3, len(common.GOOGLE_HOSTS))):
                                try:
                                    socket.create_connection((host, 443), timeout=2).close()
                                except socket.error:
                                    need_switch = True
                                    break
                            if need_switch:
                                common.GAE_PROFILE = 'google_hk'
                                common.GOOGLE_MODE = 'https'
                                common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                                common.GOOGLE_HOSTS = tuple(set(x for x in common.CONFIG.get(common.GAE_PROFILE, 'hosts').split('|') if x))
                                common.GOOGLE_WITHGAE = set(common.CONFIG.get('google_hk', 'withgae').split('|'))
            if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                with hls['setuplock']:
                    if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                        google_ipmap = {}
                        need_resolve_remote = []
                        for domain in common.GOOGLE_HOSTS:
                            if not re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                                try:
                                    iplist = socket.gethostbyname_ex(domain)[-1]
                                    if len(iplist) <= 1:
                                        need_resolve_remote.append(domain)
                                    else:
                                        google_ipmap[domain] = iplist
                                except socket.error:
                                    need_resolve_remote.append(domain)
                                    continue
                            else:
                                google_ipmap[domain] =[domain]
                        for dnsserver in ('8.8.8.8', '114.114.114.114'):
                            for domain in need_resolve_remote:
                                logging.info('resolve remote domain=%r from dnsserver=%r', domain, dnsserver)
                                try:
                                    iplist = Http.dns_remote_resolve(domain, dnsserver, timeout=3)
                                    if all(x not in Http.dns_blacklist for x in iplist):
                                        google_ipmap[domain] = iplist
                                        logging.info('resolve remote domain=%r to iplist=%s', domain, google_ipmap[domain])
                                except socket.error as e:
                                    logging.exception('resolve remote domain=%r dnsserver=%r failed: %s', domain, dnsserver, e)
                            if len(set(sum(google_ipmap.values(), []))) > 16:
                                break
                        common.GOOGLE_HOSTS = tuple(set(sum(google_ipmap.values(), [])))
                        if len(common.GOOGLE_HOSTS) == 0:
                            logging.error('resolve %s domain return empty! try remote dns resovle!', common.GAE_PROFILE)
                            sys.exit(-1)
            for fetchhost in fetchhosts:
                http.dns[fetchhost] = http.dns.default_factory(common.GOOGLE_HOSTS)
            logging.info('resolve common.GOOGLE_HOSTS domain to iplist=%r', common.GOOGLE_HOSTS)
        hls['setup'] = True

    if common.USERAGENT_ENABLE:
        headers['User-Agent'] = common.USERAGENT_STRING

    remote_addr, remote_port = address

    """do connect, convert fake https socket"""
    __realsock = None
    __realrfile = None
    if method == 'CONNECT':
        host, _, port = path.rpartition(':')
        # GAEProxy Patch
        p = "(?:\d{1,3}\.){3}\d{1,3}"
        if re.match(p, host) is not None:
            domain = DNSServer.reverse_cache.get(host)
            if domain:
                host = domain
        port = int(port)
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            logging.info('%s:%s "%s %s:%d HTTP/1.1" - -' % (remote_addr, remote_port, method, host, port))
            http_headers = ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems())
            sock.send('HTTP/1.1 200 OK\r\n\r\n')
            if not common.PROXY_ENABLE:
                if host not in http.dns:
                    http.dns[host] = http.dns.default_factory(common.GOOGLE_HOSTS)
                data = sock.recv(1024)
                for i in xrange(8):
                    try:
                        remote = http.create_connection((host, port), 8, _poolkey='__google__')
                        remote.sendall(data)
                    except socket.error as e:
                        if e[0] == 9:
                            logging.error('gaeproxy_handler direct forward remote (%r, %r) failed', host, port)
                            continue
                        else:
                            raise
                http.forward_socket(sock, remote)
            else:
                hostip = random.choice(common.GOOGLE_HOSTS)
                proxy_info = (common.PROXY_USERNAME, common.PROXY_PASSWROD, common.PROXY_HOST, common.PROXY_PORT)
                remote = http.create_connection_withproxy((hostip, int(port)), proxy=proxy_info)
                if not remote:
                    logging.error('gaeproxy_handler proxy connect remote (%r, %r) failed', host, port)
                    return
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
            rfile = sock.makefile('rb', __bufsize__)
            try:
                method, path, version, headers = http.parse_request(rfile)
            except (EOFError, socket.error) as e:
                if e[0] in ('empty line', 10053, errno.EPIPE):
                    return rfile.close()
                raise
            if path[0] == '/' and host:
                path = 'https://%s%s' % (headers['Host'], path)

    host = headers.get('Host', '')
    if path[0] == '/' and host:
        path = 'http://%s%s' % (host, path)

    """handler routine, need_direct and need_crlf"""
    need_direct = False
    if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
        if path.startswith(common.GOOGLE_FORCEHTTPS) or path.rstrip('/') == 'http://www.google.com':
            sock.sendall('HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % path.replace('http://', 'https://'))
            return
        else:
            if host not in http.dns:
                #http.dns[host] = http.dns.default_factory(http.dns_resolve(host))
                http.dns[host] = http.dns.default_factory(common.GOOGLE_HOSTS)
            need_direct = True
    elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
        if host not in http.dns:
            logging.info('crlf dns_resolve(host=%r, dnsservers=%r)', host, common.CRLF_DNSSERVER)
            http.dns[host] = set(http.dns_resolve(host, common.CRLF_DNSSERVER))
            logging.info('crlf dns_resolve(host=%r) return %s', host, list(http.dns[host]))
        need_direct = True

    if need_direct:
        """direct http forward"""
        try:
            content_length = int(headers.get('Content-Length', 0))
            payload = rfile.read(content_length) if content_length else None
            poolkey = None
            if host.endswith(common.GOOGLE_SITES):
                poolkey = '__google__'
            response = http.request(method, path, payload, headers, crlf=common.GAE_CRLF, _poolkey=poolkey)
            if not response:
                logging.warning('http.request "%s %s") return %r', method, path, response)
                return
            response_code, response_headers, response_rfile = response
            if response_code in (400, 405):
                common.GAE_CRLF = 0
            logging.info('%s:%s "%s %s HTTP/1.1" %s %s' % (remote_addr, remote_port, method, path, response_code, response_headers.get('Content-Length', '-')))
            wfile = sock.makefile('wb', 0)
            http.copy_response(response_code, response_headers, write=wfile.write)
            http.copy_body(response_rfile, response_headers, write=wfile.write)
            response_rfile.close()
        except socket.error as e:
            if e[0] not in (10053, errno.EPIPE):
                raise
            elif e[0] in (10054, 10063):
                logging.warn('http.request "%s %s" failed:%s, try addto `withgae`', method, path, e)
                common.GOOGLE_WITHGAE.add(host)
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
        """GAE http urlfetch"""
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
            try:
                content_length = int(headers.get('Content-Length', 0))
                payload = rfile.read(content_length) if content_length else ''
                app_code, code, response_headers, response_rfile = gae_urlfetch(method, path, headers, payload, common.GAE_FETCHSERVER, password=common.GAE_PASSWORD)
            except (EOFError, socket.error) as e:
                if e[0] in (11004, 10051, 10054, 10060, 'timed out', 'empty line'):
                    # connection reset or timeout, switch to https
                    if e[0] == 10054:
                        logging.error('gae_urlfetch %r failed:%s, perhaps should use mode=https', path, e)
                    else:
                        common.GOOGLE_MODE = 'https'
                        common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                else:
                    raise

            # gateway error, switch to https mode
            if app_code in (400, 504) or (app_code==502 and common.GAE_PROFILE=='google_cn'):
                common.GOOGLE_MODE = 'https'
                common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
            # appid over qouta, switch to next appid
            if app_code == 503:
                common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                http.dns[urlparse.urlparse(common.GAE_FETCHSERVER).netloc] = common.GOOGLE_HOSTS
            # bad request, disable CRLF injection
            if app_code in (400, 405):
                http.crlf = 0

            wfile = sock.makefile('wb', 0)

            if app_code != 200:
                logging.info('%s:%s "%s %s HTTP/1.1" %s -' % (remote_addr, remote_port, method, path, code))
                http.copy_response(app_code, response_headers, write=wfile.write)
                http.copy_body(response_rfile, response_headers, write=wfile.write)
                response_rfile.close()
                return

            logging.info('%s:%s "%s %s HTTP/1.1" %s %s' % (remote_addr, remote_port, method, path, code, response_headers.get('Content-Length', '-')))

            if code == 206:
                fetchservers = [re.sub(r'//\w+\.appspot\.com', '//%s.appspot.com' % x, common.GAE_FETCHSERVER) for x in common.GAE_APPIDS]
                rangefetch = RangeFetch(sock, code, response_headers, response_rfile, method, path, headers, payload, fetchservers, common.GAE_PASSWORD, maxsize=common.AUTORANGE_MAXSIZE, bufsize=common.AUTORANGE_BUFSIZE, waitsize=common.AUTORANGE_WAITSIZE, threads=common.AUTORANGE_THREADS)
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

def paas_urlfetch(method, url, headers, payload, fetchserver, **kwargs):
    # deflate = lambda x:zlib.compress(x)[2:-4]
    if payload:
        if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers['Content-Encoding'] = 'deflate'
        headers['Content-Length'] = str(len(payload))
    skip_headers = http.skip_headers
    metadata = 'G-Method:%s\nG-Url:%s\n%s\n%s\n' % (method, url, '\n'.join('G-%s:%s'%(k,v) for k,v in kwargs.iteritems() if v), '\n'.join('%s:%s'%(k,v) for k,v in headers.iteritems() if k not in skip_headers))
    metadata = zlib.compress(metadata)[2:-4]
    app_payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, payload)
    sock = http.request('POST', fetchserver, app_payload, {'Content-Length':len(app_payload)}, crlf=0, return_sock=True)

    # GAEProxy Patch
    response = httplib.HTTPResponse(sock)
    response.begin()
    app_code = response.status
    app_headers = response.getheaders()
    if app_code != 200:
        return app_code, app_code, response.getheaders(), response

    data = response.read(4)
    if len(data) < 4:
        return app_code, 502, headers, cStringIO.StringIO('connection aborted. too short leadtype data=%r' % data)
    code, headers_length = struct.unpack('!hh', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        return app_code, 502, headers, cStringIO.StringIO('connection aborted. too short headers data=%r' % data)
    headers = dict(x.split(':', 1) for x in zlib.decompress(data, -15).splitlines())

    if 'transfer-encoding' in app_headers:
        headers['Transfer-Encoding'] = app_headers['transfer-encoding']
        headers.pop('Content-Length', None)
    if 'connection' in app_headers:
        headers['Connection'] = app_headers['connection']
    if 'set-cookie' in app_headers:
        headers['Set-Cookie'] = app_headers['set-cookie']

    headers.pop('Transfer-Encoding', None)
    return app_code, code, headers, response

def php_urlfetch(method, url, headers, payload, fetchserver, **kwargs):
    # deflate = lambda x:zlib.compress(x)[2:-4]
    if payload:
        if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers['Content-Encoding'] = 'deflate'
        headers['Content-Length'] = str(len(payload))
    skip_headers = http.skip_headers
    metadata = 'G-Method:%s\nG-Url:%s\n%s\n%s\n' % (method, url, '\n'.join('G-%s:%s'%(k,v) for k,v in kwargs.iteritems() if v), '\n'.join('%s:%s'%(k,v) for k,v in headers.iteritems() if k not in skip_headers))
    metadata = zlib.compress(metadata)[2:-4]
    app_payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, payload)
    app_code, headers, rfile = http.request('POST', fetchserver, app_payload, {'Content-Length':len(app_payload)}, crlf=0)
    return app_code, app_code, headers, rfile

def paasproxy_handler(sock, address, hls={'setuplock':gevent.coros.Semaphore()}):
    rfile = sock.makefile('rb', __bufsize__)
    try:
        method, path, version, headers = http.parse_request(rfile)
    except (EOFError, socket.error) as e:
        if e[0] in ('empty line', 10053, errno.EPIPE):
            return rfile.close()
        raise

    #GAEProxy Patch
    if 'setup' not in hls:
        hls['setup'] = True

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
            domain = DNSServer.reverse_cache.get(host)
            if domain:
                host = domain
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
        rfile = sock.makefile('rb', __bufsize__)
        try:
            method, path, version, headers = http.parse_request(rfile)
        except (EOFError, socket.error) as e:
            if e[0] in ('empty line', 10053, errno.EPIPE):
                return rfile.close()
            raise
        if path[0] == '/' and host:
            path = 'https://%s%s' % (headers['Host'], path)

    host = headers.get('Host', '')
    if path[0] == '/' and host:
        path = 'http://%s%s' % (host, path)

    try:
        try:
            content_length = int(headers.get('Content-Length', 0))
            payload = rfile.read(content_length) if content_length else ''
            urlfetch = paas_urlfetch
            if common.PAAS_ISPHP or common.PAAS_FETCHSERVER.endswith('.php'):
                urlfetch = php_urlfetch
            app_code, code, response_headers, response_rfile = urlfetch(method, path, headers, payload, common.PAAS_FETCHSERVER, password=common.PAAS_PASSWORD)
            logging.info('%s:%s "%s %s HTTP/1.1" %s -' % (remote_addr, remote_port, method, path, code))
        # GAEProxy Patch
        except Exception as e:
            logging.exception('error: %s', e)
            raise

        if app_code in (400, 405):
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

def socks5proxy_handler(sock, address, hls={'setuplock':gevent.coros.Semaphore()}):
    import hmac
    if 'setup' not in hls:
        if not common.PROXY_ENABLE:
            fetchhost = re.sub(r':\d+$', '', urlparse.urlparse(common.SOCKS5_FETCHSERVER).netloc)
            logging.info('resolve common.SOCKS5_FETCHSERVER domain=%r to iplist', fetchhost)
            with hls['setuplock']:
                fethhost_iplist = socket.gethostbyname_ex(fetchhost)[-1]
                if len(fethhost_iplist) == 0:
                    logging.error('resolve %s domain return empty! please use ip list to replace domain list!', fetchhost)
                    sys.exit(-1)
                hls['dns'] = collections.defaultdict(list)
                hls['dns'][fetchhost] = list(set(fethhost_iplist))
                logging.info('resolve common.PAAS_SOCKS5SERVER domain to iplist=%r', fethhost_iplist)
        hls['setup'] = True

    remote_addr, remote_port = address
    logging.info('%s:%s "POST %s SOCKS/5" - -' % (remote_addr, remote_port, common.SOCKS5_FETCHSERVER))
    scheme, netloc, path, params, query, fragment = urlparse.urlparse(common.SOCKS5_FETCHSERVER)
    if re.search(r':\d+$', netloc):
        host, _, port = netloc.rpartition(':')
        port = int(port)
    else:
        host = netloc
        port = {'https':443,'http':80}.get(scheme, 80)
    if host in hls['dns']:
        host = random.choice(hls['dns'][host])
    remote = socket.create_connection((host, port))
    if scheme == 'https':
        remote = ssl.wrap_socket(remote)
    password = common.SOCKS5_PASSWORD.strip()
    bitmask = ord(os.urandom(1))
    digest = hmac.new(password, chr(bitmask)).hexdigest()
    request_data = 'PUT /?%s HTTP/1.1\r\n' % digest
    request_data += 'Host: %s\r\n' % host
    request_data += 'Connection: Upgrade\r\n'
    request_data += 'Content-Length: 0\r\n'
    request_data += '\r\n'
    remote.sendall(request_data)
    rfile = remote.makefile('rb', 0)
    while 1:
        line = rfile.readline()
        if not line:
            break
        if line == '\r\n':
            break
    http.forward_socket(sock, remote, bitmask=bitmask)

class Autoproxy2Pac(object):
    """Autoproxy to Pac Class, based on https://github.com/iamamac/autoproxy2pac"""
    def __init__(self, url, proxy, encoding='base64'):
        self.url = url
        self.proxy = proxy
        self.encoding = encoding
    def _fetch_rulelist(self):
        proxies = {'http':self.proxy,'https':self.proxy}
        opener = urllib2.build_opener(urllib2.ProxyHandler(proxies))
        response = opener.open(self.url)
        content  = response.read()
        response.close()
        if self.encoding:
            if self.encoding == 'base64':
                content = base64.b64decode(content)
            else:
                content = content.decode(self.encoding)
        return content
    def _rule2js(self, ruleList, indent=4):
        jsCode = []
        # Filter options (those parts start with "$") is not supported
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
                jsLine = 'if(/%s/i.test(url)) return "%s";' % (jsRegexp, 'PROXY %s' % self.proxy if useProxy else 'DIRECT')
                jsLine = ' '*indent + jsLine
                if useProxy:
                    jsCode.append(jsLine)
                else:
                    jsCode.insert(0, jsLine)
        return '\n'.join(jsCode)
    def generate_pac(self, filename):
        rulelist = self._fetch_rulelist()
        jsrule   = self._rule2js(rulelist, indent=4)
        if os.path.isfile(filename):
            with open(filename, 'rb') as fp:
                content = fp.read()
        lines = content.splitlines()
        if lines[0].strip().startswith('//'):
            lines[0] = '// Proxy Auto-Config file generated by autoproxy2pac, %s' % time.ctime()
        content = '\r\n'.join(lines)
        function = 'function FindProxyForURLByAutoProxy(url, host) {\r\n%s\r\nreturn "DIRECT";\r\n}' % jsrule
        content = re.sub('(?is)function\\s*FindProxyForURLByAutoProxy\\s*\\(url, host\\)\\s*{.+\r\n}', function, content)
        return content
    @classmethod
    def update_filename(cls, filename, url, proxy, check_mtime=False):
        if check_mtime and time.time() - os.path.getmtime(filename) < 10:
            return
        logging.info('autoproxy pac filename=%r out of date, try update it', filename)
        autoproxy = cls(url, proxy)
        content = autoproxy.generate_pac(filename)
        logging.info('autoproxy gfwlist=%r fetched and parsed.', common.PAC_GFWLIST)
        with open(filename, 'wb') as fp:
            fp.write(content)
        logging.info('autoproxy pac filename=%r updated', filename)

def pacserver_handler(sock, address, hls={}):
    rfile = sock.makefile('rb', __bufsize__)
    try:
        method, path, version, headers = http.parse_request(rfile)
    except (EOFError, socket.error) as e:
        if e[0] in ('empty line', 10053, errno.EPIPE):
            return rfile.close()
        raise

    filename = os.path.join(os.path.dirname(__file__), common.PAC_FILE)
    if 'mtime' not in hls:
        hls['mtime'] = os.path.getmtime(filename)
    if time.time() - hls['mtime'] > 60*60*12:
        hls['mtime'] = time.time()
        gevent.spawn_later(1, Autoproxy2Pac.update_filename, filename, common.PAC_GFWLIST, '%s:%s'%(common.LISTEN_IP, common.LISTEN_PORT), True)

    remote_addr, remote_port = address
    wfile = sock.makefile('wb', 0)
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

class DNSServer(gevent.server.DatagramServer):
    """DNS Proxy over TCP to avoid DNS poisoning"""
    remote_addresses = [('8.8.8.8', 53)]
    max_wait       = 1
    max_retry      = 2
    max_cache_size = 2000
    timeout        = 10
    reverse_cache  = {"127.0.0.1": 'localhost'}

    def __init__(self, *args, **kwargs):
        gevent.server.DatagramServer.__init__(self, *args, **kwargs)
        self.cache = {}
    def handle(self, data, address):
        cache   = self.cache
        timeout = self.timeout
        reqid   = data[:2]
        domain  = data[12:data.find('\x00', 12)]
        if len(cache) > self.max_cache_size:
            cache.clear()
        if domain in cache:
            return self.sendto(reqid + cache[domain], address)
        retry = 0
        while domain not in cache:
            qname = re.sub(r'[\x01-\x10]', '.', domain[1:])
            logging.info('DNSServer resolve domain=%r to iplist', qname)
            sock = None
            try:
                data = '%s%s' % (struct.pack('>H', len(data)), data)
                address_family = socket.AF_INET
                sock = socket.socket(family=address_family, type=socket.SOCK_STREAM)
                if isinstance(timeout, (int, long)):
                    sock.settimeout(timeout)
                for remote_address in self.remote_addresses:
                    sock.connect(remote_address)
                    sock.sendall(data)
                for i in xrange(self.max_wait+len(self.remote_addresses)):
                    data = sock.recv(512)
                    iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data)] 
                    if iplist:
                        #logging.info("DNSServer get iplist: %s", iplist)
                        for x in iplist:
                            DNSServer.reverse_cache[x] = qname
                    cache[domain] = data[4:]
                    self.sendto(reqid + cache[domain], address)
                    break
            except socket.error as e:
                logging.error('DNSServer resolve domain=%r to iplist failed:%s', qname, e)
            finally:
                if sock:
                    sock.close()
                retry += 1
                if retry >= self.max_retry:
                    break

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
        if '360safe' in os.popen('tasklist').read().lower():
            lineno = [sys._getframe().f_lineno-1, sys._getframe().f_lineno+2]
            #ctypes.windll.user32.MessageBoxW(None, u'某些安全软件可能和本软件存在冲突.\n可以删除proxy.py第%r行或者暂时退出安全软件来继续运行' % lineno, u'建议', 0)
            #sys.exit(0)

def main():
    global __file__
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x:x)(__file__)

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

    if common.DNS_ENABLE:
        host, port = common.DNS_LISTEN.split(':')
        server = DNSServer((host, int(port)))
        server.remote_addresses = [(x, 53) for x in common.DNS_REMOTE.split('|')]
        server.timeout = common.DNS_TIMEOUT
        server.max_cache_size = common.DNS_CACHESIZE
        gevent.spawn(server.serve_forever)

    # GAEProxy Patch
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
