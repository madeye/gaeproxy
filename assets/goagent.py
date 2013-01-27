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
#      Bin Yu         <yubinlove1991@gmail.com>

__version__ = '2.1.11'
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
        sys.stderr.write('WARNING: python-gevent not installed. `https://github.com/SiteSupport/gevent/downloads`\n')
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
import heapq
import threading
try:
    import ctypes
except ImportError:
    ctypes = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

class DNSCacheUtil(object):
    '''DNSCache module, integrated with GAEProxy'''

    cache = {"127.0.0.1": 'localhost'}

    @staticmethod
    def getHost(address):

        p = "(?:\d{1,3}\.){3}\d{1,3}"

        if re.match(p, address) is None:
            return

        if address in DNSCacheUtil.cache:
            return DNSCacheUtil.cache[address]

        host = None

        sock = None
        address_family = socket.AF_INET
        retry = 0
        while address not in DNSCacheUtil.cache:
            try:
                sock = socket.socket(family=address_family, type=socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(("127.0.0.1", 9090))
                sock.sendall(address + "\r\n")
                host = sock.recv(512)
                if host is not None and not host.startswith("null"):
                    host = host.strip()
                    DNSCacheUtil.cache[address] = host
                    break
                else:
                    if retry > 3:
                        host = None
                        break
                    else:
                        retry = retry + 1
                        continue
            except socket.error as e:
                if e[0] in (10060, 'timed out'):
                    continue
            except Exception, e:
                logging.error('reverse dns query exception: %s', e)
                break
            finally:
                if sock:
                    sock.close()

        return host


class Logging(type(sys)):
    CRITICAL = 50
    FATAL = CRITICAL
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0
    def __init__(self, *args, **kwargs):
        self.level = self.__class__.INFO
        if self.level > self.__class__.DEBUG:
            self.debug = self.dummy
        self.__write = __write = sys.stdout.write
        if os.name == 'nt':
            SetConsoleTextAttribute = ctypes.windll.kernel32.SetConsoleTextAttribute
            GetStdHandle = ctypes.windll.kernel32.GetStdHandle
            self.__set_error_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x04)
            self.__set_warning_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x06)
            self.__reset_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x07)
        elif os.name == 'posix':
            self.__set_error_color = lambda:__write('\033[31m')
            self.__set_warning_color = lambda:__write('\033[33m')
            self.__reset_color = lambda:__write('\033[0m')
    @classmethod
    def getLogger(cls, *args, **kwargs):
        return cls(*args, **kwargs)
    def basicConfig(self, *args, **kwargs):
        self.level = kwargs.get('level', self.__class__.INFO)
        if self.level > self.__class__.DEBUG:
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
        self.__set_warning_color()
        self.log('WARNING', fmt, *args, **kwargs)
        self.__reset_color()
    def warn(self, fmt, *args, **kwargs):
        self.warning(fmt, *args, **kwargs)
    def error(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('ERROR', fmt, *args, **kwargs)
        self.__reset_color()
    def exception(self, fmt, *args, **kwargs):
        self.error(fmt, *args, **kwargs)
        traceback.print_exc(file=sys.stderr)
    def critical(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('CRITICAL', fmt, *args, **kwargs)
        self.__reset_color()
logging = sys.modules['logging'] = Logging('logging')

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
    def import_ca(certfile):
        dirname, basename = os.path.split(certfile)
        commonname = os.path.splitext(certfile)[0]
        if OpenSSL:
            try:
                with open(certfile, 'rb') as fp:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())
                    commonname = (v for k,v in x509.get_subject().get_components() if k=='O').next()
            except Exception as e:
                pass

        cmd = ''
        if sys.platform.startswith('win'):
            cmd = 'cd /d "%s" && .\certmgr.exe -add %s -c -s -r localMachine Root >NUL' % (dirname, basename)
        elif sys.platform == 'cygwin':
            cmd = 'cmd /c "pushd %s && certmgr.exe -add %s -c -s -r localMachine Root"' % (dirname, basename)
        elif sys.platform == 'darwin':
            cmd = 'security find-certificate -a -c "%s" | grep "%s" || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile)
        elif sys.platform.startswith('linux'):
            import platform
            platform_distname = platform.dist()[0]
            if platform_distname == 'Ubuntu':
                pemfile = "/etc/ssl/certs/%s.pem" % commonname
                new_certfile = "/usr/local/share/ca-certificates/%s.crt" % commonname
                if not os.path.exists(pemfile):
                    cmd = 'cp "%s" "%s" && update-ca-certificates' % (certfile, new_certfile)
        return os.system(cmd)

    @staticmethod
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CA.crt')
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.name == 'nt':
                os.system('certmgr.exe -del -n "GoAgent CA" -c -s -r localMachine Root')
            [os.remove(os.path.join('certs', x)) for x in os.listdir('certs')]
            CertUtil.dump_ca('CA.key', 'CA.crt')
        #Check CA imported
        if CertUtil.import_ca(capath) != 0:
            logging.warning('GoAgent install certificate failed, Please run proxy.py by administrator/root/sudo')
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

    def __init__(self, max_window=4, max_timeout=16, max_retry=4, proxy=''):
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.connection_time = {}
        self.ssl_connection_time = {}
        self.max_timeout = max_timeout
        self.dns = collections.defaultdict(set)
        self.crlf = 0
        self.proxy = proxy

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

    def create_connection(self, (host, port), timeout=None, source_address=None):
        def _create_connection((ip, port), timeout, queue):
            sock = None
            try:
                sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
                sock.settimeout(timeout or self.max_timeout)
                start_time = time.time()
                sock.connect((ip, port))
                self.connection_time['%s:%s'%(ip,port)] = time.time() - start_time
            except socket.error as e:
                self.connection_time['%s:%s'%(ip,port)] = self.max_timeout+random.random()
                if sock:
                    sock.close()
                    sock = None
            finally:
                queue.put(sock)
        def _close_connection(count, queue):
            for i in xrange(count):
                sock = queue.get()
        sock = None
        iplist = self.dns_resolve(host)
        window = (self.max_window+1)//2
        for i in xrange(self.max_retry):
            window += i
            connection_time = self.ssl_connection_time if port == 443 else self.connection_time
            ips = heapq.nsmallest(window, iplist, key=lambda x:connection_time.get('%s:%s'%(x,port),0)) + random.sample(iplist, min(len(iplist), window))
            # print ips
            queue = gevent.queue.Queue()
            for ip in ips:
                gevent.spawn(_create_connection, (ip, port), timeout, queue)
            for i in xrange(len(ips)):
                sock = queue.get()
                if sock:
                    gevent.spawn(_close_connection, len(ips)-i-1, queue)
                else:
                    logging.warning('Http.create_connection return None, reset timeout for %s', ips)
                    for ip in ips:
                        self.connection_time['%s:%s'%(ip,port)] = self.max_timeout + random.random()
                return sock
            else:
                logging.warning('Http.create_connection to %s, port=%r return None, try again.', ips, port)
            for ip in ips:
                self.connection_time['%s:%s'%(ip,port)] = self.max_timeout + random.random()

    def create_ssl_connection(self, (host, port), timeout=None, source_address=None):
        def _create_ssl_connection((ip, port), timeout, queue):
            sock = None
            ssl_sock = None
            try:
                sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32*1024)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                sock.settimeout(timeout or self.max_timeout)
                ssl_sock = ssl.wrap_socket(sock)
                start_time = time.time()
                ssl_sock.connect((ip, port))
                self.ssl_connection_time['%s:%s'%(ip,port)] = time.time() - start_time
                ssl_sock.sock = sock
            except socket.error as e:
                self.ssl_connection_time['%s:%s'%(ip,port)] = self.max_timeout + random.random()
                if ssl_sock:
                    ssl_sock.close()
                    ssl_sock = None
                if sock:
                    sock.close()
                    sock = None
            finally:
                queue.put(ssl_sock)
        def _close_ssl_connection(count, queue):
            for i in xrange(count):
                sock = None
                ssl_sock = queue.get()
        ssl_sock = None
        iplist = self.dns_resolve(host)
        window = (self.max_window+1)//2
        for i in xrange(self.max_retry):
            window += i
            ips = heapq.nsmallest(window, iplist, key=lambda x:self.ssl_connection_time.get('%s:%s'%(x,port),0)) + random.sample(iplist, min(len(iplist), window))
            # print ips
            queue = gevent.queue.Queue()
            start_time = time.time()
            for ip in ips:
                gevent.spawn(_create_ssl_connection, (ip, port), timeout, queue)
            for i in xrange(len(ips)):
                ssl_sock = queue.get()
                if ssl_sock:
                    gevent.spawn(_close_ssl_connection, len(ips)-i-1, queue)
                    return ssl_sock
            else:
                logging.warning('Http.create_ssl_connection to %s, port=%r return None, try again.', ips, port)

    def create_connection_withproxy(self, (host, port), timeout=None, source_address=None, proxy=None):
        assert isinstance(proxy, (str, unicode))
        logging.debug('Http.create_connection_withproxy connect (%r, %r)', host, port)
        scheme, username, password, address = urllib2._parse_proxy(proxy or self.proxy)
        try:
            try:
                self.dns_resolve(host)
            except socket.error:
                pass
            proxyhost, _, proxyport = address.rpartition(':')
            sock = socket.create_connection((proxyhost, int(proxyport)))
            hostname = random.choice(list(self.dns.get(host)) or [host if not host.endswith('.appspot.com') else 'www.google.com'])
            request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
            if username and password:
                request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode('%s:%s' % (username, password)).strip()
            request_data += '\r\n'
            sock.sendall(request_data)
            response = httplib.HTTPResponse(sock)
            response.begin()
            if response.status >= 400:
                logging.error('Http.create_connection_withproxy return http error code %s', response.status)
                sock = None
            return sock
        except socket.error as e:
            logging.error('Http.create_connection_withproxy error %s', e)

    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=__bufsize__, maxping=None, maxpong=None, pongcallback=None, bitmask=None):
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
                            if sock is remote:
                                local.sendall(data)
                                timecount = maxpong or timeout
                                if pongcallback:
                                    try:
                                        #remote_addr = '%s:%s'%remote.getpeername()[:2]
                                        #logging.debug('call remote=%s pongcallback=%s', remote_addr, pongcallback)
                                        pongcallback()
                                    except Exception as e:
                                        logging.warning('remote=%s pongcallback=%s failed: %s', remote, pongcallback, e)
                                    finally:
                                        pongcallback = None
                            else:
                                remote.sendall(data)
                                timecount = maxping or timeout
                        else:
                            return
        except socket.error as e:
            if e[0] not in (10053, 10054, 10057, errno.EPIPE):
                raise
        finally:
            if local:
                local.close()
            if remote:
                remote.close()

    def parse_request(self, rfile, bufsize=__bufsize__):
        line = rfile.readline(bufsize)
        if not line:
            raise socket.error(10053, 'empty line')
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
            request_data = 'GET / HTTP/1.1\r\n\r\n\r\n'
        else:
            request_data = ''
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems() if k not in skip_headers)
        if self.proxy:
            _, username, password, _ = urllib2._parse_proxy(self.proxy)
            if username and password:
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

        if need_crlf:
            try:
                response = httplib.HTTPResponse(sock)
                response.begin()
                response.read()
            except Exception:
                logging.exception('crlf skip read')
                return None

        if return_sock:
            return sock

        response = httplib.HTTPResponse(sock, buffering=True) if sys.hexversion > 0x02070000 else httplib.HTTPResponse(sock)
        try:
            response.begin()
        except httplib.BadStatusLine:
            response = None
        return response

    def request(self, method, url, payload=None, headers={}, fullurl=False, bufsize=__bufsize__, crlf=None, return_sock=None):
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
        if not re.search(r':\d+$', netloc):
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        path += '?' + query

        if 'Host' not in headers:
            headers['Host'] = host

        for i in xrange(self.max_retry):
            sock = None
            ssl_sock = None
            try:
                if not self.proxy:
                    if scheme == 'https':
                        ssl_sock = self.create_ssl_connection((host, port), self.max_timeout)
                        sock = ssl_sock.sock
                        del ssl_sock.sock
                    else:
                        sock = self.create_connection((host, port), self.max_timeout)
                else:
                    sock = self.create_connection_withproxy((host, port), port, self.max_timeout, proxy=self.proxy)
                    path = url
                    #crlf = self.crlf = 0
                    if scheme == 'https':
                        sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1)
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

        self.GAE_APPIDS           = re.findall('[\w\-\.]+', self.CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
        self.GAE_PASSWORD         = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH             = self.CONFIG.get('gae', 'path')
        self.GAE_PROFILE          = self.CONFIG.get('gae', 'profile')
        self.GAE_CRLF             = self.CONFIG.getint('gae', 'crlf')

        self.PAC_ENABLE           = self.CONFIG.getint('pac','enable')
        self.PAC_IP               = self.CONFIG.get('pac','ip')
        self.PAC_PORT             = self.CONFIG.getint('pac','port')
        self.PAC_FILE             = self.CONFIG.get('pac','file').lstrip('/')
        self.PAC_GFWLIST          = self.CONFIG.get('pac', 'gfwlist')

        self.PAAS_ENABLE           = self.CONFIG.getint('paas', 'enable')
        self.PAAS_LISTEN           = self.CONFIG.get('paas', 'listen')
        self.PAAS_PASSWORD         = self.CONFIG.get('paas', 'password') if self.CONFIG.has_option('paas', 'password') else ''
        self.PAAS_FETCHSERVER      = self.CONFIG.get('paas', 'fetchserver')

        self.PROXY_ENABLE         = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_AUTODETECT     = self.CONFIG.getint('proxy', 'autodetect') if self.CONFIG.has_option('proxy', 'autodetect') else 0
        self.PROXY_HOST           = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT           = self.CONFIG.getint('proxy', 'port')
        self.PROXY_USERNAME       = self.CONFIG.get('proxy', 'username')
        self.PROXY_PASSWROD       = self.CONFIG.get('proxy', 'password')

        if not self.PROXY_ENABLE and self.PROXY_AUTODETECT:
            try:
                proxies = (x for x in urllib2.build_opener().handlers if isinstance(x, urllib2.ProxyHandler)).next().proxies
                proxy = proxies.get('https') or proxies.get('http') or ''
                if self.LISTEN_IP not in proxy:
                    scheme, username, password, address = urllib2._parse_proxy(proxy)
                    proxyhost, _, proxyport = address.rpartition(':')
                    self.PROXY_ENABLE   = 1
                    self.PROXY_USERNAME = username
                    self.PROXY_PASSWROD = password
                    self.PROXY_HOST     = proxyhost
                    self.PROXY_PORT     = int(proxyport)
            except StopIteration:
                pass
        if self.PROXY_ENABLE:
            self.GOOGLE_MODE = 'https'
            self.proxy = 'https://%s:%s@%s:%d' % (self.PROXY_USERNAME or '' , self.PROXY_PASSWROD or '', self.PROXY_HOST, self.PROXY_PORT)
        else:
            self.proxy = ''

        self.GOOGLE_MODE          = self.CONFIG.get(self.GAE_PROFILE, 'mode')
        self.GOOGLE_WINDOW        = self.CONFIG.getint(self.GAE_PROFILE, 'window') if self.CONFIG.has_option(self.GAE_PROFILE, 'window') else 4
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

        self.USERAGENT_ENABLE     = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING     = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE          = self.CONFIG.getint('love','enable')
        self.LOVE_TIMESTAMP       = self.CONFIG.get('love', 'timestamp')
        self.LOVE_TIP             = [re.sub(r'\\u([0-9a-fA-F]{4})', lambda m:unichr(int(m.group(1), 16)), x) for x in self.CONFIG.get('love','tip').split('|')]

        self.HOSTS                = dict((k, tuple(v.split('|')) if v else tuple()) for k, v in self.CONFIG.items('hosts'))

        random.shuffle(self.GAE_APPIDS)
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
http   = Http(max_window=common.GOOGLE_WINDOW, proxy=common.proxy)

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
    need_crlf = 0 if fetchserver.startswith('https') else common.GAE_CRLF
    response = http.request('POST', fetchserver, gae_payload, {'Content-Length':len(gae_payload)}, crlf=need_crlf)
    response.app_status = response.status
    if response.status != 200:
        if response.status in (400, 405):
            # filter by some firewall
            common.GAE_CRLF = 0
        return response
    data = response.read(4)
    if len(data) < 4:
        response.status = 502
        response.fp = cStringIO.StringIO('connection aborted. too short leadtype data=%r' % data)
        return response
    response.status, headers_length = struct.unpack('!hh', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        response.fp = cStringIO.StringIO('connection aborted. too short headers data=%r' % data)
        return response
    response.msg = httplib.HTTPMessage(cStringIO.StringIO(zlib.decompress(data, -15)))
    return response

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
        self._sock.sendall('HTTP/1.1 %s\r\n%s\r\n' % (response_status, ''.join('%s: %s\r\n' % (k.title(),v) for k,v in response_headers.items())))

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
                response = self.urlfetch(self.method, self.url, headers, self.payload, fetchserver, password=self.password)
                if response.app_status != 200:
                    logging.warning('Range Fetch %r %s return %s', self.url, headers['Range'], response.app_status)
                    time.sleep(5)
                    continue
                if 200 <= response.status < 300:
                    break
                elif 300 <= response.status < 400:
                    self.url = response.getheader('Location')
                    logging.info('Range Fetch Redirect(%r)', self.url)
                    response.close()
                    continue
                else:
                    logging.error('Range Fetch %r return %s', self.url, response.status)
                    response.close()
                    time.sleep(5)
                    continue

            content_range = response.getheader('Content-Range')
            if not content_range:
                logging.error('Range Fetch "%s %s" failed: response headers=%s', self.method, self.url, response.msg)
                return
            content_length = int(response.getheader('Content-Length',0))
            logging.info('>>>>>>>>>>>>>>> [thread %s] %s %s', id(gevent.getcurrent()), content_length, content_range)

            left = content_length
            while 1:
                data = response.read(min(self.bufsize, left))
                if not data:
                    response.close()
                    queue.put(StopIteration)
                    break
                else:
                    queue.put(data)
                    left -= len(data)
        except Exception as e:
            logging.exception('_fetch error:%s', e)
            raise

class GAEProxyHandler(object):

    bufsize       = __bufsize__
    firstrun      = None
    firstrun_lock = gevent.coros.Semaphore()
    urlfetch      = staticmethod(gae_urlfetch)

    def __init__(self, sock, address):
        self.sock = sock
        self.remote_addr, self.remote_port = self.address = address

        if not self.__class__.firstrun:
            with self.__class__.firstrun_lock:
                if not self.__class__.firstrun:
                    try:
                        self.__class__.firstrun = self.first_run()
                    except Exception as e:
                        logging.error('%r first_run raise Exception: %s', self, e)
        try:
            self.handle()
        except Exception as e:
            logging.exception('%r Exception: %s', self, e)
        finally:
            self.finish()

    def first_run(self):
        """GAEProxyHandler first_run, init domain/iplist map"""
        http.dns.update(common.HOSTS)
        fetchhosts = ['%s.appspot.com' % x for x in common.GAE_APPIDS]
        if common.GAE_PROFILE == 'google_ipv6' or common.PROXY_ENABLE:
            for fetchhost in fetchhosts:
                http.dns[fetchhost] = http.dns.default_factory(common.GOOGLE_HOSTS)
        elif not common.PROXY_ENABLE:
            logging.info('resolve common.GOOGLE_HOSTS domain=%r to iplist', common.GOOGLE_HOSTS)
            if common.GAE_PROFILE == 'google_cn':
                hosts = ('www.google.cn', 'www.g.cn')
                iplist = []
                for host in hosts:
                    try:
                        iplist += socket.gethostbyname_ex(host)[-1]
                    except socket.error as e:
                        logging.error('socket.gethostbyname_ex(host=%r) failed:%s', host, e)
                prefix = re.sub(r'\d+\.\d+$', '', random.sample(common.GOOGLE_HOSTS, 1)[0])
                iplist = [x for x in iplist if x.startswith(prefix) and re.match(r'\d+\.\d+\.\d+\.\d+', x)]
                if iplist and len(iplist) > len(hosts):
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
                        common.GOOGLE_WINDOW = common.CONFIG.getint('google_hk', 'window')
                        common.GOOGLE_HOSTS = tuple(set(x for x in common.CONFIG.get(common.GAE_PROFILE, 'hosts').split('|') if x))
                        common.GOOGLE_WITHGAE = set(common.CONFIG.get('google_hk', 'withgae').split('|'))
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
        return True

    def handle(self):
        try:
            self.rfile = self.sock.makefile('rb', self.bufsize)
            self.method, self.path, self.version, self.headers = http.parse_request(self.rfile)
            getattr(self, 'handle_%s' % self.method.lower(), self.handle_method)()
        except socket.error as e:
            if e[0] not in (10053, errno.EPIPE):
                raise

    def handle_method(self):
        host = self.headers.get('Host', '')
        if self.path[0] == '/' and host:
            self.path = 'http://%s%s' % (host, self.path)

        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING

        """rules match algorithm, need_forward= True or False"""
        need_forward = False
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            if self.path.startswith(common.GOOGLE_FORCEHTTPS) or self.path.rstrip('/') == 'http://www.google.com':
                self.sock.sendall('HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % self.path.replace('http://', 'https://'))
                return
            else:
                if host not in http.dns:
                    #http.dns[host] = http.dns.default_factory(http.dns_resolve(host))
                    http.dns[host] = http.dns.default_factory(common.GOOGLE_HOSTS)
                need_forward = True
        elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
            if host not in http.dns:
                logging.info('crlf dns_resolve(host=%r, dnsservers=%r)', host, common.CRLF_DNSSERVER)
                http.dns[host] = set(http.dns_resolve(host, common.CRLF_DNSSERVER))
                logging.info('crlf dns_resolve(host=%r) return %s', host, list(http.dns[host]))
            need_forward = True

        if need_forward:
            self.handle_method_forward()
        else:
            self.handle_method_urlfetch()

    def handle_method_forward(self):
        """Direct http forward"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            payload = self.rfile.read(content_length) if content_length else None
            response = http.request(self.method, self.path, payload, self.headers, crlf=common.GAE_CRLF)
            if not response:
                logging.warning('http.request "%s %s") return %r', self.method, self.path, response)
                return
            if response.status in (400, 405):
                common.GAE_CRLF = 0
            logging.info('%s:%s "%s %s HTTP/1.1" %s %s', self.remote_addr, self.remote_port, self.method, self.path, response.status, response.msg.get('Content-Length', '-'))
            wfile = self.sock.makefile('wb', 0)
            wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))
            wfile.write(response.read())
            response.close()
        except socket.error as e:
            if e[0] not in (10053, errno.EPIPE):
                raise
            elif e[0] in (10054, 10063):
                logging.warn('http.request "%s %s" failed:%s, try addto `withgae`', self.method, self.path, e)
                common.GOOGLE_WITHGAE.add(host)
        except Exception as e:
            logging.warn('GAEProxyHandler direct(%s) Error', host)
            raise

    def handle_method_urlfetch(self):
        """GAE http urlfetch"""
        host = self.headers.get('Host', '')
        if 'Range' in self.headers:
            m = re.search('bytes=(\d+)-', self.headers['Range'])
            start = int(m.group(1) if m else 0)
            self.headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            logging.info('autorange range=%r match url=%r', self.headers['Range'], self.path)
        elif host.endswith(common.AUTORANGE_HOSTS_TAIL):
            try:
                pattern = (p for p in common.AUTORANGE_HOSTS if host.endswith(p) or fnmatch.fnmatch(host, p)).next()
                logging.debug('autorange pattern=%r match url=%r', pattern, self.path)
                m = re.search('bytes=(\d+)-', self.headers.get('Range', ''))
                start = int(m.group(1) if m else 0)
                self.headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            except StopIteration:
                pass
        try:
            response = None
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                payload = self.rfile.read(content_length) if content_length else ''
                response = self.urlfetch(self.method, self.path, self.headers, payload, common.GAE_FETCHSERVER, password=common.GAE_PASSWORD)
            except (EOFError, socket.error) as e:
                if e[0] in (11004, 10051, 10054, 10060, 'timed out'):
                    # connection reset or timeout, switch to https
                    if e[0] == 10054:
                        logging.error('handle_method_forward %r failed:%s, perhaps should use mode=https', self.path, e)
                    else:
                        common.GOOGLE_MODE = 'https'
                        common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                else:
                    raise

            if response is None:
                return

            # gateway error, switch to https mode
            if response.app_status in (400, 504) or (response.app_status==502 and common.GAE_PROFILE=='google_cn'):
                common.GOOGLE_MODE = 'https'
                common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
            # appid over qouta, switch to next appid
            if response.app_status == 503:
                common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                http.dns[urlparse.urlparse(common.GAE_FETCHSERVER).netloc] = common.GOOGLE_HOSTS
                logging.info('APPID Over Quota,Auto Switch to [%s]' % (common.GAE_APPIDS[0]))
            # bad request, disable CRLF injection
            if response.app_status in (400, 405):
                http.crlf = 0

            wfile = self.sock.makefile('wb', 0)

            if response.app_status != 200:
                logging.info('%s:%s "%s %s HTTP/1.1" %s -', self.remote_addr, self.remote_port, self.method, self.path, response.status)
                wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))
                wfile.write(response.read())
                response.close()
                return

            logging.info('%s:%s "%s %s HTTP/1.1" %s %s', self.remote_addr, self.remote_port, self.method, self.path, response.status, response.getheader('Content-Length', '-'))

            if response.status == 206:
                fetchservers = [re.sub(r'//\w+\.appspot\.com', '//%s.appspot.com' % x, common.GAE_FETCHSERVER) for x in common.GAE_APPIDS]
                rangefetch = RangeFetch(self.sock, response.status, response.msg, response, self.method, self.path, self.headers, payload, fetchservers, common.GAE_PASSWORD, maxsize=common.AUTORANGE_MAXSIZE, bufsize=common.AUTORANGE_BUFSIZE, waitsize=common.AUTORANGE_WAITSIZE, threads=common.AUTORANGE_THREADS)
                return rangefetch.fetch()

            if 'Set-Cookie' in response.msg:
                response.msg['Set-Cookie'] = re.sub(', ([^ =]+(?:=|$))', '\\r\\nSet-Cookie: \\1', response.msg['Set-Cookie'])
            wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))

            while 1:
                data = response.read(8192)
                if not data:
                    break
                wfile.write(data)
            response.close()
        except socket.error as e:
            # Connection closed before proxy return
            if e[0] not in (10053, errno.EPIPE):
                raise

    def handle_connect(self):
        """handle CONNECT cmmand, socket forward or deploy a fake cert"""
        host = self.path.rpartition(':')[0]
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            self.handle_connect_forward()
        else:
            self.handle_connect_urlfetch()

    def handle_connect_forward(self):
        """socket forward for http CONNECT command"""
        host, _, port = self.path.rpartition(':')
        # GAEProxy Patch
        domain = DNSCacheUtil.getHost(host)
        if domain:
            host = domain
        port = int(port)
        logging.info('%s:%s "%s %s:%d HTTP/1.1" - -', self.remote_addr, self.remote_port, self.method, host, port)
        http_headers = ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.iteritems())
        self.sock.send('HTTP/1.1 200 OK\r\n\r\n')
        if not common.PROXY_ENABLE:
            if host not in http.dns:
                http.dns[host] = http.dns.default_factory(common.GOOGLE_HOSTS)
            data = self.sock.recv(1024)
            for i in xrange(4):
                try:
                    remote = http.create_connection((host, port), 6)
                    if remote is None:
                        logging.error('http.create_connection((host=%r, port=%r), 6) timeout', host, port)
                        continue
                    remote.sendall(data)
                except socket.error as e:
                    if e[0] == 9:
                        logging.error('GAEProxyHandler direct forward remote (%r, %r) failed', host, port)
                        continue
                    else:
                        raise
            if hasattr(remote, 'fileno'):
                # start_handshake = time.time()
                # remote_addr = '%s:%d' % remote.getpeername()[:2]
                # pongcallback=lambda:http.connection_time.__setitem__(remote_addr,http.connection_time.get(remote_addr,0)+time.time()-start_handshake)
                http.forward_socket(self.sock, remote, pongcallback=None)
        else:
            hostip = random.choice(common.GOOGLE_HOSTS)
            remote = http.create_connection_withproxy((hostip, int(port)), proxy=common.proxy)
            if not remote:
                logging.error('GAEProxyHandler proxy connect remote (%r, %r) failed', host, port)
                return
            http.forward_socket(self.sock, remote)

    def handle_connect_urlfetch(self):
        """deploy fake cert to client"""
        host, _, port = self.path.rpartition(':')
        # GAEProxy Patch
        domain = DNSCacheUtil.getHost(host)
        if domain:
            host = domain
        port = int(port)
        keyfile, certfile = CertUtil.get_cert(host)
        logging.info('%s:%s "%s %s:%d HTTP/1.1" - -', self.remote_addr, self.remote_port, self.method, host, port)
        self.__realsock = None
        self.__realrfile = None
        self.sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
        try:
            ssl_sock = ssl.wrap_socket(self.sock, certfile=certfile, keyfile=keyfile, server_side=True, ssl_version=ssl.PROTOCOL_SSLv23)
        except Exception as e:
            logging.error('ssl.wrap_socket(self.sock=%r) failed: %s', self.sock, e)
            return
        self.__realsock = self.sock
        self.__realrfile = self.rfile
        self.sock = ssl_sock
        self.rfile = self.sock.makefile('rb', __bufsize__)
        try:
            self.method, self.path, self.version, self.headers = http.parse_request(self.rfile)
            if self.path[0] == '/' and host:
                self.path = 'https://%s%s' % (self.headers['Host'], self.path)
            self.handle_method()
        except socket.error as e:
            if e[0] not in (10053, 10060, errno.EPIPE):
                raise
        finally:
            if self.__realsock:
                self.__realsock.shutdown(socket.SHUT_WR)
                self.__realsock.close()
            if self.__realrfile:
                self.__realrfile.close()

    def finish(self):
        try:
            self.rfile.close()
        except:
            pass
        try:
            self.sock.close()
        except:
            pass

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
    response = http.request('POST', fetchserver, app_payload, {'Content-Length':len(app_payload)}, crlf=0)
    response.app_status = response.status
    if 'x-status' in response.msg:
        response.status = int(response.msg['x-status'])
        del response.msg['x-status']
    if 'status' in response.msg:
        response.status = int(response.msg['status'])
        del response['status']
    return response

class PAASProxyHandler(GAEProxyHandler):

    firstrun      = True
    firstrun_lock = gevent.coros.Semaphore()
    urlfetch      = staticmethod(paas_urlfetch)

    def first_run(self):
        if not common.PROXY_ENABLE:
            fetchhost = re.sub(r':\d+$', '', urlparse.urlparse(common.PAAS_FETCHSERVER).netloc)
            logging.info('resolve common.PAAS_FETCHSERVER domain=%r to iplist', fetchhost)
            fethhost_iplist = socket.gethostbyname_ex(fetchhost)[-1]
            if len(fethhost_iplist) == 0:
                logging.error('resolve %s domain return empty! please use ip list to replace domain list!', common.GAE_PROFILE)
                sys.exit(-1)
            http.dns[fetchhost] = set(fethhost_iplist)
            logging.info('resolve common.PAAS_FETCHSERVER domain to iplist=%r', fethhost_iplist)

    def handle_method(self):
        try:
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                payload = self.rfile.read(content_length) if content_length else ''
                response = self.urlfetch(self.method, self.path, self.headers, payload, common.PAAS_FETCHSERVER, password=common.PAAS_PASSWORD)
                logging.info('%s:%s "PAAS %s %s HTTP/1.1" %s -', self.remote_addr, self.remote_port, self.method, self.path, response.status)
            except socket.error as e:
                if e.reason[0] not in (11004, 10051, 10060, 'timed out', 10054):
                    raise
            except Exception as e:
                logging.exception('error: %s', e)
                raise

            if response.app_status in (400, 405):
                http.crlf = 0

            wfile = self.sock.makefile('wb', 0)
            if 'Set-Cookie' in response.msg:
                response.msg['Set-Cookie'] = re.sub(', ([^ =]+(?:=|$))', '\\r\\nSet-Cookie: \\1', response.msg['Set-Cookie'])
            wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))

            while 1:
                data = response.read(8192)
                if not data:
                    break
                wfile.write(data)
            response.close()

        except socket.error as e:
            # Connection closed before proxy return
            if e[0] not in (10053, errno.EPIPE):
                raise

    def handle_connect(self):
        return GAEProxyHandler.handle_connect_urlfetch(self)

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
    logging.info('%s:%s "POST %s SOCKS/5" - -', remote_addr, remote_port, common.SOCKS5_FETCHSERVER)
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
        remote = ssl.wrap_socket(remote, ssl_version=ssl.PROTOCOL_TLSv1)
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

class PACServerHandler(GAEProxyHandler):

    firstrun      = True
    firstrun_lock = gevent.coros.Semaphore()

    def first_run(self):
        self.__class__.filename = os.path.join(os.path.dirname(__file__), common.PAC_FILE)
        self.__class__.atime = os.path.getatime(self.filename)

    def handle_get(self):
        if time.time() - self.atime > 60*60*12:
            self.__class__.atime = time.time()
            gevent.spawn_later(1, Autoproxy2Pac.update_filename, self.filename, common.PAC_GFWLIST, '%s:%s'%(common.LISTEN_IP, common.LISTEN_PORT), True)

        wfile = self.sock.makefile('wb', 0)
        if self.path != '/'+common.PAC_FILE or not os.path.isfile(self.filename):
            wfile.write('HTTP/1.1 404\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n404 Not Found')
            wfile.close()
            logging.info('%s:%s "%s %s HTTP/1.1" 404 -', self.remote_addr, self.remote_port, self.method, self.path)
            return
        with open(self.filename, 'rb') as fp:
            data = fp.read()
            wfile.write('HTTP/1.1 200\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n')
            logging.info('%s:%s "%s %s HTTP/1.1" 200 %s', self.remote_addr, self.remote_port, self.method, self.path, fp.tell())
            wfile.write(data)
            wfile.close()

    def handle_method(self):
        self.sock.sendall('HTTP/1.1 400 Bad Request\r\n\r\n')

#GAEProxy Patch
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
                    iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x)<=255 for x in s)]
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
    if ctypes and os.name == 'nt':
        ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)
        if not common.LOVE_TIMESTAMP.strip():
            sys.stdout.write('Double click addto-startup.vbs could add goagent to autorun programs. :)\n')
        if not common.LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        else:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1)
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
    if common.GAE_APPIDS[0] == 'goagent' and not common.CRLF_ENABLE:
        logging.critical('please edit %s to add your appid to [gae] !', __config__)
        sys.exit(-1)

def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x:x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    logging.basicConfig(level=logging.DEBUG if common.LISTEN_DEBUGINFO else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    CertUtil.check_ca()
    pre_start()
    sys.stdout.write(common.info())

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
        server = gevent.server.StreamServer((common.PAC_IP, common.PAC_PORT), PACServerHandler)
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
        server = gevent.server.StreamServer((host, int(port)), PAASProxyHandler)
        server.serve_forever()
    else:
        server = gevent.server.StreamServer((common.LISTEN_IP, common.LISTEN_PORT), GAEProxyHandler)
        server.serve_forever()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
