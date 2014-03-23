#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang.2008@gmail.com>
# Based on WallProxy 0.4.0 by Hust Moon <www.ehust@gmail.com>
# Contributor:
#      Phus Lu           <phus.lu@gmail.com>
#      Hewig Xu          <hewigovens@gmail.com>
#      Ayanamist Yang    <ayanamist@gmail.com>
#      V.E.O             <V.E.O@tom.com>
#      Max Lv            <max.c.lv@gmail.com>
#      AlsoTang          <alsotang@gmail.com>
#      Christopher Meng  <i@cicku.me>
#      Yonsm Guo         <YonsmGuo@gmail.com>
#      Parkman           <cseparkman@gmail.com>
#      Ming Bai          <mbbill@gmail.com>
#      Bin Yu            <yubinlove1991@gmail.com>
#      lileixuan         <lileixuan@gmail.com>
#      Cong Ding         <cong@cding.org>
#      Zhang Youfu       <zhangyoufu@gmail.com>
#      Lu Wei            <luwei@barfoo>
#      Harmony Meow      <harmony.meow@gmail.com>
#      logostream        <logostream@gmail.com>
#      Rui Wang          <isnowfy@gmail.com>
#      Wang Wei Qiang    <wwqgtxx@gmail.com>
#      Felix Yan         <felixonmars@gmail.com>
#      Sui Feng          <suifeng.me@qq.com>
#      QXO               <qxodream@gmail.com>
#      Geek An           <geekan@foxmail.com>
#      Poly Rabbit       <mcx_221@foxmail.com>
#      oxnz              <yunxinyi@gmail.com>
#      Shusen Liu        <liushusen.smart@gmail.com>
#      Yad Smood         <y.s.inside@gmail.com>
#      Chen Shuang       <cs0x7f@gmail.com>
#      cnfuyu            <cnfuyu@gmail.com>
#      cuixin            <steven.cuixin@gmail.com>
#      s2marine0         <s2marine0@gmail.com>
#      Toshio Xiang      <snachx@gmail.com>

__version__ = '3.1.5'

import sys
import os
import glob

# GAEProxy Patch
# The sys path in Android is set up outside.

try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    gevent = None
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('\033[31m  Warning: Please update gevent to the latest 1.0 version!\033[0m\n')

import errno
import binascii
import time
import struct
import collections
import zlib
import functools
import itertools
import re
import io
import fnmatch
import traceback
import random
import subprocess
import base64
import string
import hashlib
import threading
import thread
import socket
import ssl
import select
import Queue
import SocketServer
import ConfigParser
import BaseHTTPServer
import httplib
import urllib2
import urlparse
try:
    import dnslib
except ImportError:
    dnslib = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import pacparser
except ImportError:
    pacparser = None

# GAEProxy Patch
class NullDevice():
    def write(self, s):
        pass

sys.stdout = NullDevice()
sys.stderr = sys.stdout

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

HAS_PYPY = hasattr(sys, 'pypy_version_info')
NetWorkIOError = (socket.error, ssl.SSLError, OSError) if not OpenSSL else (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)


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
        #GAEProxy Patch

    @classmethod
    def getLogger(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    def basicConfig(self, *args, **kwargs):
        self.level = int(kwargs.get('level', self.__class__.INFO))
        if self.level > self.__class__.DEBUG:
            self.debug = self.dummy

    def log(self, level, fmt, *args, **kwargs):
        sys.stderr.write('%s - [%s] %s\n' % (level, time.ctime()[4:-5], fmt % args))

    def dummy(self, *args, **kwargs):
        pass

    def debug(self, fmt, *args, **kwargs):
        self.log('DEBUG', fmt, *args, **kwargs)

    def info(self, fmt, *args, **kwargs):
        self.log('INFO', fmt, *args)

    def warning(self, fmt, *args, **kwargs):
        self.log('WARNING', fmt, *args, **kwargs)

    def warn(self, fmt, *args, **kwargs):
        self.warning(fmt, *args, **kwargs)

    def error(self, fmt, *args, **kwargs):
        self.log('ERROR', fmt, *args, **kwargs)

    def exception(self, fmt, *args, **kwargs):
        self.error(fmt, *args, **kwargs)
        sys.stderr.write(traceback.format_exc() + '\n')

    def critical(self, fmt, *args, **kwargs):
        self.log('CRITICAL', fmt, *args, **kwargs)
logging = sys.modules['logging'] = Logging('logging')


class LRUCache(object):
    """http://pypi.python.org/pypi/lru/"""

    def __init__(self, max_items=100):
        self.cache = {}
        self.key_order = []
        self.max_items = max_items

    def __setitem__(self, key, value):
        self.cache[key] = value
        self._mark(key)

    def __getitem__(self, key):
        value = self.cache[key]
        self._mark(key)
        return value

    def _mark(self, key):
        if key in self.key_order:
            self.key_order.remove(key)
        self.key_order.insert(0, key)
        if len(self.key_order) > self.max_items:
            remove = self.key_order[self.max_items]
            del self.cache[remove]
            self.key_order.pop(self.max_items)

    def clear(self):
        self.cache = {}
        self.key_order = []


class CertUtil(object):
    """CertUtil module, based on mitmproxy"""

    ca_vendor = 'GoAgent'
    ca_keyfile = 'CA.crt'
    ca_certdir = 'certs'
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
        subj.organizationName = CertUtil.ca_vendor
        subj.organizationalUnitName = '%s Root' % CertUtil.ca_vendor
        subj.commonName = '%s CA' % CertUtil.ca_vendor
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA'),
            OpenSSL.crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
        ca.sign(key, 'sha1')
        return key, ca

    @staticmethod
    def dump_ca():
        key, ca = CertUtil.create_ca()
        with open(CertUtil.ca_keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

    @staticmethod
    def _get_cert(commonname, sans=()):
        with open(CertUtil.ca_keyfile, 'rb') as fp:
            content = fp.read()
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)

        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationalUnitName = '%s Branch' % CertUtil.ca_vendor
        if commonname[0] == '.':
            subj.commonName = '*' + commonname
            subj.organizationName = '*' + commonname
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            subj.commonName = commonname
            subj.organizationName = commonname
            sans = [commonname] + [x for x in sans if x != commonname]
        # GAEProxy Patch
        req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha1')

        cert = OpenSSL.crypto.X509()
        # GAEProxy Patch
        cert.set_version(3)
        try:
            cert.set_serial_number(int(hashlib.md5(commonname.encode('utf-8')).hexdigest(), 16))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time()*1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        if commonname[0] == '.':
            sans = ['*'+commonname] + [s for s in sans if s != '*'+commonname]
        else:
            sans = [commonname] + [s for s in sans if s != commonname]
        # GAEProxy Patch
        cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, 'sha1')

        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        return certfile

    @staticmethod
    def get_cert(commonname, sans=()):
        # GAEProxy Patch
        sans = ["*.akamaihd.net","*.fbcdn.net","*.google.com","*.appspot.com","*.googleapis.com","*.googlevideo.com","*.twitter.com","*.facebook.com","*.whatsapp.net"]
        if commonname.count('.') >= 2 and [len(x) for x in reversed(commonname.split('.'))] > [2, 4]:
            commonname = '.'+commonname.partition('.')[-1]
        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        if os.path.exists(certfile):
            return certfile
        elif OpenSSL is None:
            return CertUtil.ca_keyfile
        else:
            with CertUtil.ca_lock:
                if os.path.exists(certfile):
                    return certfile
                return CertUtil._get_cert(commonname, sans)

    @staticmethod
    def import_ca(certfile):
        commonname = os.path.splitext(os.path.basename(certfile))[0]
        if OpenSSL:
            try:
                with open(certfile, 'rb') as fp:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())
                    commonname = next(v.decode() for k, v in x509.get_subject().get_components() if k == b'O')
            except Exception as e:
                logging.error('load_certificate(certfile=%r) failed:%s', certfile, e)
        # GAEProxy Patch
        return 0

    @staticmethod
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_keyfile)
        certdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_certdir)
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.path.exists(certdir):
                if os.path.isdir(certdir):
                    any(os.remove(x) for x in glob.glob(certdir+'/*.crt')+glob.glob(certdir+'/.*.crt'))
                else:
                    os.remove(certdir)
                    os.mkdir(certdir)
            CertUtil.dump_ca()
        if glob.glob('%s/*.key' % CertUtil.ca_certdir):
            for filename in glob.glob('%s/*.key' % CertUtil.ca_certdir):
                try:
                    os.remove(filename)
                    os.remove(os.path.splitext(filename)[0]+'.crt')
                except EnvironmentError:
                    pass
        #Check CA imported
        if CertUtil.import_ca(capath) != 0:
            logging.warning('install root certificate failed, Please run as administrator/root/sudo')
        #Check Certs Dir
        if not os.path.exists(certdir):
            os.makedirs(certdir)


class SSLConnection(object):

    has_gevent = socket.socket is getattr(sys.modules.get('gevent.socket'), 'socket', None)

    def __init__(self, context, sock):
        self._context = context
        self._sock = sock
        self._connection = OpenSSL.SSL.Connection(context, sock)
        self._makefile_refs = 0
        if self.has_gevent:
            self._wait_read = gevent.socket.wait_read
            self._wait_write = gevent.socket.wait_write
            self._wait_readwrite = gevent.socket.wait_readwrite
        else:
            self._wait_read = lambda fd,t: select.select([fd], [], [fd], t)
            self._wait_write = lambda fd,t: select.select([], [fd], [fd], t)
            self._wait_readwrite = lambda fd,t: select.select([fd], [fd], [fd], t)

    def __getattr__(self, attr):
        if attr not in ('_context', '_sock', '_connection', '_makefile_refs'):
            return getattr(self._connection, attr)

    def accept(self):
        sock, addr = self._sock.accept()
        client = OpenSSL.SSL.Connection(sock._context, sock)
        return client, addr

    def do_handshake(self):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.do_handshake()
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError, OpenSSL.SSL.WantWriteError):
                sys.exc_clear()
                self._wait_readwrite(self._sock.fileno(), timeout)

    def connect(self, *args, **kwargs):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.connect(*args, **kwargs)
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)

    def send(self, data, flags=0):
        timeout = self._sock.gettimeout()
        while True:
            try:
                self._connection.send(data, flags)
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)
            except OpenSSL.SSL.SysCallError as e:
                if e[0] == -1 and not data:
                    # errors when writing empty strings are expected and can be ignored
                    return 0
                raise

    def recv(self, bufsiz, flags=0):
        timeout = self._sock.gettimeout()
        pending = self._connection.pending()
        if pending:
            return self._connection.recv(min(pending, bufsiz))
        while True:
            try:
                return self._connection.recv(bufsiz, flags)
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                self._wait_read(self._sock.fileno(), timeout)
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                self._wait_write(self._sock.fileno(), timeout)
            except OpenSSL.SSL.ZeroReturnError:
                return ''

    def read(self, bufsiz, flags=0):
        return self.recv(bufsiz, flags)

    def write(self, buf, flags=0):
        return self.sendall(buf, flags)

    def close(self):
        if self._makefile_refs < 1:
            self._connection = None
            if self._sock:
                socket.socket.close(self._sock)
        else:
            self._makefile_refs -= 1

    def makefile(self, mode='r', bufsize=-1):
        self._makefile_refs += 1
        return socket._fileobject(self, mode, bufsize, close=True)



class ProxyUtil(object):
    """ProxyUtil module, based on urllib2"""

    @staticmethod
    def parse_proxy(proxy):
        return urllib2._parse_proxy(proxy)

    @staticmethod
    def get_system_proxy():
        proxies = urllib2.getproxies()
        return proxies.get('https') or proxies.get('http') or {}

    @staticmethod
    def get_listen_ip():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 53))
        listen_ip = sock.getsockname()[0]
        sock.close()
        return listen_ip

# GAEProxy Patch
# No PAC

def dns_remote_resolve(qname, dnsservers, blacklist, timeout):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    """
    query = dnslib.DNSRecord(q=dnslib.DNSQuestion(qname))
    query_data = query.pack()
    dns_v4_servers = [x for x in dnsservers if ':' not in x]
    dns_v6_servers = [x for x in dnsservers if ':' in x]
    sock_v4 = sock_v6 = None
    socks = []
    if dns_v4_servers:
        sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socks.append(sock_v4)
    if dns_v6_servers:
        sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        socks.append(sock_v6)
    timeout_at = time.time() + timeout
    try:
        for _ in xrange(2):
            try:
                for dnsserver in dns_v4_servers:
                    sock_v4.sendto(query_data, (dnsserver, 53))
                for dnsserver in dns_v6_servers:
                    sock_v6.sendto(query_data, (dnsserver, 53))
                while time.time() < timeout_at:
                    ins, _, _ = select.select(socks, [], [], 0.1)
                    for sock in ins:
                        reply_data, _ = sock.recvfrom(512)
                        reply = dnslib.DNSRecord.parse(reply_data)
                        rtypes = (1, 28) if sock is sock_v6 else (1,)
                        iplist = [str(x.rdata) for x in reply.rr if x.rtype in rtypes]
                        if any(x in blacklist for x in iplist):
                            logging.warning('query qname=%r reply bad iplist=%r', qname, iplist)
                        else:
                            logging.debug('query qname=%r reply iplist=%s', qname, iplist)
                            return iplist
            except socket.error as e:
                logging.warning('handle dns query=%s socket: %r', query, e)
    finally:
        for sock in socks:
            sock.close()


def get_dnsserver_list():
    if os.name == 'nt':
        import ctypes, ctypes.wintypes, struct, socket
        DNS_CONFIG_DNS_SERVER_LIST = 6
        buf = ctypes.create_string_buffer(2048)
        ctypes.windll.dnsapi.DnsQueryConfig(DNS_CONFIG_DNS_SERVER_LIST, 0, None, None, ctypes.byref(buf), ctypes.byref(ctypes.wintypes.DWORD(len(buf))))
        ips = struct.unpack('I', buf[0:4])[0]
        out = []
        for i in xrange(ips):
            start = (i+1) * 4
            out.append(socket.inet_ntoa(buf[start:start+4]))
        return out
    elif os.path.isfile('/etc/resolv.conf'):
        with open('/etc/resolv.conf', 'rb') as fp:
            return re.findall(r'(?m)^nameserver\s+(\S+)', fp.read())
    else:
        logging.warning("get_dnsserver_list failed: unsupport platform '%s-%s'", sys.platform, os.name)
        return []


def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        __import__('time').sleep(seconds)
        return target(*args, **kwargs)
    return __import__('thread').start_new_thread(wrap, args, kwargs)


class HTTPUtil(object):
    """HTTP Request Class"""

    MessageClass = dict
    protocol_version = 'HTTP/1.1'
    skip_headers = frozenset(['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations', 'Connection', 'Cache-Control'])
    ssl_validate = False
    ssl_obfuscate = False
    ssl_ciphers = ':'.join(['ECDHE-ECDSA-AES256-SHA',
                            'ECDHE-RSA-AES256-SHA',
                            'DHE-RSA-CAMELLIA256-SHA',
                            'DHE-DSS-CAMELLIA256-SHA',
                            'DHE-RSA-AES256-SHA',
                            'DHE-DSS-AES256-SHA',
                            'ECDH-RSA-AES256-SHA',
                            'ECDH-ECDSA-AES256-SHA',
                            'CAMELLIA256-SHA',
                            'AES256-SHA',
                            'ECDHE-ECDSA-RC4-SHA',
                            'ECDHE-ECDSA-AES128-SHA',
                            'ECDHE-RSA-RC4-SHA',
                            'ECDHE-RSA-AES128-SHA',
                            'DHE-RSA-CAMELLIA128-SHA',
                            'DHE-DSS-CAMELLIA128-SHA',
                            'DHE-RSA-AES128-SHA',
                            'DHE-DSS-AES128-SHA',
                            'ECDH-RSA-RC4-SHA',
                            'ECDH-RSA-AES128-SHA',
                            'ECDH-ECDSA-RC4-SHA',
                            'ECDH-ECDSA-AES128-SHA',
                            'SEED-SHA',
                            'CAMELLIA128-SHA',
                            'RC4-SHA',
                            'RC4-MD5',
                            'AES128-SHA',
                            'ECDHE-ECDSA-DES-CBC3-SHA',
                            'ECDHE-RSA-DES-CBC3-SHA',
                            'EDH-RSA-DES-CBC3-SHA',
                            'EDH-DSS-DES-CBC3-SHA',
                            'ECDH-RSA-DES-CBC3-SHA',
                            'ECDH-ECDSA-DES-CBC3-SHA',
                            'DES-CBC3-SHA',
                            'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'])

    def __init__(self, max_window=4, max_timeout=8, max_retry=4, proxy='', dns_servers=[], dns_blacklist=set()):
        # http://docs.python.org/dev/library/ssl.html
        # http://blog.ivanristic.com/2009/07/examples-of-the-information-collected-from-ssl-handshakes.html
        # http://src.chromium.org/svn/trunk/src/net/third_party/nss/ssl/sslenum.c
        # http://www.openssl.org/docs/apps/ciphers.html
        # openssl s_server -accept 443 -key CA.crt -cert CA.crt
        # set_ciphers as Modern Browsers
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.tcp_connection_time = collections.defaultdict(float)
        self.tcp_connection_cache = collections.defaultdict(Queue.PriorityQueue)
        self.ssl_connection_time = collections.defaultdict(float)
        self.ssl_connection_cache = collections.defaultdict(Queue.PriorityQueue)
        self.dns = {}
        self.proxy = proxy
        self.openssl_context = None
        if self.proxy:
            self.dns_resolve = self.__dns_resolve_withproxy
            self.create_connection = self.__create_connection_withproxy
            self.create_ssl_connection = self.__create_ssl_connection_withproxy
        self.dns_servers = dns_servers
        self.dns_blacklist = dns_blacklist

    def set_openssl_option(self, validate=True, obfuscate=True):
        if self.openssl_context is None:
            self.openssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            self.openssl_context.set_session_id(binascii.b2a_hex(os.urandom(10)))
            if hasattr(OpenSSL.SSL, 'SESS_CACHE_BOTH'):
                self.openssl_context.set_session_cache_mode(OpenSSL.SSL.SESS_CACHE_BOTH)
        if validate:
            self.openssl_context.load_verify_locations(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cacert.pem'))
            self.openssl_context.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda c, x, e, d, ok: ok)
        if obfuscate:
            ssl_ciphers = ':'.join(x for x in self.ssl_ciphers.split(':') if random.random() > 0.5)
            self.openssl_context.set_cipher_list(ssl_ciphers)

    def dns_resolve(self, host, dnsservers=[], ipv4_only=True):
        iplist = self.dns.get(host)
        if not iplist:
            if not dnsservers:
                iplist = list(set(socket.gethostbyname_ex(host)[-1]) - self.dns_blacklist)
            else:
                iplist = dns_remote_resolve(host, dnsservers, self.dns_blacklist, timeout=2)
            if not iplist:
                iplist = dns_remote_resolve(host, self.dns_servers, self.dns_blacklist, timeout=2)
            if ipv4_only:
                iplist = [ip for ip in iplist if re.match(r'\d+\.\d+\.\d+\.\d+', ip)]
            self.dns[host] = iplist = list(set(iplist))
        return iplist

    def __dns_resolve_withproxy(self, host, dnsservers=[], ipv4_only=True):
        return [host]

    def create_connection(self, address, timeout=None, source_address=None, **kwargs):
        connection_cache_key = kwargs.get('cache_key')
        def _create_connection(ipaddr, timeout, queobj):
            sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable nagle algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                sock.connect(ipaddr)
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = time.time() - start_time
                # put ssl socket object to output queobj
                queobj.put(sock)
            except (socket.error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.tcp_connection_time[ipaddr] = self.max_timeout+random.random()
                # close tcp socket
                if sock:
                    sock.close()
        def _close_connection(count, queobj):
            for i in range(count):
                sock = queobj.get()
                if sock and not isinstance(sock, Exception):
                    if connection_cache_key and i == 0:
                        self.tcp_connection_cache[connection_cache_key].put((time.time(), sock))
                    else:
                        sock.close()
        try:
            while connection_cache_key:
                ctime, sock = self.tcp_connection_cache[connection_cache_key].get_nowait()
                if time.time() - ctime < 30:
                    return sock
        except Queue.Empty:
            pass
        host, port = address
        result = None
        addresses = [(x, port) for x in self.dns_resolve(host)]
        if port == 443:
            get_connection_time = lambda addr: self.ssl_connection_time.__getitem__(addr) or self.tcp_connection_time.__getitem__(addr)
        else:
            get_connection_time = self.tcp_connection_time.__getitem__
        for i in range(self.max_retry):
            window = min((self.max_window+1)//2 + min(i, 1), len(addresses))
            addresses.sort(key=get_connection_time)
            addrs = addresses[:window] + random.sample(addresses, min(len(addresses), window, self.max_window-window))
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(_create_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, (socket.error, OSError)):
                    thread.start_new_thread(_close_connection, (len(addrs)-i-1, queobj))
                    return result
                else:
                    if i == 0:
                        # only output first error
                        logging.warning('create_connection to %s return %r, try again.', addrs, result)

    def create_ssl_connection(self, address, timeout=None, source_address=None, **kwargs):
        connection_cache_key = kwargs.get('cache_key')
        validate = kwargs.get('validate')
        def _create_ssl_connection(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # pick up the certificate
                if not validate:
                    ssl_sock = ssl.wrap_socket(sock, do_handshake_on_connect=False)
                else:
                    ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs=os.path.join(os.path.dirname(os.path.abspath(__file__)),'cacert.pem'), do_handshake_on_connect=False)
                ssl_sock.settimeout(timeout or self.max_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                ssl_sock.ssl_time = connected_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if validate and address[0].endswith('.appspot.com'):
                    cert = ssl_sock.getpeercert()
                    orgname = next((v for ((k, v),) in cert['subject'] if k == 'organizationName'))
                    if not orgname.lower().startswith('google '):
                        raise ssl.SSLError("%r certificate organizationName(%r) not startswith 'Google'" % (address[0], orgname))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except (socket.error, ssl.SSLError, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.max_timeout + random.random()
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()
        def _create_openssl_connection(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # pick up the certificate
                server_hostname = b'www.google.com' if address[0].endswith('.appspot.com') else None
                ssl_sock = SSLConnection(self.openssl_context, sock)
                ssl_sock.set_connect_state()
                if server_hostname:
                    ssl_sock.set_tlsext_host_name(server_hostname)
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if validate and address[0].endswith('.appspot.com'):
                    cert = ssl_sock.get_peer_certificate()
                    commonname = next((v for k, v in cert.get_subject().get_components() if k == 'CN'))
                    if '.google' not in commonname and not commonname.endswith('.appspot.com'):
                        raise socket.error("Host name '%s' doesn't match certificate host '%s'" % (address[0], commonname))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except (socket.error, OpenSSL.SSL.Error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.max_timeout + random.random()
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()
        def _close_ssl_connection(count, queobj, first_tcp_time, first_ssl_time):
            for i in range(count):
                sock = queobj.get()
                ssl_time_threshold = min(1, 1.5 * first_ssl_time)
                if sock and not isinstance(sock, Exception):
                    if connection_cache_key and sock.ssl_time < ssl_time_threshold:
                        self.ssl_connection_cache[connection_cache_key].put((time.time(), sock))
                    else:
                        sock.close()
        try:
            while connection_cache_key:
                ctime, sock = self.ssl_connection_cache[connection_cache_key].get_nowait()
                if time.time() - ctime < 30:
                    return sock
        except Queue.Empty:
            pass
        host, port = address
        result = None
        # create_connection = _create_ssl_connection if not validate else _create_openssl_connection
        create_connection = _create_ssl_connection
        addresses = [(x, port) for x in self.dns_resolve(host)]
        for i in range(self.max_retry):
            window = min((self.max_window+1)//2 + min(i, 1), len(addresses))
            addresses.sort(key=self.ssl_connection_time.__getitem__)
            addrs = addresses[:window] + random.sample(addresses, min(len(addresses), window, self.max_window-window))
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(create_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, Exception):
                    thread.start_new_thread(_close_ssl_connection, (len(addrs)-i-1, queobj, result.tcp_time, result.ssl_time))
                    return result
                else:
                    if i == 0:
                        # only output first error
                        logging.warning('create_ssl_connection to %s return %r, try again.', addrs, result)

    def __create_connection_withproxy(self, address, timeout=None, source_address=None, **kwargs):
        host, port = address
        logging.debug('__create_connection_withproxy connect (%r, %r)', host, port)
        _, proxyuser, proxypass, proxyaddress = ProxyUtil.parse_proxy(self.proxy)
        try:
            try:
                self.dns_resolve(host)
            except (socket.error, OSError):
                pass
            proxyhost, _, proxyport = proxyaddress.rpartition(':')
            sock = socket.create_connection((proxyhost, int(proxyport)))
            if host in self.dns:
                hostname = random.choice(self.dns[host])
            elif host.endswith('.appspot.com'):
                hostname = 'www.google.com'
            else:
                hostname = host
            request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
            if proxyuser and proxypass:
                request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (proxyuser, proxypass)).encode()).decode().strip()
            request_data += '\r\n'
            sock.sendall(request_data)
            response = httplib.HTTPResponse(sock)
            response.begin()
            if response.status >= 400:
                logging.error('__create_connection_withproxy return http error code %s', response.status)
                sock = None
            return sock
        except Exception as e:
            logging.error('__create_connection_withproxy error %s', e)
            raise

    def __create_ssl_connection_withproxy(self, address, timeout=None, source_address=None, **kwargs):
        host, port = address
        logging.debug('__create_ssl_connection_withproxy connect (%r, %r)', host, port)
        try:
            sock = self.__create_connection_withproxy(address, timeout, source_address)
            ssl_sock = ssl.wrap_socket(sock)
            ssl_sock.sock = sock
            return ssl_sock
        except Exception as e:
            logging.error('__create_ssl_connection_withproxy error %s', e)
            raise

    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None):
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
                        if data:
                            if sock is remote:
                                local.sendall(data)
                                timecount = maxpong or timeout
                            else:
                                remote.sendall(data)
                                timecount = maxping or timeout
                        else:
                            return
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        finally:
            if local:
                local.close()
            if remote:
                remote.close()

    def green_forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, pongcallback=None, bitmask=None):
        def io_copy(dest, source):
            try:
                dest.settimeout(timeout)
                source.settimeout(timeout)
                while 1:
                    data = source.recv(bufsize)
                    if not data:
                        break
                    if bitmask:
                        data = ''.join(chr(ord(x) ^ bitmask) for x in data)
                    dest.sendall(data)
            except NetWorkIOError as e:
                if e.args[0] not in ('timed out', errno.ECONNABORTED, errno.ECONNRESET, errno.EBADF, errno.EPIPE, errno.ENOTCONN, errno.ETIMEDOUT):
                    raise
            finally:
                if local:
                    local.close()
                if remote:
                    remote.close()
        thread.start_new_thread(io_copy, (remote.dup(), local.dup()))
        io_copy(local, remote)

    def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=8192, crlf=None, return_sock=None):
        skip_headers = self.skip_headers
        need_crlf = bool(crlf)
        if need_crlf:
            fakehost = 'www.' + ''.join(random.choice(('bcdfghjklmnpqrstvwxyz','aeiou')[x&1]) for x in xrange(random.randint(5,20))) + random.choice(['.net', '.com', '.org'])
            request_data = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n\r\n\r\r' % fakehost
        else:
            request_data = ''
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k.title(), v) for k, v in headers.items() if k.title() not in skip_headers)
        if self.proxy:
            _, username, password, _ = ProxyUtil.parse_proxy(self.proxy)
            if username and password:
                request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).decode().strip()
        request_data += '\r\n'

        if isinstance(payload, bytes):
            sock.sendall(request_data.encode() + payload)
        elif hasattr(payload, 'read'):
            sock.sendall(request_data)
            while 1:
                data = payload.read(bufsize)
                if not data:
                    break
                sock.sendall(data)
        else:
            raise TypeError('http_util.request(payload) must be a string or buffer, not %r' % type(payload))

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

        response = httplib.HTTPResponse(sock, buffering=True)
        try:
            response.begin()
        except httplib.BadStatusLine:
            response = None
        return response

    def request(self, method, url, payload=None, headers={}, realhost='', bufsize=8192, crlf=None, validate=None, return_sock=None, connection_cache_key=None):
        scheme, netloc, path, _, query, _ = urlparse.urlparse(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query

        if 'Host' not in headers:
            headers['Host'] = host
        if payload and 'Content-Length' not in headers:
            headers['Content-Length'] = str(len(payload))

        for i in range(self.max_retry):
            sock = None
            ssl_sock = None
            try:
                if scheme == 'https':
                    ssl_sock = self.create_ssl_connection((realhost or host, port), self.max_timeout, validate=validate, cache_key=connection_cache_key)
                    if ssl_sock:
                        sock = ssl_sock.sock
                        del ssl_sock.sock
                    else:
                        raise socket.error('timed out', 'create_ssl_connection(%r,%r)' % (realhost or host, port))
                else:
                    sock = self.create_connection((realhost or host, port), self.max_timeout, cache_key=connection_cache_key)
                if sock:
                    if scheme == 'https':
                        crlf = 0
                    return self._request(ssl_sock or sock, method, path, self.protocol_version, headers, payload, bufsize=bufsize, crlf=crlf, return_sock=return_sock)
            except Exception as e:
                logging.debug('request "%s %s" failed:%s', method, url, e)
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

    ENV_CONFIG_PREFIX = 'GOAGENT_'

    def __init__(self):
        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        # GAEProxy Patch
        self.CONFIG_FILENAME = '/data/data/org.gaeproxy/proxy.ini'
        self.CONFIG.read(self.CONFIG_FILENAME)

        self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
        self.LISTEN_VISIBLE = self.CONFIG.getint('listen', 'visible')
        self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo')

        self.GAE_APPIDS = re.findall(r'[\w\-\.]+', self.CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
        self.GAE_PASSWORD = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH = self.CONFIG.get('gae', 'path')
        self.GAE_MODE = self.CONFIG.get('gae', 'mode')
        self.GAE_PROFILE = self.CONFIG.get('gae', 'profile').strip()
        self.GAE_WINDOW = self.CONFIG.getint('gae', 'window')
        self.GAE_VALIDATE = self.CONFIG.getint('gae', 'validate')
        self.GAE_OBFUSCATE = self.CONFIG.getint('gae', 'obfuscate')
        self.GAE_OPTIONS = self.CONFIG.get('gae', 'options')

        hosts_section, http_section = '%s/hosts' % self.GAE_PROFILE, '%s/http' % self.GAE_PROFILE
        self.HOSTS_MAP = collections.OrderedDict((k, v or k) for k, v in self.CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and not k.startswith('.'))
        self.HOSTS_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and k.startswith('.'))
        self.HOSTS_POSTFIX_ENDSWITH = tuple(self.HOSTS_POSTFIX_MAP)

        self.CONNECT_HOSTS_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if ':' in k and not k.startswith('.'))
        self.CONNECT_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if ':' in k and k.startswith('.'))
        self.CONNECT_POSTFIX_ENDSWITH = tuple(self.CONNECT_POSTFIX_MAP)

        self.METHOD_REMATCH_MAP = collections.OrderedDict((re.compile(k).match, v) for k, v in self.CONFIG.items(hosts_section) if '\\' in k)
        self.METHOD_REMATCH_HAS_LOCALFILE = any(x.startswith('file://') for x in self.METHOD_REMATCH_MAP.values())

        self.HTTP_WITHGAE = tuple(self.CONFIG.get(http_section, 'withgae').split('|'))
        self.HTTP_CRLFSITES = tuple(self.CONFIG.get(http_section, 'crlfsites').split('|'))
        self.HTTP_FORCEHTTPS = set(self.CONFIG.get(http_section, 'forcehttps').split('|'))
        self.HTTP_FAKEHTTPS = set(self.CONFIG.get(http_section, 'fakehttps').split('|'))
        self.HTTP_DNS = self.CONFIG.get(http_section, 'dns').split('|') if self.CONFIG.has_option(http_section, 'dns') else []
        for hostname in [k for k, _ in self.CONFIG.items(hosts_section) if k.startswith(('http://', 'https://', 'https?://'))]:
            m = re.search(r'(?<=//)(\-|\_|\w|\\.)+(?=/)', hostname)
            if m:
                host = m.group().replace('\\.', '.')
                self.HTTP_FAKEHTTPS.add(host)
                logging.info('add host=%r to fakehttps', host)

        self.IPLIST_MAP = collections.OrderedDict((k, v.split('|')) for k, v in self.CONFIG.items('iplist'))
        self.IPLIST_MAP.update((k, [k]) for k, v in self.HOSTS_MAP.items() if k == v)

        # GAEProxy Patch
        # No PAC

        self.PHP_ENABLE = self.CONFIG.getint('php', 'enable')
        self.PHP_LISTEN = self.CONFIG.get('php', 'listen')
        self.PHP_PASSWORD = self.CONFIG.get('php', 'password') if self.CONFIG.has_option('php', 'password') else ''
        self.PHP_CRLF = self.CONFIG.getint('php', 'crlf') if self.CONFIG.has_option('php', 'crlf') else 1
        self.PHP_VALIDATE = self.CONFIG.getint('php', 'validate') if self.CONFIG.has_option('php', 'validate') else 0
        self.PHP_FETCHSERVER = self.CONFIG.get('php', 'fetchserver')
        self.PHP_USEHOSTS = self.CONFIG.getint('php', 'usehosts')

        self.PROXY_ENABLE = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_AUTODETECT = self.CONFIG.getint('proxy', 'autodetect') if self.CONFIG.has_option('proxy', 'autodetect') else 0
        self.PROXY_HOST = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT = self.CONFIG.getint('proxy', 'port')
        self.PROXY_USERNAME = self.CONFIG.get('proxy', 'username')
        self.PROXY_PASSWROD = self.CONFIG.get('proxy', 'password')

        if not self.PROXY_ENABLE and self.PROXY_AUTODETECT:
            system_proxy = ProxyUtil.get_system_proxy()
            if system_proxy and self.LISTEN_IP not in system_proxy:
                _, username, password, address = ProxyUtil.parse_proxy(system_proxy)
                proxyhost, _, proxyport = address.rpartition(':')
                self.PROXY_ENABLE = 1
                self.PROXY_USERNAME = username
                self.PROXY_PASSWROD = password
                self.PROXY_HOST = proxyhost
                self.PROXY_PORT = int(proxyport)
        if self.PROXY_ENABLE:
            self.GAE_MODE = 'https'
            self.proxy = 'https://%s:%s@%s:%d' % (self.PROXY_USERNAME or '', self.PROXY_PASSWROD or '', self.PROXY_HOST, self.PROXY_PORT)
        else:
            self.proxy = ''

        self.AUTORANGE_HOSTS = self.CONFIG.get('autorange', 'hosts').split('|')
        self.AUTORANGE_HOSTS_MATCH = [re.compile(fnmatch.translate(h)).match for h in self.AUTORANGE_HOSTS]
        self.AUTORANGE_ENDSWITH = tuple(self.CONFIG.get('autorange', 'endswith').split('|'))
        self.AUTORANGE_NOENDSWITH = tuple(self.CONFIG.get('autorange', 'noendswith').split('|'))
        self.AUTORANGE_MAXSIZE = self.CONFIG.getint('autorange', 'maxsize')
        self.AUTORANGE_WAITSIZE = self.CONFIG.getint('autorange', 'waitsize')
        self.AUTORANGE_BUFSIZE = self.CONFIG.getint('autorange', 'bufsize')
        self.AUTORANGE_THREADS = self.CONFIG.getint('autorange', 'threads')

        self.FETCHMAX_LOCAL = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER = self.CONFIG.get('fetchmax', 'server')

        self.DNS_ENABLE = self.CONFIG.getint('dns', 'enable')
        self.DNS_LISTEN = self.CONFIG.get('dns', 'listen')
        self.DNS_SERVERS = self.HTTP_DNS or self.CONFIG.get('dns', 'servers').split('|')
        self.DNS_BLACKLIST = set(self.CONFIG.get('dns', 'blacklist').split('|'))

        self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE = self.CONFIG.getint('love', 'enable')
        # GAEProxy Patch
        self.LOVE_TIP             = [re.sub(r'\\u([0-9a-fA-F]{4})', lambda m:unichr(int(m.group(1), 16)), x) for x in self.CONFIG.get('love','tip').split('|')]

    def resolve_iplist(self):
        def do_resolve(host, dnsservers, queue):
            try:
                iplist = dns_remote_resolve(host, dnsservers, self.DNS_BLACKLIST, timeout=2)
                queue.put((host, dnsservers, iplist or []))
            except (socket.error, OSError) as e:
                logging.error('resolve remote host=%r failed: %s', host, e)
                queue.put((host, dnsservers, []))
        # https://support.google.com/websearch/answer/186669?hl=zh-Hans
        google_blacklist = ['216.239.32.20', '74.125.127.102', '74.125.155.102', '74.125.39.102', '74.125.39.113', '209.85.229.138']
        for name, need_resolve_hosts in list(self.IPLIST_MAP.items()):
            if all(re.match(r'\d+\.\d+\.\d+\.\d+', x) or ':' in x for x in need_resolve_hosts):
                continue
            need_resolve_remote = [x for x in need_resolve_hosts if ':' not in x and not re.match(r'\d+\.\d+\.\d+\.\d+', x)]
            resolved_iplist = [x for x in need_resolve_hosts if x not in need_resolve_remote]
            result_queue = Queue.Queue()
            for host in need_resolve_remote:
                for dnsserver in self.DNS_SERVERS:
                    logging.debug('resolve remote host=%r from dnsserver=%r', host, dnsserver)
                    threading._start_new_thread(do_resolve, (host, [dnsserver], result_queue))
            for _ in xrange(len(self.DNS_SERVERS) * len(need_resolve_remote)):
                try:
                    host, dnsservers, iplist = result_queue.get(timeout=2)
                    resolved_iplist += iplist or []
                    logging.debug('resolve remote host=%r from dnsservers=%s return iplist=%s', host, dnsservers, iplist)
                except Queue.Empty:
                    logging.warn('resolve remote timeout, try resolve local')
                    resolved_iplist += sum([socket.gethostbyname_ex(x)[-1] for x in need_resolve_remote], [])
                    break
            if name.startswith('google_') and name not in ('google_cn', 'google_hk'):
                iplist_prefix = re.split(r'[\.:]', resolved_iplist[0])[0]
                resolved_iplist = list(set(x for x in resolved_iplist if x.startswith(iplist_prefix)))
            else:
                resolved_iplist = list(set(resolved_iplist))
            if name.startswith('google_'):
                resolved_iplist = list(set(resolved_iplist) - set(google_blacklist))
            if len(resolved_iplist) == 0:
                logging.error('resolve %s host return empty! please retry!', name)
                sys.exit(-1)
            logging.info('resolve name=%s host to iplist=%r', name, resolved_iplist)
            common.IPLIST_MAP[name] = resolved_iplist


    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version    : %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
        info += 'Uvent Version      : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Local Proxy        : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug INFO         : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += 'GAE Mode           : %s\n' % self.GAE_MODE
        info += 'GAE Profile        : %s\n' % self.GAE_PROFILE if self.GAE_PROFILE else ''
        info += 'GAE APPID          : %s\n' % '|'.join(self.GAE_APPIDS)
        info += 'GAE Validate       : %s\n' % self.GAE_VALIDATE if self.GAE_VALIDATE else ''
        info += 'GAE Obfuscate      : %s\n' % self.GAE_OBFUSCATE if self.GAE_OBFUSCATE else ''

        # GAEProxy Patch
        # No PAC

        if common.PHP_ENABLE:
            info += 'PHP Listen         : %s\n' % common.PHP_LISTEN
            info += 'PHP FetchServer    : %s\n' % common.PHP_FETCHSERVER
        if common.DNS_ENABLE:
            info += 'DNS Listen         : %s\n' % common.DNS_LISTEN
            info += 'DNS Servers        : %s\n' % '|'.join(common.DNS_SERVERS)
        info += '------------------------------------------------------\n'
        return info

common = Common()
http_util = HTTPUtil(max_window=common.GAE_WINDOW, proxy=common.proxy, dns_servers=common.DNS_SERVERS, dns_blacklist=common.DNS_BLACKLIST)


def message_html(title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>$title</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>$banner</H1>
    $detail
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    return string.Template(MESSAGE_TEMPLATE).substitute(title=title, banner=banner, detail=detail)


try:
    from Crypto.Cipher.ARC4 import new as RC4Cipher
except ImportError:
    logging.warn('Load Crypto.Cipher.ARC4 Failed, Use Pure Python Instead.')
    class RC4Cipher(object):
        def __init__(self, key):
            x = 0
            box = range(256)
            for i, y in enumerate(box):
                x = (x + y + ord(key[i % len(key)])) & 0xff
                box[i], box[x] = box[x], y
            self.__box = box
            self.__x = 0
            self.__y = 0
        def encrypt(self, data):
            out = []
            out_append = out.append
            x = self.__x
            y = self.__y
            box = self.__box
            for char in data:
                x = (x + 1) & 0xff
                y = (y + box[x]) & 0xff
                box[x], box[y] = box[y], box[x]
                out_append(chr(ord(char) ^ box[(box[x] + box[y]) & 0xff]))
            self.__x = x
            self.__y = y
            return ''.join(out)


class RC4FileObject(object):
    """fileobj for rc4"""
    def __init__(self, stream, key):
        self.__stream = stream
        self.__cipher = RC4Cipher(key) if key else lambda x:x
    def __getattr__(self, attr):
        if attr not in ('__stream', '__cipher'):
            return getattr(self.__stream, attr)
    def read(self, size=-1):
        return self.__cipher.encrypt(self.__stream.read(size))


class XORCipher(object):
    """XOR Cipher Class"""
    def __init__(self, key):
        self.__key_gen = itertools.cycle([ord(x) for x in key]).next
        self.__key_xor = lambda s: ''.join(chr(ord(x) ^ self.__key_gen()) for x in s)
        if len(key) == 1:
            try:
                from Crypto.Util.strxor import strxor_c
                c = ord(key)
                self.__key_xor = lambda s: strxor_c(s, c)
            except ImportError:
                sys.stderr.write('Load Crypto.Util.strxor Failed, Use Pure Python Instead.\n')

    def encrypt(self, data):
        return self.__key_xor(data)


def gae_urlfetch(method, url, headers, payload, fetchserver, **kwargs):
    # deflate = lambda x:zlib.compress(x)[2:-4]
    rc4crypt = lambda s, k: RC4Cipher(k).encrypt(s) if k else s
    if payload:
        if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers['Content-Encoding'] = 'deflate'
        headers['Content-Length'] = str(len(payload))
    # GAE donot allow set `Host` header
    if 'Host' in headers:
        del headers['Host']
    metadata = 'G-Method:%s\nG-Url:%s\n%s' % (method, url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v))
    skip_headers = http_util.skip_headers
    metadata += ''.join('%s:%s\n' % (k.title(), v) for k, v in headers.items() if k not in skip_headers)
    # prepare GAE request
    request_method = 'POST'
    request_headers = {}
    if common.GAE_OBFUSCATE:
        if 'rc4' in common.GAE_OPTIONS:
            request_headers['X-GOA-Options'] = 'rc4'
            cookie = base64.b64encode(rc4crypt(zlib.compress(metadata)[2:-4], kwargs.get('password'))).strip()
            payload = rc4crypt(payload, kwargs.get('password'))
        else:
            cookie = base64.b64encode(zlib.compress(metadata)[2:-4]).strip()
        request_headers['Cookie'] = cookie
        if payload:
            request_headers['Content-Length'] = str(len(payload))
        else:
            request_method = 'GET'
    else:
        metadata = zlib.compress(metadata)[2:-4]
        payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, payload)
        if 'rc4' in common.GAE_OPTIONS:
            request_headers['X-GOA-Options'] = 'rc4'
            payload = rc4crypt(payload, kwargs.get('password'))
        request_headers['Content-Length'] = str(len(payload))
    # post data
    need_crlf = 0 if common.GAE_MODE == 'https' else 1
    need_validate = common.GAE_VALIDATE
    connection_cache_key = '%s:%d' % (common.HOSTS_POSTFIX_MAP['.appspot.com'], 443 if common.GAE_MODE == 'https' else 80)
    response = http_util.request(request_method, fetchserver, payload, request_headers, crlf=need_crlf, validate=need_validate, connection_cache_key=connection_cache_key)
    response.app_status = response.status
    response.app_options = response.getheader('X-GOA-Options', '')
    if response.status != 200:
        return response
    data = response.read(4)
    if len(data) < 4:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short leadtype data=' + data)
        response.read = response.fp.read
        return response
    response.status, headers_length = struct.unpack('!hh', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short headers data=' + data)
        response.read = response.fp.read
        return response
    if 'rc4' not in response.app_options:
        response.msg = httplib.HTTPMessage(io.BytesIO(zlib.decompress(data, -zlib.MAX_WBITS)))
    else:
        response.msg = httplib.HTTPMessage(io.BytesIO(zlib.decompress(rc4crypt(data, kwargs.get('password')), -zlib.MAX_WBITS)))
        if kwargs.get('password') and response.fp:
            response.fp = RC4FileObject(response.fp, kwargs['password'])
    return response


class RangeFetch(object):
    """Range Fetch Class"""

    maxsize = 1024*1024*4
    bufsize = 8192
    threads = 1
    waitsize = 1024*512
    expect_begin = 0

    def __init__(self, urlfetch, wfile, response, method, url, headers, payload, fetchservers, password, maxsize=0, bufsize=0, waitsize=0, threads=0):
        self.urlfetch = urlfetch
        self.wfile = wfile
        self.response = response
        self.command = method
        self.url = url
        self.headers = headers
        self.payload = payload
        self.fetchservers = fetchservers
        self.password = password
        self.maxsize = maxsize or self.__class__.maxsize
        self.bufsize = bufsize or self.__class__.bufsize
        self.waitsize = waitsize or self.__class__.bufsize
        self.threads = threads or self.__class__.threads
        self._stopped = None
        self._last_app_status = {}

    def fetch(self):
        response_status = self.response.status
        response_headers = dict((k.title(), v) for k, v in self.response.getheaders())
        content_range = response_headers['Content-Range']
        #content_length = response_headers['Content-Length']
        start, end, length = tuple(int(x) for x in re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
        if start == 0:
            response_status = 200
            response_headers['Content-Length'] = str(length)
            del response_headers['Content-Range']
        else:
            response_headers['Content-Range'] = 'bytes %s-%s/%s' % (start, end, length)
            response_headers['Content-Length'] = str(length-start)

        logging.info('>>>>>>>>>>>>>>> RangeFetch started(%r) %d-%d', self.url, start, end)
        self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response_status, ''.join('%s: %s\r\n' % (k, v) for k, v in response_headers.items()))))

        data_queue = Queue.PriorityQueue()
        range_queue = Queue.PriorityQueue()
        range_queue.put((start, end, self.response))
        for begin in range(end+1, length, self.maxsize):
            range_queue.put((begin, min(begin+self.maxsize-1, length-1), None))
        for i in xrange(0, self.threads):
            range_delay_size = i * self.maxsize
            spawn_later(float(range_delay_size)/self.waitsize, self.__fetchlet, range_queue, data_queue, range_delay_size)
        has_peek = hasattr(data_queue, 'peek')
        peek_timeout = 120
        self.expect_begin = start
        while self.expect_begin < length - 1:
            try:
                if has_peek:
                    begin, data = data_queue.peek(timeout=peek_timeout)
                    if self.expect_begin == begin:
                        data_queue.get()
                    elif self.expect_begin < begin:
                        time.sleep(0.1)
                        continue
                    else:
                        logging.error('RangeFetch Error: begin(%r) < expect_begin(%r), quit.', begin, self.expect_begin)
                        break
                else:
                    begin, data = data_queue.get(timeout=peek_timeout)
                    if self.expect_begin == begin:
                        pass
                    elif self.expect_begin < begin:
                        data_queue.put((begin, data))
                        time.sleep(0.1)
                        continue
                    else:
                        logging.error('RangeFetch Error: begin(%r) < expect_begin(%r), quit.', begin, self.expect_begin)
                        break
            except Queue.Empty:
                logging.error('data_queue peek timeout, break')
                break
            try:
                self.wfile.write(data)
                self.expect_begin += len(data)
                del data
            except Exception as e:
                logging.info('RangeFetch client connection aborted(%s).', e)
                break
        self._stopped = True

    def __fetchlet(self, range_queue, data_queue, range_delay_size):
        headers = dict((k.title(), v) for k, v in self.headers.items())
        headers['Connection'] = 'close'
        while 1:
            try:
                if self._stopped:
                    return
                try:
                    start, end, response = range_queue.get(timeout=1)
                    if self.expect_begin < start and data_queue.qsize() * self.bufsize + range_delay_size > 30*1024*1024:
                        range_queue.put((start, end, response))
                        time.sleep(10)
                        continue
                    headers['Range'] = 'bytes=%d-%d' % (start, end)
                    fetchserver = ''
                    if not response:
                        fetchserver = random.choice(self.fetchservers)
                        if self._last_app_status.get(fetchserver, 200) >= 500:
                            time.sleep(5)
                        response = self.urlfetch(self.command, self.url, headers, self.payload, fetchserver, password=self.password)
                except Queue.Empty:
                    continue
                except Exception as e:
                    logging.warning("Response %r in __fetchlet", e)
                    range_queue.put((start, end, None))
                    continue
                if not response:
                    logging.warning('RangeFetch %s return %r', headers['Range'], response)
                    range_queue.put((start, end, None))
                    continue
                if fetchserver:
                    self._last_app_status[fetchserver] = response.app_status
                if response.app_status != 200:
                    logging.warning('Range Fetch "%s %s" %s return %s', self.command, self.url, headers['Range'], response.app_status)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                if response.getheader('Location'):
                    self.url = urlparse.urljoin(self.url, response.getheader('Location'))
                    logging.info('RangeFetch Redirect(%r)', self.url)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                if 200 <= response.status < 300:
                    content_range = response.getheader('Content-Range')
                    if not content_range:
                        logging.warning('RangeFetch "%s %s" return Content-Range=%r: response headers=%r', self.command, self.url, content_range, response.getheaders())
                        response.close()
                        range_queue.put((start, end, None))
                        continue
                    content_length = int(response.getheader('Content-Length', 0))
                    logging.info('>>>>>>>>>>>>>>> [thread %s] %s %s', threading.currentThread().ident, content_length, content_range)
                    while 1:
                        try:
                            if self._stopped:
                                response.close()
                                return
                            data = response.read(self.bufsize)
                            if not data:
                                break
                            data_queue.put((start, data))
                            start += len(data)
                        except Exception as e:
                            logging.warning('RangeFetch "%s %s" %s failed: %s', self.command, self.url, headers['Range'], e)
                            break
                    if start < end + 1:
                        logging.warning('RangeFetch "%s %s" retry %s-%s', self.command, self.url, start, end)
                        response.close()
                        range_queue.put((start, end, None))
                        continue
                    logging.info('>>>>>>>>>>>>>>> Successfully reached %d bytes.', start - 1)
                else:
                    logging.error('RangeFetch %r return %s', self.url, response.status)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
            except Exception as e:
                logging.exception('RangeFetch._fetchlet error:%s', e)
                raise


class LocalProxyServer(SocketServer.ThreadingTCPServer):
    """Local Proxy Server"""
    allow_reuse_address = True

    def close_request(self, request):
        try:
            request.close()
        except Exception:
            pass

    def finish_request(self, request, client_address):
        try:
            self.RequestHandlerClass(request, client_address, self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def handle_error(self, *args):
        """make ThreadingTCPServer happy"""
        exc_info = sys.exc_info()
        error = exc_info and len(exc_info) and exc_info[1]
        if isinstance(error, NetWorkIOError) and len(error.args) > 1 and 'bad write retry' in error.args[1]:
            exc_info = error = None
        else:
            del exc_info, error
            SocketServer.ThreadingTCPServer.handle_error(self, *args)


def expand_google_hk_iplist(domains, max_count=100):
    iplist = sum([socket.gethostbyname_ex(x)[-1] for x in domains if not re.match(r'\d+\.\d+\.\d+\.\d+', x)], [])
    cranges = set(x.rpartition('.')[0] for x in iplist)
    need_expand = list(set(['%s.%d' % (c, i) for c in cranges for i in xrange(1, 254)]) - set(iplist))
    random.shuffle(need_expand)
    ip_connection_time = {}
    for ip in need_expand:
        if len(ip_connection_time) >= max_count:
            break
        sock = None
        ssl_sock = None
        try:
            start_time = time.time()
            request = urllib2.Request('https://%s/2' % ip, headers={'Host': 'goagent.appspot.com'})
            urllib2.build_opener(urllib2.ProxyHandler({})).open(request)
            ip_connection_time[(ip, 443)] = time.time() - start_time
        except socket.error as e:
            logging.debug('expand_google_hk_iplist(%s) error: %r', ip, e)
        except urllib2.HTTPError as e:
            if e.code == 404 and 'google' in e.headers.get('Server', '').lower():
                logging.debug('expand_google_hk_iplist(%s) OK', ip)
                ip_connection_time[(ip, 443)] = time.time() - start_time
            else:
                logging.debug('expand_google_hk_iplist(%s) error: %r', ip, e.code)
        except urllib2.URLError as e:
            logging.debug('expand_google_hk_iplist(%s) error: %r', ip, e)
        except Exception as e:
            logging.warn('expand_google_hk_iplist(%s) error: %r', ip, e)
        finally:
            if sock:
                sock.close()
            if ssl_sock:
                ssl_sock.close()
            time.sleep(2)
    http_util.tcp_connection_time.update(ip_connection_time)
    http_util.ssl_connection_time.update(ip_connection_time)
    common.IPLIST_MAP['google_hk'] += [x[0] for x in ip_connection_time]
    logging.info('expand_google_hk_iplist end. iplist=%s', ip_connection_time)


class GAEProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    bufsize = 256*1024
    first_run_lock = threading.Lock()
    urlfetch = staticmethod(gae_urlfetch)
    normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')
    normattachment = functools.partial(re.compile(r'filename=([^"\']+)').sub, 'filename="\\1"')

    def first_run(self):
        """GAEProxyHandler setup, init domain/iplist map"""
        if common.GAE_VALIDATE or common.GAE_OBFUSCATE:
            http_util.set_openssl_option(validate=common.GAE_VALIDATE, obfuscate=common.GAE_OBFUSCATE)
        if not common.PROXY_ENABLE:
            if 'google_hk' in common.IPLIST_MAP:
                # threading._start_new_thread(expand_google_hk_iplist, (common.IPLIST_MAP['google_hk'][:], 16))
                pass
            logging.info('resolve common.IPLIST_MAP names=%s to iplist', list(common.IPLIST_MAP))
            common.resolve_iplist()
        if len(common.GAE_APPIDS) > 10:
            random.shuffle(common.GAE_APPIDS)
        for appid in common.GAE_APPIDS:
            host = '%s.appspot.com' % appid
            if host not in common.HOSTS_MAP:
                common.HOSTS_MAP[host] = common.HOSTS_POSTFIX_MAP['.appspot.com']
            if host not in http_util.dns:
                http_util.dns[host] = common.IPLIST_MAP[common.HOSTS_MAP[host]]

    def setup(self):
        if isinstance(self.__class__.first_run, collections.Callable):
            try:
                with self.__class__.first_run_lock:
                    if isinstance(self.__class__.first_run, collections.Callable):
                        self.first_run()
                        self.__class__.first_run = None
            except Exception as e:
                logging.exception('GAEProxyHandler.first_run() return %r', e)
        self.__class__.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        self.__class__.do_GET = self.__class__.do_METHOD
        self.__class__.do_PUT = self.__class__.do_METHOD
        self.__class__.do_POST = self.__class__.do_METHOD
        self.__class__.do_HEAD = self.__class__.do_METHOD
        self.__class__.do_DELETE = self.__class__.do_METHOD
        self.__class__.do_OPTIONS = self.__class__.do_METHOD
        self.setup()

    def finish(self):
        """make python2 BaseHTTPRequestHandler happy"""
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

    def do_METHOD(self):
        if HAS_PYPY:
            self.path = re.sub(r'(://[^/]+):\d+/', '\\1/', self.path)
        host = self.headers.get('Host', '')
        if self.path[0] == '/' and host:
            self.path = 'http://%s%s' % (host, self.path)
        elif not host and '://' in self.path:
            host = urlparse.urlparse(self.path).netloc
        self.url_parts = urlparse.urlparse(self.path)
        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING
        if host.endswith(common.HTTP_WITHGAE):
            return self.do_METHOD_AGENT()
        if host in common.HTTP_FORCEHTTPS and not self.headers.get('Referer', '').startswith('https://') and not self.path.startswith('https://'):
            return self.wfile.write(('HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % self.path.replace('http://', 'https://', 1)).encode())
        if self.command not in ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH'):
            return self.do_METHOD_FWD()
        if any(x(self.path) for x in common.METHOD_REMATCH_MAP) or host in common.HOSTS_MAP or host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
            return self.do_METHOD_FWD()
        else:
            return self.do_METHOD_AGENT()

    def do_METHOD_FWD(self):
        """Direct http forward"""
        response = None
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            payload = self.rfile.read(content_length) if content_length else b''
            host = self.url_parts.netloc
            if any(x(self.path) for x in common.METHOD_REMATCH_MAP):
                hostname = next(common.METHOD_REMATCH_MAP[x] for x in common.METHOD_REMATCH_MAP if x(self.path))
            elif host in common.HOSTS_MAP:
                hostname = common.HOSTS_MAP[host]
            elif host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
                hostname = next(common.HOSTS_POSTFIX_MAP[x] for x in common.HOSTS_POSTFIX_MAP if host.endswith(x))
                common.HOSTS_MAP[host] = hostname
            else:
                hostname = host
            if common.METHOD_REMATCH_HAS_LOCALFILE and hostname.startswith('file://'):
                filename = hostname.lstrip('file://')
                if os.name == 'nt':
                    filename = filename.lstrip('/')
                content_type = None
                try:
                    import mimetypes
                    content_type = mimetypes.types_map.get(os.path.splitext(filename)[1])
                except Exception as e:
                    logging.error('import mimetypes failed: %r', e)
                try:
                    with open(filename, 'rb') as fp:
                        data = fp.read()
                        self.wfile.write('HTTP/1.1 200\r\n')
                        self.wfile.write('Connection: close\r\n')
                        self.wfile.write('Content-Length: %s\r\n' % len(data))
                        if content_type:
                            self.wfile.write('Content-Type: %s\r\n' % content_type)
                        self.wfile.write('\r\n')
                        self.wfile.write(data)
                except Exception as e:
                    self.wfile.write('HTTP/1.1 403\r\n')
                    self.wfile.write('Connection: close\r\n')
                    self.wfile.write('\r\n')
                    self.wfile.write('open %r failed: %r' % (filename, e))
                finally:
                    logging.info('%r matched local file %r, return', self.path, filename)
                    return
            need_crlf = hostname.startswith('google_') or host.endswith(common.HTTP_CRLFSITES)
            hostname = hostname or host
            if hostname in common.IPLIST_MAP:
                http_util.dns[host] = common.IPLIST_MAP[hostname]
            else:
                http_util.dns[host] = sum((http_util.dns_resolve(x) for x in hostname.split('|')), [])
            validate = common.GAE_VALIDATE if host not in common.HTTP_FAKEHTTPS else None
            connection_cache_key = hostname if host not in common.HTTP_FAKEHTTPS else None
            response = http_util.request(self.command, self.path, payload, self.headers, crlf=need_crlf, validate=validate, connection_cache_key=connection_cache_key)
            if not response:
                return
            logging.info('%s "FWD %s %s HTTP/1.1" %s %s', self.address_string(), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
            self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
            while True:
                data = response.read(8192)
                if not data:
                    break
                self.wfile.write(data)
                del data
            response.close()
        except NetWorkIOError as e:
            if response:
                response.close()
            if e.args[0] in (errno.ECONNRESET, 10063, errno.ENAMETOOLONG):
                logging.warn('http_util.request "%s %s" failed:%s, try addto `withgae`', self.command, self.path, e)
                common.HTTP_WITHGAE.add(re.sub(r':\d+$', '', self.url_parts.netloc))
            elif e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
                raise
        except Exception as e:
            host = self.headers.get('Host', '')
            logging.warn('GAEProxyHandler direct(%s) Error', host)
            raise

    def do_METHOD_AGENT(self):
        """GAE http urlfetch"""
        request_headers = dict((k.title(), v) for k, v in self.headers.items())
        host = request_headers.get('Host', '')
        path = self.url_parts.path
        need_autorange = any(x(host) for x in common.AUTORANGE_HOSTS_MATCH) or path.endswith(common.AUTORANGE_ENDSWITH)
        if path.endswith(common.AUTORANGE_NOENDSWITH) or 'range=' in self.url_parts.query or self.command == 'HEAD':
            need_autorange = False
        if self.command != 'HEAD' and 'Range' in request_headers:
            m = re.search(r'bytes=(\d+)-', request_headers['Range'])
            start = int(m.group(1) if m else 0)
            request_headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            logging.info('autorange range=%r match url=%r', request_headers['Range'], self.path)
        elif need_autorange:
            logging.info('Found [autorange]endswith match url=%r', self.path)
            m = re.search(r'bytes=(\d+)-', request_headers.get('Range', ''))
            start = int(m.group(1) if m else 0)
            request_headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)

        payload = b''
        if 'Content-Length' in request_headers:
            try:
                payload = self.rfile.read(int(request_headers.get('Content-Length', 0)))
            except NetWorkIOError as e:
                logging.error('handle_method_urlfetch read payload failed:%s', e)
                return
        response = None
        errors = []
        headers_sent = False
        get_fetchserver = lambda i: '%s://%s.appspot.com%s?' % (common.GAE_MODE, common.GAE_APPIDS[i] if i is not None else random.choice(common.GAE_APPIDS), common.GAE_PATH)
        for retry in range(common.FETCHMAX_LOCAL):
            fetchserver = get_fetchserver(0 if not need_autorange else None)
            try:
                content_length = 0
                kwargs = {}
                if common.GAE_PASSWORD:
                    kwargs['password'] = common.GAE_PASSWORD
                if common.GAE_VALIDATE:
                    kwargs['validate'] = 1
                response = self.urlfetch(self.command, self.path, request_headers, payload, fetchserver, **kwargs)
                if not response and retry == common.FETCHMAX_LOCAL-1:
                    html = message_html('502 URLFetch failed', 'Local URLFetch %r failed' % self.path, str(errors))
                    self.wfile.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n' + html.encode('utf-8'))
                    return
                # gateway error, switch to https mode
                if response.app_status in (400, 504):
                    common.GAE_MODE = 'https'
                    continue
                # appid not exists, try remove it from appid
                if response.app_status == 404:
                    if len(common.GAE_APPIDS) > 1:
                        appid = common.GAE_APPIDS.pop(0)
                        logging.warning('APPID %r not exists, remove it.', appid)
                        continue
                    else:
                        appid = common.GAE_APPIDS[0]
                        logging.error('APPID %r not exists, please ensure your appid in proxy.ini.', appid)
                        html = message_html('404 Appid Not Exists', 'Appid %r Not Exists' % appid, 'appid %r not exist, please edit your proxy.ini' % appid)
                        self.wfile.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n' + html.encode('utf-8'))
                        return
                # appid over qouta, switch to next appid
                if response.app_status == 503:
                    if len(common.GAE_APPIDS) > 1:
                        common.GAE_APPIDS.pop(0)
                        logging.info('Current APPID Over Quota,Auto Switch to [%s], Retrying…' % (common.GAE_APPIDS[0]))
                        self.do_METHOD_AGENT()
                        return
                    else:
                        logging.error('All APPID Over Quota')
                if response.app_status == 500 and need_autorange:
                    fetchserver = get_fetchserver(None)
                    logging.warning('500 with range in query, trying another fetchserver=%r', fetchserver)
                    continue
                if response.app_status != 200 and retry == common.FETCHMAX_LOCAL-1:
                    logging.info('%s "GAE %s %s HTTP/1.1" %s -', self.address_string(), self.command, self.path, response.status)
                    self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
                    self.wfile.write(response.read())
                    response.close()
                    return
                # first response, has no retry.
                if not headers_sent:
                    logging.info('%s "GAE %s %s HTTP/1.1" %s %s', self.address_string(), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
                    if response.status == 206:
                        fetchservers = [get_fetchserver(i) for i in xrange(len(common.GAE_APPIDS))]
                        rangefetch = RangeFetch(gae_urlfetch, self.wfile, response, self.command, self.path, self.headers, payload, fetchservers, common.GAE_PASSWORD, maxsize=common.AUTORANGE_MAXSIZE, bufsize=common.AUTORANGE_BUFSIZE, waitsize=common.AUTORANGE_WAITSIZE, threads=common.AUTORANGE_THREADS)
                        return rangefetch.fetch()
                    if response.getheader('Set-Cookie'):
                        response.msg['Set-Cookie'] = self.normcookie(response.getheader('Set-Cookie'))
                    if response.getheader('Content-Disposition') and '"' not in response.getheader('Content-Disposition'):
                        response.msg['Content-Disposition'] = self.normattachment(response.getheader('Content-Disposition'))
                    headers_data = 'HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))
                    logging.debug('headers_data=%s', headers_data)
                    #self.wfile.write(headers_data.encode() if bytes is not str else headers_data)
                    self.wfile.write(headers_data)
                    headers_sent = True
                content_length = int(response.getheader('Content-Length', 0))
                content_range = response.getheader('Content-Range', '')
                accept_ranges = response.getheader('Accept-Ranges', 'none')
                if content_range:
                    start, end, length = tuple(int(x) for x in re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
                else:
                    start, end, length = 0, content_length-1, content_length
                while True:
                    data = response.read(8192)
                    if not data:
                        response.close()
                        return
                    start += len(data)
                    self.wfile.write(data)
                    del data
                    if start >= end:
                        response.close()
                        return
            except Exception as e:
                errors.append(e)
                if response:
                    response.close()
                if e.args[0] in (0, errno.ECONNABORTED, errno.EPIPE):
                    logging.debug('GAEProxyHandler.do_METHOD_AGENT return %r', e)
                elif e.args[0] in (errno.ECONNRESET, errno.ETIMEDOUT, errno.ENETUNREACH, 11004):
                    # connection reset or timeout, switch to https
                    common.GAE_MODE = 'https'
                elif e.args[0] == errno.ETIMEDOUT or isinstance(e.args[0], str) and 'timed out' in e.args[0]:
                    if content_length and accept_ranges == 'bytes':
                        # we can retry range fetch here
                        logging.warn('GAEProxyHandler.do_METHOD_AGENT timed out, url=%r, content_length=%r, try again', self.path, content_length)
                        self.headers['Range'] = 'bytes=%d-%d' % (start, end)
                elif isinstance(e, NetWorkIOError) and 'bad write retry' in e.args[-1]:
                    logging.info('GAEProxyHandler.do_METHOD_AGENT url=%r return %r, abort.', self.path, e)
                    return
                else:
                    logging.exception('GAEProxyHandler.do_METHOD_AGENT %r return %r, try again', self.path, e)

    def do_CONNECT(self):
        """handle CONNECT cmmand, socket forward or deploy a fake cert"""
        host, _, port = self.path.rpartition(':')
        if host in common.HTTP_FAKEHTTPS or host.endswith(common.HTTP_WITHGAE):
            return self.do_CONNECT_AGENT()
        elif self.path in common.CONNECT_HOSTS_MAP or self.path.endswith(common.CONNECT_POSTFIX_ENDSWITH):
            return self.do_CONNECT_FWD()
        elif host in common.HOSTS_MAP or host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
            return self.do_CONNECT_FWD()
        else:
            return self.do_CONNECT_AGENT()

    def do_CONNECT_FWD(self):
        """socket forward for http CONNECT command"""
        host, _, port = self.path.rpartition(':')
        # GAEProxy Patch
        domain = DNSCacheUtil.getHost(host)
        if domain:
            host = domain
        port = int(port)
        logging.info('%s "FWD %s %s:%d HTTP/1.1" - -', self.address_string(), self.command, host, port)
        #http_headers = ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.items())
        if not common.PROXY_ENABLE:
            self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
            data = self.connection.recv(1024)
            for i in range(5):
                try:
                    if self.path in common.CONNECT_HOSTS_MAP:
                        hostname = common.CONNECT_HOSTS_MAP[self.path]
                    elif self.path.endswith(common.CONNECT_POSTFIX_ENDSWITH):
                        hostname = next(common.CONNECT_POSTFIX_MAP[x] for x in common.CONNECT_POSTFIX_MAP if self.path.endswith(x))
                        common.CONNECT_HOSTS_MAP[self.path] = hostname
                    elif host in common.HOSTS_MAP:
                        hostname = common.HOSTS_MAP[host]
                    elif host.endswith(common.HOSTS_POSTFIX_ENDSWITH):
                        hostname = next(common.HOSTS_POSTFIX_MAP[x] for x in common.HOSTS_POSTFIX_MAP if host.endswith(x))
                        common.HOSTS_MAP[host] = hostname
                    else:
                        hostname = host
                    hostname = hostname or host
                    if hostname in common.IPLIST_MAP:
                        http_util.dns[host] = common.IPLIST_MAP[hostname]
                    else:
                        http_util.dns[host] = sum((http_util.dns_resolve(x) for x in hostname.split('|')), [])
                    #connection_cache_key = '%s:%d' % (hostname or host, port)
                    connection_cache_key = None
                    timeout = 4
                    remote = http_util.create_connection((host, port), timeout, cache_key=connection_cache_key)
                    if remote is not None and data:
                        remote.sendall(data)
                        break
                    elif i == 0:
                        # only logging first create_connection error
                        logging.error('http_util.create_connection((host=%r, port=%r), %r) timeout', host, port, timeout)
                except NetWorkIOError as e:
                    if e.args[0] == 9:
                        logging.error('GAEProxyHandler direct forward remote (%r, %r) failed', host, port)
                        continue
                    else:
                        raise
            if hasattr(remote, 'fileno'):
                # reset timeout default to avoid long http upload failure, but it will delay timeout retry :(
                remote.settimeout(None)
                http_util.forward_socket(self.connection, remote, bufsize=self.bufsize)
        else:
            hostip = random.choice(http_util.dns_resolve(host))
            remote = http_util.create_connection((hostip, int(port)), timeout=4)
            if not remote:
                logging.error('GAEProxyHandler proxy connect remote (%r, %r) failed', host, port)
                return
            self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
            http_util.forward_socket(self.connection, remote, bufsize=self.bufsize)

    def do_CONNECT_AGENT(self):
        """deploy fake cert to client"""
        host, _, port = self.path.rpartition(':')
        # GAEProxy Patch
        domain = DNSCacheUtil.getHost(host)
        if domain:
            host = domain
        port = int(port)
        certfile = CertUtil.get_cert(host)
        logging.info('%s "AGENT %s %s:%d HTTP/1.1" - -', self.address_string(), self.command, host, port)
        self.__realconnection = None
        self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
        try:
            ssl_sock = ssl.wrap_socket(self.connection, keyfile=certfile, certfile=certfile, server_side=True)
            # if not http_util.ssl_validate and not http_util.ssl_obfuscate:
            #     ssl_sock = ssl.wrap_socket(self.connection, keyfile=certfile, certfile=certfile, server_side=True)
            # else:
            #     ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            #     ssl_context.use_privatekey_file(certfile)
            #     ssl_context.use_certificate_file(certfile)
            #     ssl_sock = SSLConnection(ssl_context, self.connection)
            #     ssl_sock.set_accept_state()
            #     ssl_sock.do_handshake()
        except Exception as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
                logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
            return
        self.__realconnection = self.connection
        self.__realwfile = self.wfile
        self.__realrfile = self.rfile
        self.connection = ssl_sock
        self.rfile = self.connection.makefile('rb', self.bufsize)
        self.wfile = self.connection.makefile('wb', 0)
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                return
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise
        if self.path[0] == '/' and host:
            self.path = 'https://%s%s' % (self.headers['Host'], self.path)
        try:
            self.do_METHOD()
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ETIMEDOUT, errno.EPIPE):
                raise
        finally:
            if self.__realconnection:
                try:
                    self.__realconnection.shutdown(socket.SHUT_WR)
                    self.__realconnection.close()
                except NetWorkIOError:
                    pass
                finally:
                    self.__realconnection = None


def php_urlfetch(method, url, headers, payload, fetchserver, **kwargs):
    if payload:
        if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers['Content-Encoding'] = 'deflate'
        headers['Content-Length'] = str(len(payload))
    skip_headers = http_util.skip_headers
    if common.PHP_VALIDATE:
        kwargs['validate'] = 1
    metadata = 'G-Method:%s\nG-Url:%s\n%s%s' % (method, url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v), ''.join('%s:%s\n' % (k, v) for k, v in headers.items() if k not in skip_headers))
    metadata = zlib.compress(metadata)[2:-4]
    app_payload = b''.join((struct.pack('!h', len(metadata)), metadata, payload))
    app_headers = {'Content-Length': len(app_payload), 'Content-Type': 'application/octet-stream'}
    fetchserver += '?%s' % random.random()
    crlf = 0 if fetchserver.startswith('https') else common.PHP_CRLF
    connection_cache_key = '%s//:%s' % urlparse.urlparse(fetchserver)[:2]
    response = http_util.request('POST', fetchserver, app_payload, app_headers, crlf=crlf, connection_cache_key=connection_cache_key)
    if not response:
        raise socket.error(errno.ECONNRESET, 'urlfetch %r return None' % url)
    response.app_status = response.status
    if response.status != 200:
        if response.status in (400, 405):
            # filter by some firewall
            common.PHP_CRLF = 0
        return response
    return response


class PHPProxyHandler(GAEProxyHandler):

    urlfetch = staticmethod(php_urlfetch)
    first_run_lock = threading.Lock()

    def first_run(self):
        if not common.PROXY_ENABLE:
            common.resolve_iplist()
            fetchhost = re.sub(r':\d+$', '', urlparse.urlparse(common.PHP_FETCHSERVER).netloc)
            logging.info('resolve common.PHP_FETCHSERVER domain=%r to iplist', fetchhost)
            if common.PHP_USEHOSTS and fetchhost in common.HOSTS_MAP:
                hostname = common.HOSTS_MAP[fetchhost]
                fetchhost_iplist = sum([socket.gethostbyname_ex(x)[-1] for x in common.IPLIST_MAP.get(hostname) or hostname.split('|')], [])
            else:
                fetchhost_iplist = http_util.dns_resolve(fetchhost)
            if len(fetchhost_iplist) == 0:
                logging.error('resolve %r domain return empty! please use ip list to replace domain list!', fetchhost)
                sys.exit(-1)
            http_util.dns[fetchhost] = list(set(fetchhost_iplist))
            logging.info('resolve common.PHP_FETCHSERVER domain to iplist=%r', fetchhost_iplist)
        return True

    def setup(self):
        if isinstance(self.__class__.first_run, collections.Callable):
            try:
                with self.__class__.first_run_lock:
                    if isinstance(self.__class__.first_run, collections.Callable):
                        self.first_run()
                        self.__class__.first_run = None
            except NetWorkIOError as e:
                logging.error('PHPProxyHandler.first_run() return %r', e)
            except Exception as e:
                logging.exception('PHPProxyHandler.first_run() return %r', e)
        self.__class__.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        if common.PHP_USEHOSTS:
            self.__class__.do_GET = self.__class__.do_METHOD
            self.__class__.do_PUT = self.__class__.do_METHOD
            self.__class__.do_POST = self.__class__.do_METHOD
            self.__class__.do_HEAD = self.__class__.do_METHOD
            self.__class__.do_DELETE = self.__class__.do_METHOD
            self.__class__.do_OPTIONS = self.__class__.do_METHOD
            self.__class__.do_CONNECT = GAEProxyHandler.do_CONNECT
        else:
            self.__class__.do_GET = self.__class__.do_METHOD_AGENT
            self.__class__.do_PUT = self.__class__.do_METHOD_AGENT
            self.__class__.do_POST = self.__class__.do_METHOD_AGENT
            self.__class__.do_HEAD = self.__class__.do_METHOD_AGENT
            self.__class__.do_DELETE = self.__class__.do_METHOD_AGENT
            self.__class__.do_OPTIONS = self.__class__.do_METHOD_AGENT
            self.__class__.do_CONNECT = GAEProxyHandler.do_CONNECT_AGENT
        self.setup()

    def do_METHOD_AGENT(self):
        response = None
        try:
            headers = dict((k.title(), v) for k, v in self.headers.items())
            payload = b''
            if 'Content-Length' in headers:
                try:
                    payload = self.rfile.read(int(headers.get('Content-Length', 0)))
                except NetWorkIOError as e:
                    logging.error('handle_method read payload failed:%s', e)
                    return
            errors = []
            for _ in range(common.FETCHMAX_LOCAL):
                try:
                    kwargs = {}
                    if common.PHP_PASSWORD:
                        kwargs['password'] = common.PHP_PASSWORD
                    if common.PHP_VALIDATE:
                        kwargs['validate'] = 1
                    response = self.urlfetch(self.command, self.path, headers, payload, common.PHP_FETCHSERVER, **kwargs)
                    if response:
                        break
                except Exception as e:
                    errors.append(e)

            if response is None:
                html = message_html('502 php URLFetch failed', 'Local php URLFetch %r failed' % self.path, str(errors))
                self.wfile.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n' + html.encode('utf-8'))
                return

            logging.info('%s "PHP %s %s HTTP/1.1" %s -', self.address_string(), self.command, self.path, response.status)
            if response.status != 200:
                self.wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k, v) for k, v in response.getheaders())))

            cipher = response.status == 200 and response.getheader('Content-Type', '') == 'image/gif' and XORCipher(common.PHP_PASSWORD[0])
            while True:
                data = response.read(8192)
                if not data:
                    response.close()
                    break
                if cipher:
                    data = cipher.encrypt(data)
                self.wfile.write(data)
                del data
        except NetWorkIOError as e:
            # Connection closed before proxy return
            if response:
                response.close()
            if e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
                raise


def get_uptime():
    if os.name == 'nt':
        import ctypes
        try:
            tick = ctypes.windll.kernel32.GetTickCount64()
        except AttributeError:
            tick = ctypes.windll.kernel32.GetTickCount()
        return tick / 1000.0
    elif os.path.isfile('/proc/uptime'):
        with open('/proc/uptime', 'rb') as fp:
            uptime = fp.readline().strip().split()[0].strip()
            return float(uptime)
    elif any(os.path.isfile(os.path.join(x, 'uptime')) for x in os.environ['PATH'].split(os.pathsep)):
        # http://www.opensource.apple.com/source/lldb/lldb-69/test/pexpect-2.4/examples/uptime.py
        pattern = r'up\s+(.*?),\s+([0-9]+) users?,\s+load averages?: ([0-9]+\.[0-9][0-9]),?\s+([0-9]+\.[0-9][0-9]),?\s+([0-9]+\.[0-9][0-9])'
        output = os.popen('uptime').read()
        duration, _, _, _, _ = re.search(pattern, output).groups()
        days, hours, mins = 0, 0, 0
        if 'day' in duration:
            m = re.search(r'([0-9]+)\s+day', duration)
            days = int(m.group(1))
        if ':' in duration:
            m = re.search(r'([0-9]+):([0-9]+)', duration)
            hours = int(m.group(1))
            mins = int(m.group(2))
        if 'min' in duration:
            m = re.search(r'([0-9]+)\s+min', duration)
            mins = int(m.group(1))
        return days * 86400 + hours * 3600 + mins * 60
    else:
        #TODO: support other platforms
        return None

# GAEProxy Patch
# No PAC

def get_process_list():
    import os
    import glob
    import ctypes
    import collections
    Process = collections.namedtuple('Process', 'pid name exe')
    process_list = []
    if os.name == 'nt':
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        lpidProcess= (ctypes.c_ulong * 1024)()
        cb = ctypes.sizeof(lpidProcess)
        cbNeeded = ctypes.c_ulong()
        ctypes.windll.psapi.EnumProcesses(ctypes.byref(lpidProcess), cb, ctypes.byref(cbNeeded))
        nReturned = cbNeeded.value/ctypes.sizeof(ctypes.c_ulong())
        pidProcess = [i for i in lpidProcess][:nReturned]
        has_queryimage = hasattr(ctypes.windll.kernel32, 'QueryFullProcessImageNameA')
        for pid in pidProcess:
            hProcess = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
            if hProcess:
                modname = ctypes.create_string_buffer(2048)
                count = ctypes.c_ulong(ctypes.sizeof(modname))
                if has_queryimage:
                    ctypes.windll.kernel32.QueryFullProcessImageNameA(hProcess, 0, ctypes.byref(modname), ctypes.byref(count))
                else:
                    ctypes.windll.psapi.GetModuleFileNameExA(hProcess, 0, ctypes.byref(modname), ctypes.byref(count))
                exe = modname.value
                name = os.path.basename(exe)
                process_list.append(Process(pid=pid, name=name, exe=exe))
                ctypes.windll.kernel32.CloseHandle(hProcess)
    elif sys.platform.startswith('linux'):
        for filename in glob.glob('/proc/[0-9]*/cmdline'):
            pid = int(filename.split('/')[2])
            exe_link = '/proc/%d/exe' % pid
            if os.path.exists(exe_link):
                exe = os.readlink(exe_link)
                name = os.path.basename(exe)
                process_list.append(Process(pid=pid, name=name, exe=exe))
    else:
        try:
            import psutil
            process_list = psutil.get_process_list()
        except Exception as e:
            logging.exception('psutil.get_process_list() failed: %r', e)
    return process_list

def pre_start():
    # GAEProxy Patch
    if common.GAE_APPIDS[0] == 'goagent':
        logging.critical('please edit %s to add your appid to [gae] !', common.CONFIG_FILENAME)
        sys.exit(-1)
    if common.GAE_MODE == 'http' and common.GAE_PASSWORD == '':
        logging.critical('to enable http mode, you should set %r [gae]password = <your_pass> and [gae]options = rc4', common.CONFIG_FILENAME)
        sys.exit(-1)

    # GAEProxy Patch
    # No PAC
    # No dnslib

    if os.name == 'nt' and not common.DNS_ENABLE:
        any(common.DNS_SERVERS.insert(0, x) for x in [y for y in get_dnsserver_list() if y not in common.DNS_SERVERS])
    if not OpenSSL:
        logging.warning('python-openssl not found, please install it!')
    if 'uvent.loop' in sys.modules and isinstance(gevent.get_hub().loop, __import__('uvent').loop.UVLoop):
        logging.info('Uvent enabled, patch forward_socket')
        http_util.forward_socket = http_util.green_forward_socket


def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    logging.basicConfig(level=logging.DEBUG if common.LISTEN_DEBUGINFO else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    pre_start()
    CertUtil.check_ca()
    sys.stdout.write(common.info())

    # GAEProxy Patch
    # Do the UNIX double-fork magic.
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

    # GAEProxy Patch
    # No dnslib

    # GAEProxy Patch
    if common.PHP_ENABLE:
        host, port = common.PHP_LISTEN.split(':')
        server = LocalProxyServer((host, int(port)), PHPProxyHandler)
        server.serve_forever()
    else:
        server = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GAEProxyHandler)
        server.serve_forever()

if __name__ == '__main__':
    main()
