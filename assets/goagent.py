#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

from __future__ import with_statement

__version__ = '1.8.11'
__author__  = "{phus.lu,hewigovens}@gmail.com (Phus Lu and Hewig Xu)"
__config__  = 'proxy.ini'

try:
    import gevent, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except:
    pass

import sys
import os
import re
import time
import errno
import binascii
import itertools
import zlib
import struct
import random
import hashlib
import fnmatch
import base64
import urlparse
import thread
import threading
import socket
import ssl
import select
import httplib
import urllib2
import BaseHTTPServer
import SocketServer
import ConfigParser
import traceback
try:
    import logging
except ImportError:
    logging = None
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

class Common(object):
    """global config object"""

    def __init__(self):
        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()

        # GAEProxy Patch
        self.CONFIG.read('/data/data/org.gaeproxy/proxy.ini')

        self.LISTEN_IP            = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT          = self.CONFIG.getint('listen', 'port')
        self.LISTEN_VISIBLE       = self.CONFIG.getint('listen', 'visible')

        self.GAE_ENABLE           = self.CONFIG.getint('gae', 'enable')
        self.GAE_APPIDS           = self.CONFIG.get('gae', 'appid').replace('.appspot.com', '').split('|')
        self.GAE_PASSWORD         = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH             = self.CONFIG.get('gae', 'path')
        self.GAE_PROFILE          = self.CONFIG.get('gae', 'profile')
        self.GAE_MULCONN          = self.CONFIG.getint('gae', 'mulconn')
        self.GAE_DEBUGLEVEL       = self.CONFIG.getint('gae', 'debuglevel') if self.CONFIG.has_option('gae', 'debuglevel') else 0

        paas_section = 'paas' if self.CONFIG.has_section('paas') else 'php'
        self.PAAS_ENABLE           = self.CONFIG.getint(paas_section, 'enable')
        self.PAAS_LISTEN           = self.CONFIG.get(paas_section, 'listen')
        self.PAAS_PASSWORD         = self.CONFIG.get(paas_section, 'password') if self.CONFIG.has_option(paas_section, 'password') else ''
        self.PAAS_FETCHSERVER      = self.CONFIG.get(paas_section, 'fetchserver')

        if self.CONFIG.has_section('pac'):
            # XXX, cowork with GoAgentX
            self.PAC_ENABLE           = self.CONFIG.getint('pac','enable')
            self.PAC_IP               = self.CONFIG.get('pac','ip')
            self.PAC_PORT             = self.CONFIG.getint('pac','port')
            self.PAC_FILE             = self.CONFIG.get('pac','file').lstrip('/')
            self.PAC_UPDATE           = self.CONFIG.getint('pac', 'update')
            self.PAC_REMOTE           = self.CONFIG.get('pac', 'remote')
            self.PAC_TIMEOUT          = self.CONFIG.getint('pac', 'timeout')
            self.PAC_DIRECTS          = self.CONFIG.get('pac', 'direct').split('|') if self.CONFIG.get('pac', 'direct') else []
        else:
            self.PAC_ENABLE           = 0

        self.PROXY_ENABLE         = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_HOST           = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT           = self.CONFIG.getint('proxy', 'port')
        self.PROXY_USERNAME       = self.CONFIG.get('proxy', 'username')
        self.PROXY_PASSWROD       = self.CONFIG.get('proxy', 'password')

        self.GOOGLE_MODE          = self.CONFIG.get(self.GAE_PROFILE, 'mode')
        self.GOOGLE_HOSTS         = tuple(self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|'))
        self.GOOGLE_SITES         = tuple(self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|'))
        self.GOOGLE_FORCEHTTPS    = frozenset(self.CONFIG.get(self.GAE_PROFILE, 'forcehttps').split('|'))
        self.GOOGLE_WITHGAE       = frozenset(self.CONFIG.get(self.GAE_PROFILE, 'withgae').split('|'))

        self.FETCHMAX_LOCAL       = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER      = self.CONFIG.get('fetchmax', 'server')

        self.AUTORANGE_HOSTS      = tuple(self.CONFIG.get('autorange', 'hosts').split('|'))
        self.AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in self.AUTORANGE_HOSTS)
        self.AUTORANGE_MAXSIZE    = self.CONFIG.getint('autorange', 'maxsize')
        self.AUTORANGE_WAITSIZE   = self.CONFIG.getint('autorange', 'waitsize')
        self.AUTORANGE_BUFSIZE    = self.CONFIG.getint('autorange', 'bufsize')

        assert self.AUTORANGE_BUFSIZE <= self.AUTORANGE_WAITSIZE <= self.AUTORANGE_MAXSIZE

        if self.CONFIG.has_section('crlf'):
            # XXX, cowork with GoAgentX
            self.CRLF_ENABLE          = self.CONFIG.getint('crlf', 'enable')
            self.CRLF_DNS             = self.CONFIG.get('crlf', 'dns')
            self.CRLF_SITES           = tuple(self.CONFIG.get('crlf', 'sites').split('|'))
            self.CRLF_CNAME           = dict(x.split('=') for x in self.CONFIG.get('crlf', 'cname').split('|'))
        else:
            self.CRLF_ENABLE          = 0

        self.USERAGENT_ENABLE     = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING     = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE          = self.CONFIG.getint('love','enable')
        self.LOVE_TIMESTAMP       = self.CONFIG.get('love', 'timestamp')
        self.LOVE_TIP             = [re.sub(r'(?i)\\u([0-9a-f]{4})', lambda m:unichr(int(m.group(1),16)), x) for x in self.CONFIG.get('love','tip').split('|')]

        self.HOSTS                = dict((k, tuple(v.split('|')) if v else tuple()) for k, v in self.CONFIG.items('hosts'))

        self.build_gae_fetchserver()
        self.PAAS_FETCH_INFO       = dict(((listen.rpartition(':')[0], int(listen.rpartition(':')[-1])), (re.sub(r':\d+$', '', urlparse.urlparse(server).netloc), server)) for listen, server in zip(self.PAAS_LISTEN.split('|'), [re.sub(r'/index\.[^/]+$','/',x) for x in self.PAAS_FETCHSERVER.split('|')]))

    def build_gae_fetchserver(self):
        """rebuild gae fetch server config"""
        if self.PROXY_ENABLE:
            self.GOOGLE_MODE = 'https'
        self.GAE_FETCHHOST = '%s.appspot.com' % self.GAE_APPIDS[0]
        if not self.PROXY_ENABLE:
            # append '?' to url, it can avoid china telicom/unicom AD
            self.GAE_FETCHSERVER = '%s://%s%s?' % (self.GOOGLE_MODE, self.GAE_FETCHHOST, self.GAE_PATH)
        else:
            self.GAE_FETCHSERVER = '%s://%s%s?' % (self.GOOGLE_MODE, random.choice(self.GOOGLE_HOSTS), self.GAE_PATH)

    def install_opener(self):
        """install urllib2 opener"""
        httplib.HTTPMessage = SimpleMessageClass
        if self.PROXY_ENABLE:
            proxy = '%s:%s@%s:%d'%(self.PROXY_USERNAME, self.PROXY_PASSWROD, self.PROXY_HOST, self.PROXY_PORT)
            handlers = [urllib2.ProxyHandler({'http':proxy,'https':proxy})]
        else:
            handlers = [urllib2.ProxyHandler({})]
        opener = urllib2.build_opener(*handlers)
        opener.addheaders = []
        urllib2.install_opener(opener)

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version  : %s (python/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
        info += 'Listen Address   : %s:%d\n' % (self.LISTEN_IP,self.LISTEN_PORT)
        info += 'Local Proxy      : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug Level      : %s\n' % self.GAE_DEBUGLEVEL if self.GAE_DEBUGLEVEL else ''
        info += 'GAE Mode         : %s\n' % self.GOOGLE_MODE if self.GAE_ENABLE else ''
        info += 'GAE Profile      : %s\n' % self.GAE_PROFILE
        info += 'GAE APPID        : %s\n' % '|'.join(self.GAE_APPIDS)
        if common.PAAS_ENABLE:
            for (ip, port),(fetchhost, fetchserver) in common.PAAS_FETCH_INFO.iteritems():
                info += 'PAAS Listen      : %s:%d\n' % (ip, port)
                info += 'PAAS FetchServer : %s\n' % fetchserver
        if common.PAC_ENABLE:
            info += 'Pac Server       : http://%s:%d/%s\n' % (self.PAC_IP,self.PAC_PORT,self.PAC_FILE)
        if common.CRLF_ENABLE:
            #http://www.acunetix.com/websitesecurity/crlf-injection.htm
            info += 'CRLF Injection   : %s\n' % '|'.join(self.CRLF_SITES)
        info += '------------------------------------------------------\n'
        return info

common = Common()

class MultiplexConnection(object):
    """multiplex tcp connection class"""

    retry = 3
    timeout = 8
    timeout_min = 4
    timeout_max = 60
    timeout_ack = 0
    window = 8
    window_min = 4
    window_max = 60
    window_ack = 0

    def __init__(self, hosts, port):
        self.socket = None
        self._sockets = set([])
        self.connect(hosts, port, MultiplexConnection.timeout, MultiplexConnection.window)
    def connect(self, hostlist, port, timeout, window):
        for i in xrange(MultiplexConnection.retry):
            hosts = random.sample(hostlist, window) if len(hostlist) > window else hostlist
            logging.debug('MultiplexConnection try connect hosts=%s, port=%d', hosts, port)
            socks = []
            # multiple connect start here
            for host in hosts:
                sock = socket.socket(2 if ':' not in host else socket.AF_INET6)
                sock.setblocking(0)
                #logging.debug('MultiplexConnection connect_ex (%r, %r)', host, port)
                err = sock.connect_ex((host, port))
                self._sockets.add(sock)
                socks.append(sock)
            # something happens :D
            (_, outs, _) = select.select([], socks, [], timeout)
            if outs:
                self.socket = outs[0]
                self.socket.setblocking(1)
                self._sockets.remove(self.socket)
                if window > MultiplexConnection.window_min:
                    MultiplexConnection.window_ack += 1
                    if MultiplexConnection.window_ack > 10:
                        MultiplexConnection.window = window - 1
                        MultiplexConnection.window_ack = 0
                        logging.info('MultiplexConnection CONNECT port=%s OK 10 times, switch new window=%d', port, MultiplexConnection.window)
                if timeout > MultiplexConnection.timeout_min:
                    MultiplexConnection.timeout_ack += 1
                    if MultiplexConnection.timeout_ack > 10:
                        MultiplexConnection.timeout = timeout - 1
                        MultiplexConnection.timeout_ack = 0
                        logging.info('MultiplexConnection CONNECT port=%s OK 10 times, switch new timeout=%d', port, MultiplexConnection.timeout)
                break
            else:
                logging.debug('MultiplexConnection Cannot hosts %r:%r, window=%d', hosts, port, window)
        else:
            # OOOPS, cannot multiple connect
            MultiplexConnection.window = min(int(round(window*1.5)), self.window_max)
            MultiplexConnection.window_ack = 0
            MultiplexConnection.timeout = min(int(round(timeout*1.5)), self.timeout_max)
            MultiplexConnection.timeout_ack = 0
            logging.warning(r'MultiplexConnection Connect hosts %s:%s fail %d times!', hosts, port, MultiplexConnection.retry)
            raise socket.error('MultiplexConnection connect hosts=%s failed' % repr(hosts))
    def connect_single(self, hostlist, port, timeout, window):
        for host in hostlist:
            logging.debug('MultiplexConnection try connect host=%s, port=%d', host, port)
            sock = None
            try:
                sock_family = socket.AF_INET6 if ':' in host else socket.AF_INET
                sock = socket.socket(sock_family, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                self.socket = sock
            except socket.error:
                if sock is not None:
                    sock.close()
                raise
    def close(self):
        """close all sockets, otherwise CLOSE_WAIT"""
        for sock in self._sockets:
            try:
                sock.close()
            except:
                pass
        del self._sockets

def socket_create_connection((host, port), timeout=None, source_address=None):
    logging.debug('socket_create_connection connect (%r, %r)', host, port)
    if host == common.GAE_FETCHHOST:
        msg = 'socket_create_connection returns an empty list'
        try:
            conn = MultiplexConnection(common.GOOGLE_HOSTS, port)
            sock = conn.socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            return sock
        except socket.error:
            logging.error('socket_create_connection connect fail: (%r, %r)', common.GOOGLE_HOSTS, port)
            sock = None
        if not sock:
            raise socket.error, msg
    elif host in common.HOSTS:
        msg = 'socket_create_connection returns an empty list'
        try:
            iplist = common.HOSTS[host]
            if not iplist:
                iplist = tuple(x[-1][0] for x in socket.getaddrinfo(host, 80))
                common.HOSTS[host] = iplist
            conn = MultiplexConnection(iplist, port)
            sock = conn.socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            return sock
        except socket.error:
            logging.error('socket_create_connection connect fail: (%r, %r)', common.HOSTS[host], port)
            sock = None
        if not sock:
            raise socket.error, msg
    else:
        msg = 'getaddrinfo returns an empty list'
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                if isinstance(timeout, (int, float)):
                    sock.settimeout(timeout)
                if source_address is not None:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock
            except socket.error:
                if sock is not None:
                    sock.close()
        raise socket.error, msg
socket.create_connection = socket_create_connection

def socket_forward(local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, idlecall=None):
    timecount = timeout
    try:
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
                        if sock is local:
                            remote.sendall(data)
                            timecount = maxping or timeout
                        else:
                            local.sendall(data)
                            timecount = maxpong or timeout
                    else:
                        return
            else:
                if idlecall:
                    try:
                        idlecall()
                    except Exception:
                        logging.exception('socket_forward idlecall fail')
                    finally:
                        idlecall = None
    except Exception:
        logging.exception('socket_forward error')
        raise
    finally:
        if idlecall:
            idlecall()

def dns_resolve(host, dnsserver='8.8.8.8', dnscache=common.HOSTS, dnslock=threading.Lock()):
    index = os.urandom(2)
    hoststr = ''.join(chr(len(x))+x for x in host.split('.'))
    data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (index, hoststr)
    data = struct.pack('!H', len(data)) + data
    if host not in dnscache:
        with dnslock:
            if host not in dnscache:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET6 if ':' in dnsserver else socket.AF_INET)
                    sock.connect((dnsserver, 53))
                    sock.sendall(data)
                    rfile = sock.makefile('rb')
                    size = struct.unpack('!H', rfile.read(2))[0]
                    data = rfile.read(size)
                    iplist = re.findall('\xC0.\x00\x01\x00\x01.{6}(.{4})', data)
                    iplist = tuple('.'.join(str(ord(x)) for x in s) for s in iplist)
                    logging.info('dns_resolve(host=%r) return %s', host, iplist)
                    dnscache[host] = iplist
                except socket.error:
                    logging.exception('dns_resolve(host=%r) fail', host)
                finally:
                    if sock:
                        sock.close()
    return dnscache.get(host, tuple())

_httplib_HTTPConnection_putrequest = httplib.HTTPConnection.putrequest
def httplib_HTTPConnection_putrequest(self, method, url, skip_host=0, skip_accept_encoding=1):
    self._output('\r\n\r\n')
    return _httplib_HTTPConnection_putrequest(self, method, url, skip_host, skip_accept_encoding)
httplib.HTTPConnection.putrequest = httplib_HTTPConnection_putrequest

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
    '''CertUtil module, based on WallProxy 0.4.0'''

    CA = None
    CALock = threading.Lock()
    subj_alts = \
            'DNS: twitter.com, DNS: facebook.com, \
            DNS: *.twitter.com, DNS: *.twimg.com, \
            DNS: *.akamaihd.net, DNS: *.google.com, \
            DNS: *.facebook.com, DNS: *.ytimg.com, \
            DNS: *.appspot.com, DNS: *.google.com, \
            DNS: *.youtube.com, DNS: *.googleusercontent.com, \
            DNS: *.gstatic.com, DNS: *.live.com, \
            DNS: *.ak.fbcdn.net, DNS: *.ak.facebook.com, \
            DNS: *.android.com, DNS: *.fbcdn.net'

    @staticmethod
    def readFile(filename):
        content = None
        with open(filename, 'rb') as fp:
            content = fp.read()
        return content

    @staticmethod
    def writeFile(filename, content):
        with open(filename, 'wb') as fp:
            fp.write(str(content))

    @staticmethod
    def createKeyPair(type=None, bits=1024):
        if type is None:
            type = OpenSSL.crypto.TYPE_RSA
        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(type, bits)
        return pkey

    @staticmethod
    def createCertRequest(pkey, digest='sha1', **subj):
        req = OpenSSL.crypto.X509Req()
        subject = req.get_subject()
        for k,v in subj.iteritems():
            setattr(subject, k, v)
        req.set_pubkey(pkey)
        req.sign(pkey, digest)
        return req

    @staticmethod
    def createCertificate(req, (issuerKey, issuerCert), serial, (notBefore,
        notAfter), digest='sha1', host=None):
        cert = OpenSSL.crypto.X509()
        cert.set_version(3)
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        alts = CertUtil.subj_alts
        if host is not None:
            alts += ", DNS: %s" % host
        cert.add_extensions([OpenSSL.crypto.X509Extension("subjectAltName",
            True, alts)])
        cert.sign(issuerKey, digest)
        return cert

    @staticmethod
    def loadPEM(pem, type):
        handlers = ('load_privatekey', 'load_certificate_request', 'load_certificate')
        return getattr(OpenSSL.crypto, handlers[type])(OpenSSL.crypto.FILETYPE_PEM, pem)

    @staticmethod
    def dumpPEM(obj, type):
        handlers = ('dump_privatekey', 'dump_certificate_request', 'dump_certificate')
        return getattr(OpenSSL.crypto, handlers[type])(OpenSSL.crypto.FILETYPE_PEM, obj)

    @staticmethod
    def makeCA():
        pkey = CertUtil.createKeyPair(bits=2048)
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': 'GoAgent',
                'organizationalUnitName': 'GoAgent Root', 'commonName': 'GoAgent CA'}
        req = CertUtil.createCertRequest(pkey, **subj)
        cert = CertUtil.createCertificate(req, (pkey, req), 0, (0, 60*60*24*7305))  #20 years
        return (CertUtil.dumpPEM(pkey, 0), CertUtil.dumpPEM(cert, 2))

    @staticmethod
    def makeCert(host, (cakey, cacrt), serial):
        pkey = CertUtil.createKeyPair()
        subj = {'countryName': 'CN', 'stateOrProvinceName': 'Internet',
                'localityName': 'Cernet', 'organizationName': host,
                'organizationalUnitName': 'GoAgent Branch', 'commonName': host}
        req = CertUtil.createCertRequest(pkey, **subj)
        cert = CertUtil.createCertificate(req, (cakey, cacrt), serial, (0,
            60*60*24*7305), host=host)
        return (CertUtil.dumpPEM(pkey, 0), CertUtil.dumpPEM(cert, 2))

    # GAEProxy Patch
    @staticmethod
    def getCertificate(host):
        basedir = '/data/data/org.gaeproxy'
        keyFile = os.path.join(basedir, 'certs/%s.key' % host)
        crtFile = os.path.join(basedir, 'certs/%s.crt' % host)
        if os.path.exists(keyFile):
            return (keyFile, crtFile)
        if OpenSSL is None:
            keyFile = os.path.join(basedir, 'CA.key')
            crtFile = os.path.join(basedir, 'CA.crt')
            return (keyFile, crtFile)
        if not os.path.isfile(keyFile):
            with CertUtil.CALock:
                if not os.path.isfile(keyFile):
                    logging.info('CertUtil getCertificate for %r', host)
                    # FIXME: howto generate a suitable serial number?
                    for serial in (int(hashlib.md5(host).hexdigest(), 16), int(time.time()*100)):
                        try:
                            key, crt = CertUtil.makeCert(host, CertUtil.CA, serial)
                            CertUtil.writeFile(crtFile, crt)
                            CertUtil.writeFile(keyFile, key)
                            break
                        except Exception:
                            logging.exception('CertUtil.makeCert failed: host=%r, serial=%r', host, serial)
                    else:
                        keyFile = os.path.join(basedir, 'CA.key')
                        crtFile = os.path.join(basedir, 'CA.crt')
        return (keyFile, crtFile)

    @staticmethod
    def checkCA():
        #Check CA exists
        basedir = '/data/data/org.gaeproxy'
        keyFile = os.path.join(basedir, 'CA.key')
        crtFile = os.path.join(basedir, 'CA.crt')
        if not os.path.exists(keyFile):
            if not OpenSSL:
                logging.critical('CA.crt is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            key, crt = CertUtil.makeCA()
            CertUtil.writeFile(keyFile, key)
            CertUtil.writeFile(crtFile, crt)
            [os.remove(os.path.join('certs', x)) for x in os.listdir('certs')]
        if OpenSSL:
            keyFile = os.path.join(basedir, 'CA.key')
            crtFile = os.path.join(basedir, 'CA.crt')
            cakey = CertUtil.readFile(keyFile)
            cacrt = CertUtil.readFile(crtFile)
            CertUtil.CA = (CertUtil.loadPEM(cakey, 0), CertUtil.loadPEM(cacrt, 2))

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

class SimpleMessageClass(object):

    def __init__(self, fp, seekable = 0):
        self.dict = dict = {}
        self.headers = headers = []
        readline = getattr(fp, 'readline', None)
        headers_append = headers.append
        if readline:
            while 1:
                line = readline(8192)
                if not line or line == '\r\n':
                    break
                key, _, value = line.partition(':')
                if value:
                    headers_append(line)
                    dict[key.title()] = value.strip()
        else:
            for key, value in fp:
                key = key.title()
                dict[key] = value
                headers_append('%s: %s\r\n' % (key, value))

    def getheader(self, name, default=None):
        return self.dict.get(name.title(), default)

    def getheaders(self, name, default=None):
        return [self.getheader(name, default)]

    def addheader(self, key, value):
        self[key] = value

    def get(self, name, default=None):
        return self.dict.get(name.title(), default)

    def iteritems(self):
        return self.dict.iteritems()

    def iterkeys(self):
        return self.dict.iterkeys()

    def itervalues(self):
        return self.dict.itervalues()

    def keys(self):
        return self.dict.keys()

    def values(self):
        return self.dict.values()

    def items(self):
        return self.dict.items()

    def __getitem__(self, name):
        return self.dict[name.title()]

    def __setitem__(self, name, value):
        name = name.title()
        self.dict[name] = value
        headers = self.headers
        try:
            i = (i for i, line in enumerate(headers) if line.partition(':')[0].title() == name).next()
            headers[i] = '%s: %s\r\n' % (name, value)
        except StopIteration:
            headers.append('%s: %s\r\n' % (name, value))

    def __delitem__(self, name):
        name = name.title()
        del self.dict[name]
        headers = self.headers
        for i in reversed([i for i, line in enumerate(headers) if line.partition(':')[0].title() == name]):
            del headers[i]

    def __contains__(self, name):
        return name.title() in self.dict

    def __len__(self):
        return len(self.dict)

    def __iter__(self):
        return iter(self.dict)

    def __str__(self):
        return ''.join(self.headers)

def urlfetch(url, payload, method, headers, fetchhost, fetchserver, password=None, dns=None, on_error=None):
    errors = []
    params = {'url':url, 'method':method, 'headers':headers, 'payload':payload}
    logging.debug('urlfetch params %s', params)
    if password:
        params['password'] = password
    if common.FETCHMAX_SERVER:
        params['fetchmax'] = common.FETCHMAX_SERVER
    if dns:
        params['dns'] = dns
    params =  '&'.join('%s=%s' % (k, binascii.b2a_hex(v)) for k, v in params.iteritems())
    for i in xrange(common.FETCHMAX_LOCAL):
        try:
            logging.debug('urlfetch %r by %r', url, fetchserver)
            request = urllib2.Request(fetchserver, zlib.compress(params, 9))
            request.add_header('Content-Type', '')
            if common.PROXY_ENABLE:
                request.add_header('Host', fetchhost)
            response = urllib2.urlopen(request)
            compressed = response.read(1)

            data = {}
            if compressed == '0':
                data['code'], hlen, clen = struct.unpack('>3I', response.read(12))
                data['headers'] = SimpleMessageClass((k, binascii.a2b_hex(v)) for k, _, v in (x.partition('=') for x in response.read(hlen).split('&')))
                data['response'] = response
            elif compressed == '1':
                rawdata = zlib.decompress(response.read())
                data['code'], hlen, clen = struct.unpack('>3I', rawdata[:12])
                data['headers'] = SimpleMessageClass((k, binascii.a2b_hex(v)) for k, _, v in (x.partition('=') for x in rawdata[12:12+hlen].split('&')))
                data['content'] = rawdata[12+hlen:12+hlen+clen]
                response.close()
            else:
                raise ValueError('Data format not match(%s)' % url)

            return (0, data)
        except Exception as e:
            if on_error:
                logging.info('urlfetch error=%s on_error=%s', str(e), str(on_error))
                data = on_error(e)
                if data:
                    newfetch = (data.get('fetchhost'), data.get('fetchserver'))
                    if newfetch != (fetchhost, fetchserver):
                        (fetchhost, fetchserver) = newfetch
                        sys.stdout.write(common.info())
            errors.append(str(e))
            time.sleep(i+1)
            continue
    return (-1, errors)

class GAEProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    skip_headers = frozenset(['Host', 'Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'Keep-Alive'])
    SetupLock = threading.Lock()
    MessageClass = SimpleMessageClass
    DefaultHosts = 'eJxdztsNgDAMQ9GNIvIoSXZjeApSqc3nUVT3ZojakFTR47wSNEhB8qXhorXg+kMjckGtQM9efDKf\n91Km4W+N4M1CldNIYMu+qSVoTm7MsG5E4KPd8apInNUUMo4betRQjg=='

    def handle_fetch_error(self, error):
        logging.info('handle_fetch_error self.path=%r', self.path)
        if isinstance(error, urllib2.HTTPError):
            # http error 400/502/504, swith to https
            if error.code in (400, 504) or (error.code==502 and common.GAE_PROFILE=='google_cn'):
                common.GOOGLE_MODE = 'https'
                logging.error('GAE Error(%s) switch to https', error)
            # seems that current appid is overqouta, swith to next appid
            if error.code == 503:
                common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                logging.error('GAE Error(%s) switch to appid(%r)', error, common.GAE_APPIDS[0])
            # 405 method not allowed, disable CRLF
            if error.code == 405:
                httplib.HTTPConnection.putrequest = _httplib_HTTPConnection_putrequest
        elif isinstance(error, urllib2.URLError):
            if error.reason[0] in (11004, 10051, 10060, 'timed out', 10054):
                # it seems that google.cn is reseted, switch to https
                common.GOOGLE_MODE = 'https'
        elif isinstance(error, httplib.HTTPException):
            common.GOOGLE_MODE = 'https'
            httplib.HTTPConnection.putrequest = _httplib_HTTPConnection_putrequest
        else:
            logging.warning('GAEProxyHandler.handle_fetch_error Exception %s', error)
            return {}
        common.build_gae_fetchserver()
        return {'fetchhost':common.GAE_FETCHHOST, 'fetchserver':common.GAE_FETCHSERVER}

    def fetch(self, url, payload, method, headers):
        return urlfetch(url, payload, method, headers, common.GAE_FETCHHOST, common.GAE_FETCHSERVER, password=common.GAE_PASSWORD, on_error=self.handle_fetch_error)

    def rangefetch(self, m, data):
        m = map(int, m.groups())
        if 'range' in self.headers:
            content_range = 'bytes %d-%d/%d' % (m[0], m[1], m[2])
            req_range = re.search(r'(\d+)?-(\d+)?', self.headers['range'])
            if req_range:
                req_range = [u and int(u) for u in req_range.groups()]
                if req_range[0] is None:
                    if req_range[1] is not None:
                        if not (m[1]-m[0]+1==req_range[1] and m[1]+1==m[2]):
                            return False
                        if m[2] >= req_range[1]:
                            content_range = 'bytes %d-%d/%d' % (req_range[1], m[2]-1, m[2])
                else:
                    if req_range[1] is not None:
                        if not (m[0]==req_range[0] and m[1]==req_range[1]):
                            return False
                        if m[2] - 1 > req_range[1]:
                            content_range = 'bytes %d-%d/%d' % (req_range[0], req_range[1], m[2])
            data['headers']['Content-Range'] = content_range
            data['headers']['Content-Length'] = m[2]-m[0]
        elif m[0] == 0:
            data['code'] = 200
            data['headers']['Content-Length'] = m[2]
            del data['headers']['Content-Range']

        self.wfile.write('%s %d %s\r\n%s\r\n' % (self.protocol_version, data['code'], 'OK', data['headers']))
        if 'response' in data:
            response = data['response']
            bufsize = common.AUTORANGE_BUFSIZE
            if data['headers'].get('Content-Type', '').startswith('video/'):
                bufsize = common.AUTORANGE_WAITSIZE
            while 1:
                content = response.read(bufsize)
                if not content:
                    response.close()
                    break
                self.wfile.write(content)
                bufsize = common.AUTORANGE_BUFSIZE
        else:
            self.wfile.write(data['content'])

        start = m[1] + 1
        end   = m[2] - 1
        failed = 0
        logging.info('>>>>>>>>>>>>>>> Range Fetch started(%r)', self.headers.get('Host'))
        while start < end:
            if failed > 16:
                break
            self.headers['Range'] = 'bytes=%d-%d' % (start, min(start+common.AUTORANGE_MAXSIZE-1, end))
            retval, data = self.fetch(self.path, '', self.command, str(self.headers))
            if retval != 0 or data['code'] >= 400:
                failed += 1
                seconds = random.randint(2*failed, 2*(failed+1))
                logging.error('Range Fetch fail %d times, retry after %d secs!', failed, seconds)
                time.sleep(seconds)
                continue
            if 'Location' in data['headers']:
                logging.info('Range Fetch got a redirect location:%r', data['headers']['Location'])
                self.path = data['headers']['Location']
                failed += 1
                continue
            m = re.search(r'bytes\s+(\d+)-(\d+)/(\d+)', data['headers'].get('Content-Range',''))
            if not m:
                failed += 1
                logging.error('Range Fetch fail %d times, data[\'headers\']=%s', failed, data['headers'])
                continue
            start = int(m.group(2)) + 1
            logging.info('>>>>>>>>>>>>>>> %s %d' % (data['headers']['Content-Range'], end+1))
            failed = 0
            if 'response' in data:
                response = data['response']
                while 1:
                    content = response.read(common.AUTORANGE_BUFSIZE)
                    if not content:
                        response.close()
                        break
                    self.wfile.write(content)
            else:
                self.wfile.write(data['content'])
        logging.info('>>>>>>>>>>>>>>> Range Fetch ended(%r)', self.headers.get('Host'))
        return True

    def log_message(self, fmt, *args):
        host, port = self.client_address[:2]
        sys.stdout.write("%s:%d - - [%s] %s\n" % (host, port, time.ctime()[4:-5], fmt%args))

    def send_response(self, code, message=None):
        self.log_request(code)
        message = message or self.responses.get(code, ('GoAgent Notify',))[0]
        self.connection.sendall('%s %d %s\r\n' % (self.protocol_version, code, message))

    def end_error(self, code, message=None, data=None):
        if not data:
            self.send_error(code, message)
        else:
            self.send_response(code, message)
            self.connection.sendall(data)

    def setup(self):
        if not common.PROXY_ENABLE and common.GAE_PROFILE != 'google_ipv6':
            logging.info('resolve common.GOOGLE_HOSTS domian=%r to iplist', common.GOOGLE_HOSTS)
            if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                with GAEProxyHandler.SetupLock:
                    if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                        google_iplist = [host for host in common.GOOGLE_HOSTS if re.match(r'\d+\.\d+\.\d+\.\d+', host)]
                        google_hosts = [host for host in common.GOOGLE_HOSTS if not re.match(r'\d+\.\d+\.\d+\.\d+', host)]
                        try:
                            google_hosts_iplist = [[x[-1][0] for x in socket.getaddrinfo(host, 80)] for host in google_hosts]
                            need_remote_dns = google_hosts and any(len(iplist)==1 for iplist in google_hosts_iplist)
                        except socket.gaierror:
                            need_remote_dns = True
                        if need_remote_dns:
                            logging.warning('OOOPS, there are some mistake in socket.getaddrinfo, try remote dns_resolve')
                            google_hosts_iplist = [list(dns_resolve(host)) for host in google_hosts]
                        common.GOOGLE_HOSTS = tuple(set(sum(google_hosts_iplist, google_iplist)))
                        if len(common.GOOGLE_HOSTS) == 0:
                            logging.error('resolve common.GOOGLE_HOSTS domian to iplist return empty! use default iplist')
                            common.GOOGLE_HOSTS = zlib.decompress(base64.b64decode(self.DefaultHosts)).split('|')
                        common.GOOGLE_HOSTS = tuple(x for x in common.GOOGLE_HOSTS if ':' not in x)
                        logging.info('resolve common.GOOGLE_HOSTS domian to iplist=%r', common.GOOGLE_HOSTS)
        if not common.GAE_MULCONN:
            MultiplexConnection.connect = MultiplexConnection.connect_single
        if not common.GAE_ENABLE:
            GAEProxyHandler.do_CONNECT = GAEProxyHandler.do_CONNECT_Direct
            GAEProxyHandler.do_METHOD  = GAEProxyHandler.do_METHOD_Direct
        GAEProxyHandler.do_GET     = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_POST    = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_PUT     = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_DELETE  = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_OPTIONS = GAEProxyHandler.do_METHOD
        GAEProxyHandler.do_HEAD    = GAEProxyHandler.do_METHOD
        GAEProxyHandler.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(':')
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            common.HOSTS[host] = common.GOOGLE_HOSTS
            return self.do_CONNECT_Direct()
        elif host in common.HOSTS:
            return self.do_CONNECT_Direct()
        elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
            if host not in common.HOSTS:
                try:
                    cname = common.CRLF_CNAME[itertools.ifilter(host.endswith, common.CRLF_CNAME).next()]
                except StopIteration:
                    cname = host
                logging.info('crlf dns_resolve(host=%r, cname=%r dnsserver=%r)', host, cname, common.CRLF_DNS)
                iplist = tuple(set(sum((dns_resolve(x, common.CRLF_DNS) if not re.match(r'\d+\.\d+\.\d+\.\d+', host) else (host,) for x in cname.split(',')), ())))
                common.HOSTS[host] = iplist
            return self.do_CONNECT_Direct()
        else:
            return self.do_CONNECT_Tunnel()

    def do_CONNECT_Direct(self):
        try:
            logging.debug('GAEProxyHandler.do_CONNECT_Directt %s' % self.path)
            host, _, port = self.path.rpartition(':')
            port = int(port)
            idlecall = None
            if not common.PROXY_ENABLE:
                if host in common.HOSTS:
                    iplist = common.HOSTS[host]
                    if not iplist:
                        common.HOSTS[host] = iplist = tuple(x[-1][0] for x in socket.getaddrinfo(host, 80))
                    conn = MultiplexConnection(iplist, port)
                    sock = conn.socket
                    idlecall=conn.close
                else:
                    sock = socket.create_connection((host, port))
                self.log_request(200)
                self.connection.sendall('%s 200 Tunnel established\r\n\r\n' % self.protocol_version)
            else:
                sock = socket.create_connection((common.PROXY_HOST, common.PROXY_PORT))
                if host in common.HOSTS:
                    iplist = common.HOSTS[host]
                    if not iplist:
                        common.HOSTS[host] = iplist = tuple(x[-1][0] for x in socket.getaddrinfo(host, 80))
                    conn = MultiplexConnection(iplist, port)
                else:
                    iplist = (host,)
                if 'Host' in self.headers:
                    del self.headers['Host']
                if common.PROXY_USERNAME and 'Proxy-Authorization' not in self.headers:
                    self.headers['Proxy-Authorization'] = 'Basic %s' + base64.b64encode('%s:%s'%(common.PROXY_USERNAME, common.PROXY_PASSWROD))
                data = '\r\n\r\n%s %s:%s %s\r\n%s\r\n' % (self.command, random.choice(iplist), port, self.protocol_version, self.headers)
                sock.sendall(data)
            socket_forward(self.connection, sock, idlecall=idlecall)
        except Exception:
            logging.exception('GAEProxyHandler.do_CONNECT_Direct Error')
        finally:
            try:
                sock.close()
                del sock
            except:
                pass

    def do_CONNECT_Tunnel(self):
        # for ssl proxy
        host, _, port = self.path.rpartition(':')
        p = "(?:\d{1,3}\.){3}\d{1,3}"
        if re.match(p, host) is not None:
            host = DNSCacheUtil.getHost(host)
        keyFile, crtFile = CertUtil.getCertificate(host)
        self.log_request(200)
        self.connection.sendall('%s 200 OK\r\n\r\n' % self.protocol_version)
        try:
            self._realpath = self.path
            self._realrfile = self.rfile
            self._realwfile = self.wfile
            self._realconnection = self.connection
            self.connection = ssl.wrap_socket(self.connection, keyFile, crtFile, True)
            self.rfile = self.connection.makefile('rb', self.rbufsize)
            self.wfile = self.connection.makefile('wb', self.wbufsize)
            self.raw_requestline = self.rfile.readline(8192)
            if self.raw_requestline == '':
                return
            self.parse_request()
            if self.path[0] == '/':
                if 'Host' in self.headers:
                    self.path = 'https://%s:%s%s' % (self.headers['Host'].partition(':')[0], port or 443, self.path)
                else:
                    self.path = 'https://%s%s' % (self._realpath, self.path)
                self.requestline = '%s %s %s' % (self.command, self.path, self.protocol_version)
            self.do_METHOD_Tunnel()
        except socket.error:
            logging.exception('do_CONNECT_Tunnel socket.error')
        finally:
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except socket.error:
                pass
            self.rfile = self._realrfile
            self.wfile = self._realwfile
            self.connection = self._realconnection

    def do_METHOD(self):
        host = self.headers['Host']
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            if host in common.GOOGLE_FORCEHTTPS:
                self.send_response(301)
                self.send_header('Location', self.path.replace('http://', 'https://'))
                self.end_headers()
                return
            common.HOSTS[host] = common.GOOGLE_HOSTS
            return self.do_METHOD_Direct()
        elif host in common.HOSTS:
            return self.do_METHOD_Direct()
        elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
            if host not in common.HOSTS:
                try:
                    cname = common.CRLF_CNAME[itertools.ifilter(host.endswith, common.CRLF_CNAME).next()]
                except StopIteration:
                    cname = host
                logging.info('crlf dns_resolve(host=%r, cname=%r dnsserver=%r)', host, cname, common.CRLF_DNS)
                iplist = tuple(set(sum((dns_resolve(x, common.CRLF_DNS) if re.match(r'\d+\.\d+\.\d+\.\d+', host) else (host,) for x in cname.split(',')), ())))
                common.HOSTS[host] = iplist
            return self.do_METHOD_Direct()
        else:
            return self.do_METHOD_Tunnel()

    def do_METHOD_Direct(self):
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(self.path, 'http')
        try:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        except ValueError:
            host = netloc
            port = 80
        try:
            self.log_request()
            idlecall = None
            if not common.PROXY_ENABLE:
                if host in common.HOSTS:
                    iplist = common.HOSTS[host]
                    if not iplist:
                        common.HOSTS[host] = iplist = tuple(x[-1][0] for x in socket.getaddrinfo(host, 80))
                    conn = MultiplexConnection(iplist, port)
                    sock = conn.socket
                    idlecall = conn.close
                else:
                    sock = socket.create_connection((host, port))
                self.headers['Connection'] = 'close'
                data = '\r\n\r\n%s %s %s\r\n%s\r\n'  % (self.command, urlparse.urlunparse(('', '', path, params, query, '')), self.request_version, ''.join(line for line in self.headers.headers if not line.startswith('Proxy-')))
            else:
                sock = socket.create_connection((common.PROXY_HOST, common.PROXY_PORT))
                if host in common.HOSTS:
                    host = random.choice(common.HOSTS[host])
                else:
                    host = host
                url = urlparse.urlunparse((scheme, host + ('' if port == 80 else ':%d' % port), path, params, query, ''))
                self.headers['Host'] = netloc
                self.headers['Proxy-Connection'] = 'close'
                if common.PROXY_USERNAME and 'Proxy-Authorization' not in self.headers:
                    self.headers['Proxy-Authorization'] = 'Basic %s' + base64.b64encode('%s:%s'%(common.PROXY_USERNAME, common.PROXY_PASSWROD))
                data ='\r\n\r\n%s %s %s\r\n%s\r\n'  % (self.command, url, self.request_version, self.headers)
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                data += self.rfile.read(content_length)
            sock.sendall(data)
            socket_forward(self.connection, sock, idlecall=idlecall)
        except Exception:
            logging.exception('GAEProxyHandler.do_GET Error')
        finally:
            try:
                sock.close()
                del sock
            except:
                pass

    def do_METHOD_Tunnel(self):
        headers = self.headers
        host = headers.get('Host') or urlparse.urlparse(self.path).netloc.partition(':')[0]
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)
        payload_len = int(headers.get('Content-Length', 0))
        if payload_len:
            payload = self.rfile.read(payload_len)
        else:
            payload = ''

        if common.USERAGENT_ENABLE:
            headers['User-Agent'] = common.USERAGENT_STRING

        if 'Range' in headers.dict:
            m = re.search('bytes=(\d+)-', headers.dict['Range'])
            start = int(m.group(1) if m else 0)
            headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            logging.info('autorange range=%r match url=%r', headers['Range'], self.path)
        elif host.endswith(common.AUTORANGE_HOSTS_TAIL):
            try:
                pattern = (p for p in common.AUTORANGE_HOSTS if host.endswith(p) or fnmatch.fnmatch(host, p)).next()
                logging.debug('autorange pattern=%r match url=%r', pattern, self.path)
                m = re.search('bytes=(\d+)-', headers.get('Range', ''))
                start = int(m.group(1) if m else 0)
                headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            except StopIteration:
                pass

        skip_headers = self.skip_headers
        strheaders = ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems() if k not in skip_headers)

        retval, data = self.fetch(self.path, payload, self.command, strheaders)
        try:
            if retval == -1:
                return self.end_error(502, str(data))
            code = data['code']
            headers = data['headers']
            self.log_request(code)
            if code == 206 and self.command=='GET':
                content_range = headers.get('Content-Range') or headers.get('content-range') or ''
                m = re.search(r'bytes\s+(\d+)-(\d+)/(\d+)', content_range)
                if m and self.rangefetch(m, data):
                    return
            content = '%s %d %s\r\n%s\r\n' % (self.protocol_version, code, self.responses.get(code, ('GoAgent Notify', ''))[0], headers)
            self.connection.sendall(content)
            try:
                self.connection.sendall(data['content'])
            except KeyError:
                #logging.info('OOPS, KeyError! Content-Type=%r', headers.get('Content-Type'))
                response = data['response']
                while 1:
                    content = response.read(common.AUTORANGE_BUFSIZE)
                    if not content:
                        response.close()
                        break
                    self.connection.sendall(content)
            if 'close' == headers.get('Connection',''):
                self.close_connection = 1
        except socket.error as e:
            # Connection closed before proxy return
            if e[0] in (10053, errno.EPIPE):
                return

class PAASProxyHandler(GAEProxyHandler):

    HOSTS = {}

    def handle_fetch_error(self, error):
        logging.error('PAASProxyHandler handle_fetch_error %s', error)
        httplib.HTTPConnection.putrequest = _httplib_HTTPConnection_putrequest

    def fetch(self, url, payload, method, headers):
        fetchhost, fetchserver = common.PAAS_FETCH_INFO[self.server.server_address]
        dns  = None
        host = self.headers.get('Host')
        if host in PAASProxyHandler.HOSTS:
            dns = random.choice(tuple(x[-1][0] for x in socket.getaddrinfo(host, 80)))
        return urlfetch(url, payload, method, headers, fetchhost, fetchserver, password=common.PAAS_PASSWORD, dns=dns, on_error=self.handle_fetch_error)

    def setup(self):
        PAASProxyHandler.HOSTS = dict((k, tuple(v.split('|')) if v else None) for k, v in common.CONFIG.items('hosts'))
        if common.PROXY_ENABLE:
            logging.info('Local Proxy is enable, PAASProxyHandler dont resole DNS')
        else:
            for fetchhost, _ in common.PAAS_FETCH_INFO.itervalues():
                logging.info('PAASProxyHandler.setup check %s is in common.HOSTS', fetchhost)
                if fetchhost not in common.HOSTS:
                    with GAEProxyHandler.SetupLock:
                        if fetchhost not in common.HOSTS:
                            try:
                                logging.info('Resole PAAS fetchserver address.')
                                common.HOSTS[fetchhost] = tuple(x[-1][0] for x in socket.getaddrinfo(fetchhost, 80))
                                logging.info('Resole PAAS fetchserver address OK. %s', common.HOSTS[fetchhost])
                            except Exception:
                                logging.exception('PAASProxyHandler.setup resolve fail')
        PAASProxyHandler.do_CONNECT = GAEProxyHandler.do_CONNECT_Tunnel
        PAASProxyHandler.do_GET     = GAEProxyHandler.do_METHOD_Tunnel
        PAASProxyHandler.do_POST    = GAEProxyHandler.do_METHOD_Tunnel
        PAASProxyHandler.do_PUT     = GAEProxyHandler.do_METHOD_Tunnel
        PAASProxyHandler.do_DELETE  = GAEProxyHandler.do_METHOD_Tunnel
        PAASProxyHandler.do_HEAD    = PAASProxyHandler.do_METHOD
        PAASProxyHandler.setup      = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

class PacServerHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def _generate_pac(self):
        url = common.PAC_REMOTE
        logging.info('PacServerHandler._generate_pac url=%r, timeout=%r', url, common.PAC_TIMEOUT)
        content = urllib2.urlopen(url, timeout=common.PAC_TIMEOUT).read()
        cndatas = re.findall(r'(?i)apnic\|cn\|ipv4\|([0-9\.]+)\|([0-9]+)\|[0-9]+\|a.*', content)
        logging.info('PacServerHandler._generate_pac download %s bytes %s items', len(content), len(cndatas))
        assert len(cndatas) > 0
        cndatas = [(ip, socket.inet_ntoa(struct.pack('!I', (int(n)-1)^0xffffffff))) for ip, n in cndatas]
        cndataslist = [[] for i in xrange(256)]
        for ip, mask in cndatas:
            i = int(ip.partition('.')[0])
            cndataslist[i].append([ip, mask])
        if common.LISTEN_IP in ('', '0.0.0.0', '::'):
            proxy = 'PROXY %s:%d' % (socket.gethostbyname(socket.gethostname()), common.LISTEN_PORT)
        else:
            proxy = 'PROXY %s:%d' % (common.LISTEN_IP, common.LISTEN_PORT)
        PAC_TEMPLATE = '''\
            //inspired from https://github.com/Leask/Flora_Pac
            function FindProxyForURL(url, host)
            {
                if (false %s) {
                    return 'DIRECT';
                }
                var ip = dnsResolve(host);
                if (ip == null) {
                    return '%s';
                }
                var lists = %s;
                var index  = parseInt(ip.split('.', 1)[0], 10);
                var list = lists[index];
                for (var i in list) {
                    if (isInNet(ip, list[i][0], list[i][1])) {
                        return 'DIRECT';
                    }
                }
                return '%s';
            }'''
        directs = '||'.join(['dnsDomainIs(host, "%s")' % x for x in common.PAC_DIRECTS]) if common.PAC_DIRECTS else ''
        return PAC_TEMPLATE % (directs, proxy, repr(cndataslist), proxy)

    def do_GET(self):
        filename = os.path.join(os.path.dirname(__file__), common.PAC_FILE)
        if self.path != '/'+common.PAC_FILE or not os.path.isfile(filename):
            return self.send_error(404, 'Not Found')
        if common.PAC_UPDATE and time.time() - os.path.getmtime(common.PAC_FILE) > 86400:
            try:
                logging.info('PacServerHandler begin sync remote pac')
                content = self._generate_pac()
                with open(filename, 'wb') as fp:
                    fp.write(content)
                logging.info('PacServerHandler end sync remote pac')
            except Exception:
                logging.exception('PacServerHandler sync remote pac failed')
        with open(filename, 'rb') as fp:
            data = fp.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-ns-proxy-autoconfig')
            self.end_headers()
            self.wfile.write(data)
            self.wfile.close()

class ProxyAndPacHandler(GAEProxyHandler, PacServerHandler):
    def do_GET(self):
        if self.path == '/'+common.PAC_FILE:
            PacServerHandler.do_GET(self)
        else:
            GAEProxyHandler.do_METHOD(self)

class LocalProxyServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def try_show_love():
    '''If you hate this funtion, please go back to gappproxy/wallproxy'''
    if ctypes and os.name == 'nt' and common.LOVE_ENABLE:
        SetConsoleTitleW = ctypes.windll.kernel32.SetConsoleTitleW
        GetConsoleTitleW = ctypes.windll.kernel32.GetConsoleTitleW
        if common.LOVE_TIMESTAMP.strip():
            common.LOVE_TIMESTAMP = int(common.LOVE_TIMESTAMP)
        else:
            common.LOVE_TIMESTAMP = int(time.time())
            with open(__config__, 'w') as fp:
                common.CONFIG.set('love', 'timestamp', int(time.time()))
                common.CONFIG.write(fp)
        if time.time() - common.LOVE_TIMESTAMP > 86400 and random.randint(1,10) > 5:
            title = ctypes.create_unicode_buffer(1024)
            GetConsoleTitleW(ctypes.byref(title), len(title)-1)
            SetConsoleTitleW(u'%s %s' % (title.value, random.choice(common.LOVE_TIP)))
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

    global logging
    if logging is None:
        sys.modules['logging'] = logging = SimpleLogging()
    logging.basicConfig(level=logging.DEBUG if common.GAE_DEBUGLEVEL else logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    if ctypes and os.name == 'nt':
        ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)
        if not common.LOVE_TIMESTAMP.strip():
            sys.stdout.write('Double click addto-startup.vbs could add goagent to autorun programs. :)\n')
        try_show_love()
        if not common.LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    if common.GAE_APPIDS[0] == 'goagent' and not common.CRLF_ENABLE:
        logging.critical('please edit %s to add your appid to [gae] !', __config__)
        sys.exit(-1)
    CertUtil.checkCA()
    common.install_opener()
    sys.stdout.write(common.info())

    LocalProxyServer.address_family = (socket.AF_INET, socket.AF_INET6)[':' in common.LISTEN_IP]

    # GAEProxy Patch
    pid = str(os.getpid())
    f = open('/data/data/org.gaeproxy/python.pid','a')
    f.write(" ")
    f.write(pid)
    f.close()

    if common.PAAS_ENABLE:
        for address in common.PAAS_FETCH_INFO:
            httpd = LocalProxyServer(address, PAASProxyHandler)
            thread.start_new_thread(httpd.serve_forever, ())

    if common.PAC_ENABLE and common.PAC_PORT != common.LISTEN_PORT:
        httpd = LocalProxyServer((common.PAC_IP,common.PAC_PORT),PacServerHandler)
        thread.start_new_thread(httpd.serve_forever,())

    if common.PAC_ENABLE and common.PAC_PORT == common.LISTEN_PORT:
        httpd = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), ProxyAndPacHandler)
    else:
        httpd = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GAEProxyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
   try:
       main()
   except KeyboardInterrupt:
       pass
