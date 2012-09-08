#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>
# Contributor:
#      Phus Lu        <phus.lu@gmail.com>
#      Hewig Xu       <hewigovens@gmail.com>
#      Ayanamist Yang <ayanamist@gmail.com>
#      Max Lv         <max.c.lv@gmail.com>
#      AlsoTang       <alsotang@gmail.com>
#      Yonsm          <YonsmGuo@gmail.com>

from __future__ import with_statement

__version__ = '2.0.5'
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

class HTTPNoRedirectHandler(urllib2.HTTPRedirectHandler, urllib2.HTTPDefaultErrorHandler):
    http_error_301 = http_error_302 = http_error_303 = http_error_304 = http_error_307 = urllib2.HTTPDefaultErrorHandler.http_error_default

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

        self.PAAS_ENABLE           = self.CONFIG.getint('paas', 'enable')
        self.PAAS_LISTEN           = self.CONFIG.get('paas', 'listen')
        self.PAAS_PASSWORD         = self.CONFIG.get('paas', 'password') if self.CONFIG.has_option('paas', 'password') else ''
        self.PAAS_FETCHSERVER      = self.CONFIG.get('paas', 'fetchserver')
        self.PAAS_FETCHHOST        = urlparse.urlparse(self.CONFIG.get('paas', 'fetchserver')).netloc.rsplit(':', 1)[0]

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

        self.AUTORANGE_ENABLE     = self.CONFIG.getint('autorange', 'enable') if self.CONFIG.has_option('autorange', 'enable') else 0
        self.AUTORANGE_HOSTS      = tuple(self.CONFIG.get('autorange', 'hosts').split('|'))
        self.AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in self.AUTORANGE_HOSTS)
        self.AUTORANGE_MAXSIZE    = self.CONFIG.getint('autorange', 'maxsize')
        self.AUTORANGE_WAITSIZE   = self.CONFIG.getint('autorange', 'waitsize')

        assert self.AUTORANGE_WAITSIZE <= self.AUTORANGE_MAXSIZE

        if self.CONFIG.has_section('crlf'):
            # XXX, cowork with GoAgentX
            self.CRLF_ENABLE          = self.CONFIG.getint('crlf', 'enable')
            self.CRLF_DNS             = self.CONFIG.get('crlf', 'dns')
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
        self.GAE_FETCHHOST = '%s.appspot.com' % self.GAE_APPIDS[0]
        if not self.PROXY_ENABLE:
            # append '?' to url, it can avoid china telicom/unicom AD
            self.GAE_FETCHSERVER = '%s://%s%s?' % (self.GOOGLE_MODE, self.GAE_FETCHHOST, self.GAE_PATH)
        else:
            self.GAE_FETCHSERVER = '%s://%s%s?' % (self.GOOGLE_MODE, random.choice(self.GOOGLE_HOSTS), self.GAE_PATH)

    def install_opener(self):
        """install urllib2 opener"""
        httplib.HTTPMessage = SimpleMessageClass
        handlers = [HTTPNoRedirectHandler]
        if self.PROXY_ENABLE:
            proxy = '%s:%s@%s:%d'%(self.PROXY_USERNAME, self.PROXY_PASSWROD, self.PROXY_HOST, self.PROXY_PORT)
            handlers += [urllib2.ProxyHandler({'http':proxy,'https':proxy})]
        else:
            handlers += [urllib2.ProxyHandler({})]
        opener = urllib2.build_opener(*handlers)
        opener.addheaders = []
        urllib2.install_opener(opener)

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version   : %s (python/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
        info += 'Listen Address    : %s:%d\n' % (self.LISTEN_IP,self.LISTEN_PORT)
        info += 'Local Proxy       : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug Level       : %s\n' % self.GAE_DEBUGLEVEL if self.GAE_DEBUGLEVEL else ''
        info += 'GAE Mode          : %s\n' % self.GOOGLE_MODE if self.GAE_ENABLE else ''
        info += 'GAE Profile       : %s\n' % self.GAE_PROFILE
        info += 'GAE APPID         : %s\n' % '|'.join(self.GAE_APPIDS)
        if common.PAAS_ENABLE:
            info += 'PAAS Listen       : %s\n' % common.PAAS_LISTEN
            info += 'PAAS FetchServer  : %s\n' % common.PAAS_FETCHSERVER
        if common.SOCKS5_ENABLE:
            info += 'SOCKS5 Listen      : %s\n' % common.PAAS_LISTEN
            info += 'SOCKS5 FetchServer : %s\n' % common.SOCKS5_FETCHSERVER
        if common.PAC_ENABLE:
            info += 'Pac Server        : http://%s:%d/%s\n' % (self.PAC_IP,self.PAC_PORT,self.PAC_FILE)
        if common.CRLF_ENABLE:
            #http://www.acunetix.com/websitesecurity/crlf-injection.htm
            info += 'CRLF Injection    : %s\n' % '|'.join(self.CRLF_SITES)
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
            except socket.error:
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

def httplib_normalize_headers(response_headers, skip_headers=[]):
    headers = []
    for keyword, value in response_headers:
        keyword = keyword.title()
        if keyword in skip_headers:
            continue
        if keyword == 'Connection':
            headers.append(('Connection', 'close'))
        elif keyword != 'Set-Cookie':
            headers.append((keyword, value))
        else:
            scs = value.split(', ')
            cookies = []
            i = -1
            for sc in scs:
                if re.match(r'[^ =]+ ', sc):
                    try:
                        cookies[i] = '%s, %s' % (cookies[i], sc)
                    except IndexError:
                        pass
                else:
                    cookies.append(sc)
                    i += 1
            headers += [('Set-Cookie', x) for x in cookies]
    return headers

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
        if len(commonname) >= 32:
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
        basedir = '/data/data/org.gaeproxy'
        capath = os.path.join(basedir, 'CA.key')
        #Check Certs Dir
        certdir = os.path.join(basedir, 'certs')
        if not os.path.exists(certdir):
            os.makedirs(certdir)


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

def encode_request(headers, **kwargs):
    if hasattr(headers, 'items'):
        headers = headers.items()
    data = ''.join('%s: %s\r\n' % (k, v) for k, v in headers) + ''.join('X-Goa-%s: %s\r\n' % (k.title(), v) for k, v in kwargs.iteritems())
    return base64.b64encode(zlib.compress(data)).rstrip()

def decode_request(request):
    data     = zlib.decompress(base64.b64decode(request))
    headers  = []
    kwargs   = {}
    for line in data.splitlines():
        keyword, _, value = line.partition(':')
        if keyword.startswith('X-Goa-'):
            kwargs[keyword[6:].lower()] = value.strip()
        else:
            headers.append((keyword.title(), value.strip()))
    return headers, kwargs

def pack_request(method, url, headers, payload, fetchhost, password=''):
    content_length = int(headers.get('Content-Length',0))
    request_kwargs = {'method':method, 'url':url}
    if password:
        request_kwargs['password'] = password
    request_headers = {'Host':fetchhost, 'Cookie':encode_request(headers, **request_kwargs), 'Content-Length':str(content_length)}
    if not isinstance(payload, str):
        payload = payload.read(content_length)
    return 'POST', request_headers, payload

class GAEProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    MessageClass = SimpleMessageClass
    setup_lock = threading.Lock()

    def log_message(self, fmt, *args):
        host, port = self.client_address[:2]
        sys.stdout.write("%s:%d - - [%s] %s\n" % (host, port, time.ctime()[4:-5], fmt%args))

    def send_response(self, code, headers=None):
        self.log_request(code)
        message = self.responses.get(code, ('OK',))[0]
        self.connection.sendall('%s %d %s\r\n%s\r\n' % 
            (self.protocol_version, code, message, headers))

    # GAEProxy patch
    # send all headers in one operation, hacks for redsocks
    def send_headers(self, code, headers=None):
        content = None
        if headers is not None:
            content = ''
            for keyword, value in headers:
                content += '%s: %s\r\n' % (keyword, value)
        self.send_response(code, content)

    def setup(self):
        if not common.PROXY_ENABLE and common.GAE_PROFILE != 'google_ipv6':
            logging.info('resolve common.GOOGLE_HOSTS domian=%r to iplist', common.GOOGLE_HOSTS)
            if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
                with self.__class__.setup_lock:
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
                            logging.error('resolve %s domian return empty! please use ip list to replace domain list!', common.GAE_PROFILE)
                            sys.exit(-1)
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
                logging.info('crlf dns_resolve(host=%r, dnsserver=%r)', host, common.CRLF_DNS)
                common.HOSTS[host] = dns_resolve(host, common.CRLF_DNS)
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
        keyfile, certfile = CertUtil.get_cert(host)
        self.log_request(200)
        self.connection.sendall('%s 200 OK\r\n\r\n' % self.protocol_version)
        try:
            self._realpath = self.path
            self._realrfile = self.rfile
            self._realwfile = self.wfile
            self._realconnection = self.connection
            try:
                self.connection = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=keyfile, server_side=True)
            except Exception as e:
                logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
                self.connection = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=keyfile, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
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
                self.send_headers(301, [('Location', self.path.replace('http://', 'https://'))])
                return
            common.HOSTS[host] = common.GOOGLE_HOSTS
            return self.do_METHOD_Direct()
        elif host in common.HOSTS:
            return self.do_METHOD_Direct()
        elif common.CRLF_ENABLE and host.endswith(common.CRLF_SITES):
            if host not in common.HOSTS:
                logging.info('crlf dns_resolve(host=%r, dnsserver=%r)', host, common.CRLF_DNS)
                common.HOSTS[host] = dns_resolve(host, common.CRLF_DNS)
            return self.do_METHOD_Direct()
        else:
            return self.do_METHOD_Tunnel()

    def do_METHOD_Direct(self):
        try:
            self.log_request()

            content_length = int(self.headers.get('Content-Length', 0))
            payload = self.rfile.read(content_length) if content_length else None
            request = urllib2.Request(self.path, data=payload, headers=dict(self.headers))
            request.get_method = lambda: self.command
            try:
                response = urllib2.urlopen(request)
            except urllib2.HTTPError as http_error:
                response = http_error
            except urllib2.URLError as url_error:
                raise

            headers = httplib_normalize_headers(response.headers.items(), skip_headers=['Transfer-Encoding'])

            self.send_headers(response.code, headers)

            while 1:
                data = response.read(8192)
                if not data:
                    response.close()
                    break
                self.wfile.write(data)
        except Exception:
            logging.exception('GAEProxyHandler.do_GET Error')

    def rangefetch(self, method, url, headers, payload, current_length, content_length):
        if current_length < content_length:
            headers['Range'] = 'bytes=%d-%d' % (current_length, min(current_length+common.AUTORANGE_MAXSIZE-1, content_length-1))
            request_method, request_headers, payload = pack_request(method, url, headers, payload, common.GAE_FETCHHOST, common.GAE_PASSWORD)
            request  = urllib2.Request(common.GAE_FETCHSERVER, data=payload, headers=request_headers)
            request.get_method = lambda: request_method
            try:
                response = urllib2.urlopen(request)
            except urllib2.HTTPError as http_error:
                response = http_error
            except urllib2.URLError as url_error:
                raise

            if 'Set-Cookie' not in response.headers:
                self.send_headers(response.code, response.headers.items());
                self.wfile.write(response.read())
                return

            response_headers, response_kwargs = decode_request(response.headers['Set-Cookie'])
            response_status = int(response_kwargs['status'])

            if response_status == 302:
                response_location = dict(response_headers)['Location']
                logging.info('Range Fetch Redirect(%r)', response_location)
                return self.rangefetch(method, response_location, headers, payload, current_length, content_length)

            content_range = dict(response_headers).get('Content-Range')

            if not content_range:
                logging.wa('rangefetch "%s %s" failed: response_kwargs=%s response_headers=%s', method, url, response_kwargs, response_headers)
                return

            logging.info('>>>>>>>>>>>>>>> %s %d', content_range, content_length)
            while 1:
                data = response.read(8192)
                if not data or current_length >= content_length:
                    response.close()
                    break
                current_length += len(data)
                self.wfile.write(data)

            if current_length < content_length:
                return self.rangefetch(method, url, headers, payload, current_length, content_length)

    def do_METHOD_Tunnel(self):
        host = self.headers.get('Host') or urlparse.urlparse(self.path).netloc.partition(':')[0]
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)

        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING

        if common.AUTORANGE_ENABLE:
            if 'Range' in self.headers:
                m = re.search('bytes=(\d+)-', self.headers.dict['Range'])
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
            method, headers, payload = pack_request(self.command, self.path, self.headers, self.rfile, common.GAE_FETCHHOST, common.GAE_PASSWORD)
            request  = urllib2.Request(common.GAE_FETCHSERVER, data=payload, headers=headers)
            request.get_method = lambda: method

            try:
                response = urllib2.urlopen(request)
            except urllib2.HTTPError as http_error:
                response = http_error
                # gateway error, switch to https mode
                if response.code in (400, 504) or (response.code==502 and common.GAE_PROFILE=='google_cn'):
                    common.GOOGLE_MODE = 'https'
                    common.build_gae_fetchserver()
                # appid over qouta, switch to next appid
                if response.code == 503:
                    common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                    common.build_gae_fetchserver()
                # bad request, disable CRLF injection
                if response.code in (400, 405):
                    httplib.HTTPConnection.putrequest = _httplib_HTTPConnection_putrequest
            except urllib2.URLError as url_error:
                if url_error.reason[0] in (11004, 10051, 10060, 'timed out', 10054):
                    # connection reset or timeout, switch to https
                    common.GOOGLE_MODE = 'https'
                    common.build_gae_fetchserver()
                raise

            if 'Set-Cookie' not in response.headers:
                self.send_headers(response.code, response.headers.items())
                self.wfile.write(response.read())
                return

            response_headers, response_kwargs = decode_request(response.headers['Set-Cookie'])
            response_status = int(response_kwargs['status'])
            headers = httplib_normalize_headers(response_headers, skip_headers=['Transfer-Encoding'])

            if response_status == 206:
                response_headers_towrite = []
                for keyword, value in headers:
                    if keyword == 'Content-Range':
                        content_range = value
                    elif keyword == 'Content-Length':
                        content_length = value
                    else:
                        response_headers_towrite.append((keyword, value))
                start, end, length = map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3))
                if start == 0:
                    response_headers_towrite.append(('Content-Length', str(length)))
                    self.send_headers(200, response_headers_towrite)
                else:
                    response_headers_towrite.append(('Content-Length', content_length))
                    response_headers_towrite.append(('Content-Range', content_range))
                    self.send_headers(206, response_headers_towrite)

                while 1:
                    data = response.read(8192)
                    if not data:
                        response.close()
                        break
                    self.wfile.write(data)

                logging.info('>>>>>>>>>>>>>>> Range Fetch started(%r)', host)
                self.rangefetch(self.command, self.path, self.headers, payload, end+1, length)
                logging.info('>>>>>>>>>>>>>>> Range Fetch ended(%r)', host)
                return

            self.send_headers(response_status, headers)

            while 1:
                data = response.read(8192)
                if not data:
                    response.close()
                    break
                #logging.debug('response.read(8192) return %r', data)
                self.wfile.write(data)
        except httplib.HTTPException as e:
            raise
        except socket.error as e:
            # Connection closed before proxy return
            if e[0] in (10053, errno.EPIPE):
                return

class PAASProxyHandler(GAEProxyHandler):

    def setup(self):
        host = common.PAAS_FETCHHOST
        if host not in common.HOSTS:
            logging.info('resolve host domian=%r to iplist', host)
            with self.__class__.setup_lock:
                if host not in common.HOSTS:
                    common.HOSTS[host] = tuple(x[-1][0] for x in socket.getaddrinfo(host, 80))
                    logging.info('resolve host domian to iplist=%r', common.HOSTS[host])
        PAASProxyHandler.do_GET     = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_POST    = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_PUT     = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_DELETE  = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_OPTIONS = PAASProxyHandler.do_METHOD
        PAASProxyHandler.do_HEAD    = PAASProxyHandler.do_METHOD
        PAASProxyHandler.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def do_METHOD(self):
        host = self.headers.get('Host') or urlparse.urlparse(self.path).netloc.partition(':')[0]
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)

        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING

        if common.AUTORANGE_ENABLE:
            if 'Range' in self.headers:
                m = re.search('bytes=(\d+)-', self.headers.dict['Range'])
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
            method, headers, payload = pack_request(self.command, self.path, self.headers, self.rfile, common.PAAS_FETCHHOST, common.PAAS_PASSWORD)
            request  = urllib2.Request(common.PAAS_FETCHSERVER, data=payload, headers=headers)
            request.get_method = lambda: method

            try:
                response = urllib2.urlopen(request)
            except urllib2.HTTPError as http_error:
                response = http_error
                if response.code in (400, 405):
                    httplib.HTTPConnection.putrequest = _httplib_HTTPConnection_putrequest
            except urllib2.URLError as url_error:
                raise

            headers = httplib_normalize_headers(response.headers.items())

            self.send_headers(response.code, headers)

            while 1:
                data = response.read(8192)
                if not data:
                    response.close()
                    break
                self.wfile.write(data)
        except httplib.HTTPException as e:
            raise
        except socket.error as e:
            # Connection closed before proxy return
            if e[0] in (10053, errno.EPIPE):
                return

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(':')
        keyfile, certfile = CertUtil.get_cert(host)
        self.log_request(200)
        self.connection.sendall('%s 200 OK\r\n\r\n' % self.protocol_version)
        try:
            self._realpath = self.path
            self._realrfile = self.rfile
            self._realwfile = self.wfile
            self._realconnection = self.connection
            try:
                self.connection = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=keyfile, server_side=True)
            except Exception as e:
                logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
                self.connection = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=keyfile, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1)
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
            self.do_METHOD()
        except socket.error as e:
            logging.exception('PAASProxyHandler.do_CONNECT socket.error %s', e)
        finally:
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except socket.error:
                pass
            self.rfile = self._realrfile
            self.wfile = self._realwfile
            self.connection = self._realconnection

class Sock5ProxyHandler(SocketServer.StreamRequestHandler):

    setup_lock = threading.Lock()

    def log_message(self, fmt, *args):
        host, port = self.client_address[:2]
        sys.stdout.write("%s:%d - - [%s] %s\n" % (host, port, time.ctime()[4:-5], fmt%args))

    def connect_paas(self, socks5_fetchserver):
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(socks5_fetchserver)
        if re.search(r':\d+$', netloc):
            host, _, port = netloc.rpartition(':')
            port = int(port)
        else:
            host = netloc
            port = {'https':443,'http':80}.get(scheme, 80)
        sock = socket.create_connection((host, port))
        if scheme == 'https':
            sock = ssl.wrap_socket(sock)
        sock.sendall('PUT /socks5 HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n' % host)
        return sock

    def handle(self):
        try:
            socks5_fetchserver = common.SOCKS5_FETCHSERVER
            self.log_message('Connect to socks5_server=%r', socks5_fetchserver)
            sock = self.connect_paas(socks5_fetchserver)
            socket_forward(self.connection, sock)
        except Exception, e:
            logging.exception('Sock5ProxyHandler.handle client_address=%r failed:%s', self.client_address[:2], e)

    def setup(self):
        fetchhost = re.sub(r':\d+$', '', urlparse.urlparse(common.SOCKS5_FETCHSERVER).netloc)
        if not common.PROXY_ENABLE:
            logging.info('resolve socks5 fetchhost=%r to iplist', fetchhost)
            if fetchhost not in common.HOSTS:
                with Sock5ProxyHandler.setup_lock:
                    if fetchhost not in common.HOSTS:
                        common.HOSTS[fetchhost] = tuple(x[-1][0] for x in socket.getaddrinfo(fetchhost, 80))
                        logging.info('resolve socks5 fetchhost=%r to iplist=%r', fetchhost, common.HOSTS[fetchhost])
        Sock5ProxyHandler.setup = SocketServer.StreamRequestHandler.setup
        SocketServer.StreamRequestHandler.setup(self)

class PacServerHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def send_file(self, filename, headers):
        pass

    def do_GET(self):
        filename = os.path.join(os.path.dirname(__file__), common.PAC_FILE)
        if self.path != '/'+common.PAC_FILE or not os.path.isfile(filename):
            return self.send_error(404, 'Not Found')
        with open(filename, 'rb') as fp:
            data = fp.read()
            self.send_headers(200, [('Content-Type', 'application/x-ns-proxy-autoconfig')])
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
    """If you hate this funtion, please go back to gappproxy/wallproxy"""
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

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    global logging
    if logging is None:
        sys.modules['logging'] = logging = SimpleLogging()
    logging.basicConfig(level=logging.DEBUG if common.GAE_DEBUGLEVEL else logging.INFO, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')
    CertUtil.check_ca()
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
        host, _, port = common.PAAS_LISTEN.rpartition(':')
        httpd = LocalProxyServer((host, int(port)), PAASProxyHandler)
        thread.start_new_thread(httpd.serve_forever, ())

    if common.SOCKS5_ENABLE:
        host, _, port = common.SOCKS5_LISTEN.rpartition(':')
        httpd = LocalProxyServer((host, int(port)), Sock5ProxyHandler)
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