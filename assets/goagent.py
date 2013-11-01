#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang.2008@gmail.com>
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
#      Zhang Youfu    <zhangyoufu@gmail.com>
#      Harmony Meow   <harmony.meow@gmail.com>
#      logostream     <logostream@gmail.com>
#      Felix Yan      <felixonmars@gmail.com>
#      Mort Yao       <mort.yao@gmail.com>
#      Wang Wei Qiang <wwqgtxx@gmail.com>
#      Poly Rabbit    <mcx_221@foxmail.com>

__version__ = '3.0.5'

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
    import gevent.event
    import gevent.monkey
    gevent.monkey.patch_all()
except (ImportError, SystemError):
    gevent = None

import errno
import binascii
import time
import struct
import collections
import zlib
import functools
import re
import io
import fnmatch
import traceback
import random
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
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import dnslib
except ImportError:
    dnslib = None

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
        self.__write = __write = sys.stderr.write
        #GAEProxy Patch
        self.__set_error_color = lambda: None
        self.__set_warning_color = lambda: None
        self.__set_debug_color = lambda: None
        self.__reset_color = lambda: None
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
        self.__set_debug_color()
        self.log('DEBUG', fmt, *args, **kwargs)
        self.__reset_color()

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
        #req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans)).encode()])
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha1')

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
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
        #cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, 'sha1')

        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        return certfile

    @staticmethod
    def get_cert(commonname, sans=()):
        if commonname.count('.') >= 2 and len(commonname.split('.')[-2]) > 4:
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
        #GAEProxy Patch
        return 0

    @staticmethod
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_keyfile)
        certdir = os.path.join(os.path.dirname(__file__), CertUtil.ca_certdir)
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.path.exists(certdir):
                if os.path.isdir(certdir):
                    any(os.remove(x) for x in glob.glob(certdir+'/*.crt'))
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


class PacUtil(object):
    """GoAgent Pac Util"""

    @staticmethod
    def update_pacfile(filename):
        listen_ip = ProxyUtil.get_listen_ip() if common.LISTEN_IP in ('', '::', '0.0.0.0') else common.LISTEN_IP
        autoproxy = '%s:%s' % (listen_ip, common.LISTEN_PORT)
        blackhole = '%s:%s' % (listen_ip, common.PAC_PORT)
        default = '%s:%s' % (common.PROXY_HOST, common.PROXY_PORT) if common.PROXY_ENABLE else 'DIRECT'
        opener = urllib2.build_opener(urllib2.ProxyHandler({'http': autoproxy, 'https': autoproxy}))
        content = ''
        need_update = True
        with open(filename, 'rb') as fp:
            content = fp.read()
        try:
            placeholder = '// AUTO-GENERATED RULES, DO NOT MODIFY!'
            content = content[:content.index(placeholder)+len(placeholder)]
            content = re.sub(r'''blackhole\s*=\s*['"]PROXY [\.\w:]+['"]''', 'blackhole = \'PROXY %s\'' % blackhole, content)
            content = re.sub(r'''autoproxy\s*=\s*['"]PROXY [\.\w:]+['"]''', 'autoproxy = \'PROXY %s\'' % autoproxy, content)
            if content.startswith('//'):
                line = '// Proxy Auto-Config file generated by autoproxy2pac, %s\r\n' % time.strftime('%Y-%m-%d %H:%M:%S')
                content = line + '\r\n'.join(content.splitlines()[1:])
        except ValueError:
            need_update = False
        try:
            logging.info('try download %r to update_pacfile(%r)', common.PAC_ADBLOCK, filename)
            adblock_content = opener.open(common.PAC_ADBLOCK).read()
            logging.info('%r downloaded, try convert it with adblock2pac', common.PAC_ADBLOCK)
            if 'gevent' in sys.modules and time.sleep is getattr(sys.modules['gevent'], 'sleep', None) and hasattr(gevent.get_hub(), 'threadpool'):
                jsrule = gevent.get_hub().threadpool.apply(PacUtil.adblock2pac, (adblock_content, 'FindProxyForURLByAdblock', blackhole, default))
            else:
                jsrule = PacUtil.adblock2pac(adblock_content, 'FindProxyForURLByAdblock', blackhole, default)
            content += '\r\n' + jsrule + '\r\n'
            logging.info('%r downloaded and parsed', common.PAC_ADBLOCK)
        except Exception as e:
            need_update = False
            logging.exception('update_pacfile failed: %r', e)
        try:
            logging.info('try download %r to update_pacfile(%r)', common.PAC_GFWLIST, filename)
            autoproxy_content = base64.b64decode(opener.open(common.PAC_GFWLIST).read())
            logging.info('%r downloaded, try convert it with autoproxy2pac', common.PAC_GFWLIST)
            if 'gevent' in sys.modules and time.sleep is getattr(sys.modules['gevent'], 'sleep', None) and hasattr(gevent.get_hub(), 'threadpool'):
                jsrule = gevent.get_hub().threadpool.apply(PacUtil.autoproxy2pac, (autoproxy_content, 'FindProxyForURLByAutoProxy', autoproxy, default))
            else:
                jsrule = PacUtil.autoproxy2pac(autoproxy_content, 'FindProxyForURLByAutoProxy', autoproxy, default)
            content += '\r\n' + jsrule + '\r\n'
            logging.info('%r downloaded and parsed', common.PAC_GFWLIST)
        except Exception as e:
            need_update = False
            logging.exception('update_pacfile failed: %r', e)
        if need_update:
            with open(filename, 'wb') as fp:
                fp.write(content)
            logging.info('%r successfully updated', filename)

    @staticmethod
    def autoproxy2pac(content, func_name='FindProxyForURLByAutoProxy', proxy='127.0.0.1:8087', default='DIRECT', indent=4):
        """Autoproxy to Pac, based on https://github.com/iamamac/autoproxy2pac"""
        jsLines = []
        for line in content.splitlines()[1:]:
            if line and not line.startswith("!"):
                use_proxy = True
                if line.startswith("@@"):
                    line = line[2:]
                    use_proxy = False
                return_proxy = 'PROXY %s' % proxy if use_proxy else default
                if line.startswith('/') and line.endswith('/'):
                    jsLine = 'if (/%s/i.test(url)) return "%s";' % (line[1:-1], return_proxy)
                elif line.startswith('||'):
                    domain = line[2:].lstrip('.')
                    if 'host.indexOf(".%s") >= 0' % domain in jsLines[-1] or 'host.indexOf("%s") >= 0' % domain in jsLines[-1]:
                        jsLines.pop()
                    jsLine = 'if (dnsDomainIs(host, ".%s") || host == "%s") return "%s";' % (domain, domain, return_proxy)
                elif line.startswith('|'):
                    jsLine = 'if (url.indexOf("%s") == 0) return "%s";' % (line[1:], return_proxy)
                elif '*' in line:
                    jsLine = 'if (shExpMatch(url, "*%s*")) return "%s";' % (line.strip('*'), return_proxy)
                elif '/' not in line:
                    jsLine = 'if (host.indexOf("%s") >= 0) return "%s";' % (line, return_proxy)
                else:
                    jsLine = 'if (url.indexOf("%s") >= 0) return "%s";' % (line, return_proxy)
                jsLine = ' ' * indent + jsLine
                if use_proxy:
                    jsLines.append(jsLine)
                else:
                    jsLines.insert(0, jsLine)
        function = 'function %s(url, host) {\r\n%s\r\n%sreturn "%s";\r\n}' % (func_name, '\n'.join(jsLines), ' '*indent, default)
        return function

    @staticmethod
    def urlfilter2pac(content, func_name='FindProxyForURLByUrlfilter', proxy='127.0.0.1:8086', default='DIRECT', indent=4):
        """urlfilter.ini to Pac, based on https://github.com/iamamac/autoproxy2pac"""
        jsLines = []
        for line in content[content.index('[exclude]'):].splitlines()[1:]:
            if line and not line.startswith(';'):
                use_proxy = True
                if line.startswith("@@"):
                    line = line[2:]
                    use_proxy = False
                return_proxy = 'PROXY %s' % proxy if use_proxy else default
                if '*' in line:
                    jsLine = 'if (shExpMatch(url, "%s")) return "%s";' % (line, return_proxy)
                else:
                    jsLine = 'if (url == "%s") return "%s";' % (line, return_proxy)
                jsLine = ' ' * indent + jsLine
                if use_proxy:
                    jsLines.append(jsLine)
                else:
                    jsLines.insert(0, jsLine)
        function = 'function %s(url, host) {\r\n%s\r\n%sreturn "%s";\r\n}' % (func_name, '\n'.join(jsLines), ' '*indent, default)
        return function

    @staticmethod
    def adblock2pac(content, func_name='FindProxyForURLByAdblock', proxy='127.0.0.1:8086', default='DIRECT', indent=4):
        """adblock list to Pac, based on https://github.com/iamamac/autoproxy2pac"""
        jsLines = []
        for line in content.splitlines()[1:]:
            if not line or line.startswith('!') or '##' in line or '#@#' in line:
                continue
            use_proxy = True
            use_start = False
            use_end = False
            use_domain = False
            use_postfix = []
            if '$' in line:
                posfixs = line.split('$')[-1].split(',')
                if any('domain' in x for x in posfixs):
                    continue
                if 'image' in posfixs:
                    use_postfix += ['.jpg', '.gif']
                elif 'script' in posfixs:
                    use_postfix += ['.js']
                else:
                    continue
            line = line.split('$')[0]
            if line.startswith("@@"):
                line = line[2:]
                use_proxy = False
            if '||' == line[:2]:
                line = line[2:]
                use_domain = True
            elif '|' == line[0]:
                line = line[1:]
                use_start = True
            if line[-1] in ('^', '|'):
                line = line[:-1]
                use_end = True
            return_proxy = 'PROXY %s' % proxy if use_proxy else default
            line = line.replace('^', '*').strip('*')
            if use_start and use_end:
                if '*' in line:
                    jsLine = 'if (shExpMatch(url, "%s")) return "%s";' % (line, return_proxy)
                else:
                    jsLine = 'if (url == "%s") return "%s";' % (line, return_proxy)
            elif use_start:
                if '*' in line:
                    if use_postfix:
                        jsCondition = ' || '.join('shExpMatch(url, "%s*%s")' % (line, x) for x in use_postfix)
                        jsLine = 'if (%s) return "%s";' % (jsCondition, return_proxy)
                    else:
                        jsLine = 'if (shExpMatch(url, "%s*")) return "%s";' % (line, return_proxy)
                else:
                    jsLine = 'if (url.indexOf("%s") == 0) return "%s";' % (line, return_proxy)
            elif use_domain and use_end:
                if '*' in line:
                    jsLine = 'if (shExpMatch(host, "%s*")) return "%s";' % (line, return_proxy)
                else:
                    jsLine = 'if (host == "%s") return "%s";' % (line, return_proxy)
            elif use_domain:
                if line.split('/')[0].count('.') <= 1:
                    jsLine = 'if (shExpMatch(url, "http://*.%s*")) return "%s";' % (line, return_proxy)
                else:
                    if '*' in line:
                        if use_postfix:
                            jsCondition = ' || '.join('shExpMatch(url, "http://%s*%s")' % (line, x) for x in use_postfix)
                            jsLine = 'if (%s) return "%s";' % (jsCondition, return_proxy)
                        else:
                            jsLine = 'if (shExpMatch(url, "http://%s*")) return "%s";' % (line, return_proxy)
                    else:
                        if use_postfix:
                            jsCondition = ' || '.join('shExpMatch(url, "http://%s*%s")' % (line, x) for x in use_postfix)
                            jsLine = 'if (%s) return "%s";' % (jsCondition, return_proxy)
                        else:
                            jsLine = 'if (url.indexOf("http://%s") == 0) return "%s";' % (line, return_proxy)
            else:
                if use_postfix:
                    jsCondition = ' || '.join('shExpMatch(url, "*%s*%s")' % (line, x) for x in use_postfix)
                    jsLine = 'if (%s) return "%s";' % (jsCondition, return_proxy)
                else:
                    jsLine = 'if (shExpMatch(url, "*%s*")) return "%s";' % (line, return_proxy)
            jsLine = ' ' * indent + jsLine
            if use_proxy:
                jsLines.append(jsLine)
            else:
                jsLines.insert(0, jsLine)
        function = 'function %s(url, host) {\r\n%s\r\n%sreturn "%s";\r\n}' % (func_name, '\n'.join(jsLines), ' '*indent, default)
        return function


class DNSUtil(object):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    """
    blacklist = set(['1.1.1.1',
                     '255.255.255.255',
                     # for google+
                     '74.125.127.102',
                     '74.125.155.102',
                     '74.125.39.102',
                     '74.125.39.113',
                     '209.85.229.138',
                     # other ip list
                     '4.36.66.178',
                     '8.7.198.45',
                     '37.61.54.158',
                     '46.82.174.68',
                     '59.24.3.173',
                     '64.33.88.161',
                     '64.33.99.47',
                     '64.66.163.251',
                     '65.104.202.252',
                     '65.160.219.113',
                     '66.45.252.237',
                     '72.14.205.104',
                     '72.14.205.99',
                     '78.16.49.15',
                     '93.46.8.89',
                     '128.121.126.139',
                     '159.106.121.75',
                     '169.132.13.103',
                     '192.67.198.6',
                     '202.106.1.2',
                     '202.181.7.85',
                     '203.161.230.171',
                     '203.98.7.65',
                     '207.12.88.98',
                     '208.56.31.43',
                     '209.145.54.50',
                     '209.220.30.174',
                     '209.36.73.33',
                     '209.85.229.138',
                     '211.94.66.147',
                     '213.169.251.35',
                     '216.221.188.182',
                     '216.234.179.13',
                     '243.185.187.3',
                     '243.185.187.39'])
    max_retry = 3
    max_wait = 3

    @staticmethod
    def _reply_to_iplist(data):
        assert isinstance(data, bytes)
        if bytes is str:
            iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
        else:
            iplist = ['.'.join(str(x) for x in s) for s in re.findall(b'\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(x <= 255 for x in s)]
        return iplist

    @staticmethod
    def is_bad_reply(data):
        assert isinstance(data, bytes)
        if bytes is str:
            iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall(b'\xc0.\x00\x01\x00\x01.{6}(.{4})', data)+re.findall(b'\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
        else:
            iplist = ['.'.join(str(x) for x in s) for s in re.findall(b'\xc0.\x00\x01\x00\x01.{6}(.{4})', data)+re.findall(b'\x00\x01\x00\x01.{6}(.{4})', data) if all(x <= 255 for x in s)]
        return any(x in DNSUtil.blacklist for x in iplist)

    @staticmethod
    def _remote_resolve(dnsserver, qname, timeout=None):
        if isinstance(dnsserver, tuple):
            dnsserver, port = dnsserver
        else:
            port = 53
        for i in range(DNSUtil.max_retry):
            data = os.urandom(2)
            data += b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            data += ''.join(chr(len(x))+x for x in qname.split('.')).encode()
            data += b'\x00\x00\x01\x00\x01'
            address_family = socket.AF_INET6 if ':' in dnsserver else socket.AF_INET
            sock = None
            try:
                if i < DNSUtil.max_retry-1:
                    # UDP mode query
                    sock = socket.socket(family=address_family, type=socket.SOCK_DGRAM)
                    sock.settimeout(timeout)
                    sock.sendto(data, (dnsserver, port))
                    for i in range(DNSUtil.max_wait):
                        data = sock.recv(512)
                        if data and not DNSUtil.is_bad_reply(data):
                            return data[2:]
                        else:
                            logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return poisoned udp data=%r', qname, dnsserver, data)
                else:
                    # TCP mode query
                    sock = socket.socket(family=address_family, type=socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((dnsserver, port))
                    data = struct.pack('>h', len(data)) + data
                    sock.send(data)
                    rfile = sock.makefile('rb', 512)
                    data = rfile.read(2)
                    if not data:
                        logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp header data=%r', qname, dnsserver, data)
                        continue
                    data = rfile.read(struct.unpack('>h', data)[0])
                    if data and not DNSUtil.is_bad_reply(data):
                        return data[2:]
                    else:
                        logging.warning('DNSUtil._remote_resolve(dnsserver=%r, %r) return bad tcp data=%r', qname, dnsserver, data)
            except (socket.error, ssl.SSLError, OSError) as e:
                if e.args[0] in (errno.ETIMEDOUT, 'timed out'):
                    continue
            except Exception as e:
                raise
            finally:
                if sock:
                    sock.close()

    @staticmethod
    def remote_resolve(dnsserver, qname, timeout=None):
        data = DNSUtil._remote_resolve(dnsserver, qname, timeout)
        iplist = DNSUtil._reply_to_iplist(data or b'')
        return iplist


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

    def __init__(self, max_window=4, max_timeout=16, max_retry=4, proxy='', ssl_validate=False, ssl_obfuscate=False):
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
        self.ssl_connection_time = collections.defaultdict(float)
        self.max_timeout = max_timeout
        self.dns = {}
        self.crlf = 0
        self.proxy = proxy
        self.ssl_validate = ssl_validate or self.ssl_validate
        self.ssl_obfuscate = ssl_obfuscate or self.ssl_obfuscate
        if self.ssl_validate or self.ssl_obfuscate:
            self.ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            self.ssl_context.set_session_id(binascii.b2a_hex(os.urandom(10)))
            if hasattr(OpenSSL.SSL, 'SESS_CACHE_BOTH'):
                self.ssl_context.set_session_cache_mode(OpenSSL.SSL.SESS_CACHE_BOTH)
            else:
                try:
                    import ctypes
                    SSL_CTRL_SET_SESS_CACHE_MODE = 44
                    SESS_CACHE_BOTH = 0x3
                    ctx = ctypes.c_void_p.from_address(id(self.ssl_context)+ctypes.sizeof(ctypes.c_int)+ctypes.sizeof(ctypes.c_voidp))
                    ctypes.cdll.ssleay32.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, SESS_CACHE_BOTH, None)
                except Exception as e:
                    logging.warning('SSL_CTX_set_session_cache_mode failed: %r', e)
        else:
            self.ssl_context = None
        if self.ssl_validate:
            self.ssl_context.load_verify_locations(r'cacert.pem')
            self.ssl_context.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda c, x, e, d, ok: ok)
        if self.ssl_obfuscate:
            self.ssl_ciphers = ':'.join(x for x in self.ssl_ciphers.split(':') if random.random() > 0.5)
            self.ssl_context.set_cipher_list(self.ssl_ciphers)

    def dns_resolve(self, host, dnsserver='', ipv4_only=True):
        iplist = self.dns.get(host)
        if not iplist:
            if not dnsserver:
                iplist = list(set(socket.gethostbyname_ex(host)[-1]) - DNSUtil.blacklist)
            else:
                iplist = DNSUtil.remote_resolve(dnsserver, host, timeout=2)
            if not iplist:
                iplist = DNSUtil.remote_resolve('8.8.8.8', host, timeout=2)
            if ipv4_only:
                iplist = [ip for ip in iplist if re.match(r'\d+\.\d+\.\d+\.\d+', ip)]
            self.dns[host] = iplist = list(set(iplist))
        return iplist

    def create_connection(self, address, timeout=None, source_address=None):
        def _create_connection(address, timeout, queobj):
            sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in address[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                sock.connect(address)
                # record TCP connection time
                self.tcp_connection_time[address] = time.time() - start_time
                # put ssl socket object to output queobj
                queobj.put(sock)
            except (socket.error, ssl.SSLError, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the address
                self.tcp_connection_time[address] = self.max_timeout+random.random()
                # close tcp socket
                if sock:
                    sock.close()

        def _close_connection(count, queobj):
            for _ in range(count):
                queobj.get()
        host, port = address
        result = None
        addresses = [(x, port) for x in self.dns_resolve(host)]
        if port == 443:
            get_connection_time = lambda addr: self.ssl_connection_time.__getitem__(addr) or self.tcp_connection_time.__getitem__(addr)
        else:
            get_connection_time = self.tcp_connection_time.__getitem__
        for i in range(self.max_retry):
            window = min((self.max_window+1)//2 + i, len(addresses))
            addresses.sort(key=get_connection_time)
            addrs = addresses[:window] + random.sample(addresses, window)
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

    def create_ssl_connection(self, address, timeout=None, source_address=None):
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
                ssl_sock = ssl.wrap_socket(sock, do_handshake_on_connect=False)
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
                self.tcp_connection_time[ipaddr] = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = handshaked_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if self.ssl_validate and address[0].endswith('.appspot.com'):
                    cert = ssl_sock.getpeercert()
                    commonname = next((v for ((k, v),) in cert['subject'] if k == 'commonName'))
                    if '.google' not in commonname and not commonname.endswith('.appspot.com'):
                        raise ssl.SSLError("Host name '%s' doesn't match certificate host '%s'" % (address[0], commonname))
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
                ssl_sock = SSLConnection(self.ssl_context, sock)
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
                self.tcp_connection_time[ipaddr] = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = handshaked_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if self.ssl_validate and address[0].endswith('.appspot.com'):
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
        def _close_ssl_connection(count, queobj):
            for _ in range(count):
                queobj.get()
        host, port = address
        result = None
        create_connection = _create_ssl_connection if not self.ssl_obfuscate and not self.ssl_validate else _create_openssl_connection
        addresses = [(x, port) for x in self.dns_resolve(host)]
        for i in range(self.max_retry):
            window = min((self.max_window+1)//2 + i, len(addresses))
            addresses.sort(key=self.ssl_connection_time.__getitem__)
            addrs = addresses[:window] + random.sample(addresses, window)
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(create_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, Exception):
                    thread.start_new_thread(_close_ssl_connection, (len(addrs)-i-1, queobj))
                    return result
                else:
                    if i == 0:
                        # only output first error
                        logging.warning('create_ssl_connection to %s return %r, try again.', addrs, result)

    def create_connection_withdata(self, address, timeout=None, source_address=None, data=None):
        assert isinstance(data, str) and data
        host, port = address
        # result = None
        addresses = [(x, port) for x in self.dns_resolve(host)]
        if port == 443:
            get_connection_time = lambda addr: self.ssl_connection_time.get(addr) or self.tcp_connection_time.get(addr)
        else:
            get_connection_time = self.tcp_connection_time.get
        for i in range(self.max_retry):
            window = min((self.max_window+1)//2 + i, len(addresses))
            addresses.sort(key=get_connection_time)
            addrs = addresses[:window] + random.sample(addresses, window)
            socks = []
            for addr in addrs:
                sock = socket.socket(socket.AF_INET if ':' not in address[0] else socket.AF_INET6)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                sock.setblocking(0)
                sock.connect_ex(addr)
                socks.append(sock)
            # something happens :D
            (_, outs, _) = select.select([], socks, [], 5)
            if outs:
                sock = outs[0]
                sock.setblocking(1)
                socks.remove(sock)
                any(s.close() for s in socks)
                return sock

    def create_connection_withproxy(self, address, timeout=None, source_address=None, proxy=None):
        assert isinstance(proxy, str)
        host, port = address
        logging.debug('create_connection_withproxy connect (%r, %r)', host, port)
        _, username, password, address = ProxyUtil.parse_proxy(proxy or self.proxy)
        try:
            try:
                self.dns_resolve(host)
            except (socket.error, OSError):
                pass
            proxyhost, _, proxyport = address.rpartition(':')
            sock = socket.create_connection((proxyhost, int(proxyport)))
            hostname = random.choice(self.dns.get(host) or [host if not host.endswith('.appspot.com') else 'www.google.com'])
            request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
            if username and password:
                request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).decode().strip()
            request_data += '\r\n'
            sock.sendall(request_data)
            response = httplib.HTTPResponse(sock)
            response.begin()
            if response.status >= 400:
                logging.error('create_connection_withproxy return http error code %s', response.status)
                sock = None
            return sock
        except Exception as e:
            logging.error('create_connection_withproxy error %s', e)
            raise

    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, pongcallback=None, bitmask=None):
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
                            data = ''.join(chr(ord(x) ^ bitmask) for x in data)
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
        need_crlf = http_util.crlf
        if crlf:
            need_crlf = 1
        if need_crlf:
            request_data = 'GET / HTTP/1.1\r\n\r\n\r\n'
        else:
            request_data = ''
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.items() if k not in skip_headers)
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

        response = httplib.HTTPResponse(sock)
        try:
            response.begin()
        except httplib.BadStatusLine:
            response = None
        return response

    def request(self, method, url, payload=None, headers={}, realhost='', fullurl=False, bufsize=8192, crlf=None, return_sock=None):
        scheme, netloc, path, _, query, _ = urlparse.urlparse(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        path += '?' + query

        if 'Host' not in headers:
            headers['Host'] = host

        for i in range(self.max_retry):
            sock = None
            ssl_sock = None
            try:
                if not self.proxy:
                    if scheme == 'https':
                        ssl_sock = self.create_ssl_connection((realhost or host, port), self.max_timeout)
                        if ssl_sock:
                            sock = ssl_sock.sock
                            del ssl_sock.sock
                        else:
                            raise socket.error('timed out', 'create_ssl_connection(%r,%r)' % (realhost or host, port))
                    else:
                        sock = self.create_connection((realhost or host, port), self.max_timeout)
                else:
                    sock = self.create_connection_withproxy((realhost or host, port), port, self.max_timeout, proxy=self.proxy)
                    path = url
                    #crlf = self.crlf = 0
                    if scheme == 'https':
                        sock = SSLConnection(self.ssl_context, sock)
                        sock.set_connect_state()
                        sock.do_handshake()
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
        self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo') if self.CONFIG.has_option('listen', 'debuginfo') else 0

        self.GAE_APPIDS = re.findall(r'[\w\-\.]+', self.CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
        self.GAE_PASSWORD = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH = self.CONFIG.get('gae', 'path')
        self.GAE_PROFILE = self.CONFIG.get('gae', 'profile')
        self.GAE_CRLF = self.CONFIG.getint('gae', 'crlf')
        self.GAE_VALIDATE = self.CONFIG.getint('gae', 'validate')
        self.GAE_OBFUSCATE = self.CONFIG.getint('gae', 'obfuscate') if self.CONFIG.has_option('gae', 'obfuscate') else 0

        self.PAC_ENABLE = self.CONFIG.getint('pac', 'enable')
        self.PAC_IP = self.CONFIG.get('pac', 'ip')
        self.PAC_PORT = self.CONFIG.getint('pac', 'port')
        self.PAC_FILE = self.CONFIG.get('pac', 'file').lstrip('/')
        self.PAC_GFWLIST = self.CONFIG.get('pac', 'gfwlist')
        self.PAC_ADBLOCK = self.CONFIG.get('pac', 'adblock')
        self.PAC_EXPIRED = self.CONFIG.getint('pac', 'expired')

        self.PAAS_ENABLE = self.CONFIG.getint('paas', 'enable')
        self.PAAS_LISTEN = self.CONFIG.get('paas', 'listen')
        self.PAAS_PASSWORD = self.CONFIG.get('paas', 'password') if self.CONFIG.has_option('paas', 'password') else ''
        self.PAAS_CRLF = self.CONFIG.getint('paas', 'crlf') if self.CONFIG.has_option('paas', 'crlf') else 1
        self.PAAS_VALIDATE = self.CONFIG.getint('paas', 'validate') if self.CONFIG.has_option('paas', 'validate') else 0
        self.PAAS_FETCHSERVER = self.CONFIG.get('paas', 'fetchserver')

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
            self.GOOGLE_MODE = 'https'
            self.proxy = 'https://%s:%s@%s:%d' % (self.PROXY_USERNAME or '', self.PROXY_PASSWROD or '', self.PROXY_HOST, self.PROXY_PORT)
        else:
            self.proxy = ''

        self.GOOGLE_MODE = self.CONFIG.get(self.GAE_PROFILE, 'mode')
        self.GOOGLE_WINDOW = self.CONFIG.getint(self.GAE_PROFILE, 'window') if self.CONFIG.has_option(self.GAE_PROFILE, 'window') else 4
        self.GOOGLE_HOSTS = [x for x in self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|') if x]
        self.GOOGLE_SITES = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|') if x)
        self.GOOGLE_FORCEHTTPS = tuple('http://'+x for x in self.CONFIG.get(self.GAE_PROFILE, 'forcehttps').split('|') if x)
        self.GOOGLE_WITHGAE = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'withgae').split('|') if x)

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

        if self.CONFIG.has_section('dns'):
            self.DNS_ENABLE = self.CONFIG.getint('dns', 'enable')
            self.DNS_LISTEN = self.CONFIG.get('dns', 'listen')
            self.DNS_REMOTE = self.CONFIG.get('dns', 'remote')
            self.DNS_TIMEOUT = self.CONFIG.getint('dns', 'timeout')
            self.DNS_CACHESIZE = self.CONFIG.getint('dns', 'cachesize')
        else:
            self.DNS_ENABLE = 0

        if self.CONFIG.has_section('light'):
            self.LIGHT_ENABLE = self.CONFIG.getint('light', 'enable')
            self.LIGHT_PASSWORD = self.CONFIG.get('light', 'password')
            self.LIGHT_LISTEN = self.CONFIG.get('light', 'listen')
            self.LIGHT_SERVER = self.CONFIG.get('light', 'server')
        else:
            self.LIGHT_ENABLE = 0

        self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE = self.CONFIG.getint('love', 'enable')
        # GAEProxy Patch
        self.LOVE_TIP             = [re.sub(r'\\u([0-9a-fA-F]{4})', lambda m:unichr(int(m.group(1), 16)), x) for x in self.CONFIG.get('love','tip').split('|')]

        DictType = getattr(collections, 'OrderedDict', dict)
        self.HOSTS = DictType(self.CONFIG.items('hosts'))
        self.HOSTS_MATCH = DictType((re.compile(k).search, v) for k, v in self.HOSTS.items() if not re.search(r'\d+$', k))
        self.HOSTS_CONNECT_MATCH = DictType((re.compile(k).search, v) for k, v in self.HOSTS.items() if re.search(r'\d+$', k))

        random.shuffle(self.GAE_APPIDS)
        self.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (self.GOOGLE_MODE, self.GAE_APPIDS[0], self.GAE_PATH)

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version    : %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
        info += 'Uvent Version      : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Local Proxy        : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug INFO         : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += 'GAE Mode           : %s\n' % self.GOOGLE_MODE
        info += 'GAE Profile        : %s\n' % self.GAE_PROFILE
        info += 'GAE APPID          : %s\n' % '|'.join(self.GAE_APPIDS)
        info += 'GAE Validate       : %s\n' % self.GAE_VALIDATE if self.GAE_VALIDATE else ''
        info += 'GAE Obfuscate      : %s\n' % self.GAE_OBFUSCATE if self.GAE_OBFUSCATE else ''
        if common.PAC_ENABLE:
            info += 'Pac Server         : http://%s:%d/%s\n' % (self.PAC_IP, self.PAC_PORT, self.PAC_FILE)
            info += 'Pac File           : file://%s\n' % os.path.join(os.path.dirname(os.path.abspath(__file__)), self.PAC_FILE).replace('\\', '/')
        if common.PAAS_ENABLE:
            info += 'PAAS Listen        : %s\n' % common.PAAS_LISTEN
            info += 'PAAS FetchServer   : %s\n' % common.PAAS_FETCHSERVER
        if common.DNS_ENABLE:
            info += 'DNS Listen         : %s\n' % common.DNS_LISTEN
            info += 'DNS Remote         : %s\n' % common.DNS_REMOTE
        if common.LIGHT_ENABLE:
            info += 'LIGHT Listen       : %s\n' % common.LIGHT_LISTEN
            info += 'LIGHT Server       : %s\n' % common.LIGHT_SERVER
        info += '------------------------------------------------------\n'
        return info

common = Common()
http_util = HTTPUtil(max_window=common.GOOGLE_WINDOW, ssl_validate=common.GAE_VALIDATE or common.PAAS_VALIDATE, ssl_obfuscate=common.GAE_OBFUSCATE, proxy=common.proxy)


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


def response_replace_header(response, name, value):
    if sys.hexversion < 0x3000000:
        response.msg[name] = value
    else:
        response.header.replace_header(name, value)


def gae_urlfetch(method, url, headers, payload, fetchserver, **kwargs):
    # deflate = lambda x:zlib.compress(x)[2:-4]
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
    metadata = zlib.compress(metadata)[2:-4]
    need_crlf = 0 if fetchserver.startswith('https') else common.GAE_CRLF
    if common.GAE_OBFUSCATE:
        cookie = base64.b64encode(metadata).strip().decode()
        if not payload:
            response = http_util.request('GET', fetchserver, payload, {'Cookie': cookie}, crlf=need_crlf)
        else:
            response = http_util.request('POST', fetchserver, payload, {'Cookie': cookie, 'Content-Length': str(len(payload))}, crlf=need_crlf)
    else:
        payload = b''.join((struct.pack('!h', len(metadata)), metadata, payload))
        response = http_util.request('POST', fetchserver, payload, {'Content-Length': str(len(payload))}, crlf=need_crlf)
    response.app_status = response.status
    if response.status != 200:
        if response.status in (400, 405):
            # filter by some firewall
            common.GAE_CRLF = 0
        return response
    data = response.read(4)
    if len(data) < 4:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short leadtype data=' + data)
        return response
    response.status, headers_length = struct.unpack('!hh', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short headers data=' + data)
        return response
    response.msg = httplib.HTTPMessage(io.BytesIO(zlib.decompress(data, -zlib.MAX_WBITS)))
    return response


class RangeFetch(object):
    """Range Fetch Class"""

    maxsize = 1024*1024*4
    bufsize = 8192
    threads = 1
    waitsize = 1024*512
    urlfetch = staticmethod(gae_urlfetch)

    def __init__(self, wfile, response, method, url, headers, payload, fetchservers, password, maxsize=0, bufsize=0, waitsize=0, threads=0):
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
        any(thread.start_new_thread(self.__fetchlet, (range_queue, data_queue)) for _ in range(self.threads))
        has_peek = hasattr(data_queue, 'peek')
        peek_timeout = 90
        expect_begin = start
        while expect_begin < length-1:
            try:
                if has_peek:
                    begin, data = data_queue.peek(timeout=peek_timeout)
                    if expect_begin == begin:
                        data_queue.get()
                    elif expect_begin < begin:
                        time.sleep(0.1)
                        continue
                    else:
                        logging.error('RangeFetch Error: begin(%r) < expect_begin(%r), quit.', begin, expect_begin)
                        break
                else:
                    begin, data = data_queue.get(timeout=peek_timeout)
                    if expect_begin == begin:
                        pass
                    elif expect_begin < begin:
                        data_queue.put((begin, data))
                        time.sleep(0.1)
                        continue
                    else:
                        logging.error('RangeFetch Error: begin(%r) < expect_begin(%r), quit.', begin, expect_begin)
                        break
            except Queue.Empty:
                logging.error('data_queue peek timeout, break')
                break
            try:
                self.wfile.write(data)
                expect_begin += len(data)
            except Exception as e:
                logging.info('RangeFetch client connection aborted(%s).', e)
                break
        self._stopped = True

    def __fetchlet(self, range_queue, data_queue):
        headers = dict((k.title(), v) for k, v in self.headers.items())
        headers['Connection'] = 'close'
        while 1:
            try:
                if self._stopped:
                    return
                if data_queue.qsize() * self.bufsize > 180*1024*1024:
                    time.sleep(10)
                    continue
                try:
                    start, end, response = range_queue.get(timeout=1)
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
                else:
                    logging.error('RangeFetch %r return %s', self.url, response.status)
                    response.close()
                    #range_queue.put((start, end, None))
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
        etype, value, tb = sys.exc_info()
        if isinstance(value, NetWorkIOError) and 'bad write retry' in value.args[1]:
            etype = value = tb = None
        else:
            del etype, value, tb
            SocketServer.ThreadingTCPServer.handle_error(self, *args)


class GAEProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    bufsize = 256*1024
    first_run_lock = threading.Lock()
    urlfetch = staticmethod(gae_urlfetch)
    normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')
    normattachment = functools.partial(re.compile(r'filename=(.+?)').sub, 'filename="\\1"')

    def _update_google_iplist(self):
        if any(not re.match(r'\d+\.\d+\.\d+\.\d+', x) for x in common.GOOGLE_HOSTS):
            google_ipmap = {}
            need_resolve_remote = []
            for domain in common.GOOGLE_HOSTS:
                if not re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    try:
                        iplist = socket.gethostbyname_ex(domain)[-1]
                        if len(iplist) >= 2:
                            google_ipmap[domain] = iplist
                    except (socket.error, OSError):
                        need_resolve_remote.append(domain)
                        continue
                else:
                    google_ipmap[domain] = [domain]
            google_iplist = list(set(sum(list(google_ipmap.values()), [])))
            if len(google_iplist) < 10 or len(set(x.split('.', 1)[0] for x in google_iplist)) == 1:
                logging.warning('local google_iplist=%s is too short, try remote_resolve', google_iplist)
                need_resolve_remote += list(common.GOOGLE_HOSTS)
            for dnsserver in ('8.8.8.8', '8.8.4.4', '114.114.114.114', '114.114.115.115'):
                for domain in need_resolve_remote:
                    logging.info('resolve remote domain=%r from dnsserver=%r', domain, dnsserver)
                    try:
                        iplist = DNSUtil.remote_resolve(dnsserver, domain, timeout=3)
                        if iplist:
                            google_ipmap.setdefault(domain, []).extend(iplist)
                            logging.info('resolve remote domain=%r to iplist=%s', domain, google_ipmap[domain])
                    except (socket.error, OSError) as e:
                        logging.exception('resolve remote domain=%r dnsserver=%r failed: %s', domain, dnsserver, e)
            common.GOOGLE_HOSTS = list(set(sum(list(google_ipmap.values()), [])))
            if len(common.GOOGLE_HOSTS) == 0:
                logging.error('resolve %s domain return empty! try remote dns resovle!', common.GAE_PROFILE)
                common.GOOGLE_HOSTS = common.CONFIG.get(common.GAE_PROFILE, 'hosts').split('|')
                #sys.exit(-1)
        for appid in common.GAE_APPIDS:
            http_util.dns['%s.appspot.com' % appid] = list(set(common.GOOGLE_HOSTS))
        logging.info('resolve common.GOOGLE_HOSTS domain to iplist=%r', common.GOOGLE_HOSTS)

    def first_run(self):
        """GAEProxyHandler setup, init domain/iplist map"""
        if common.GAE_PROFILE == 'google_ipv6' or common.PROXY_ENABLE:
            for appid in common.GAE_APPIDS:
                http_util.dns['%s.appspot.com' % appid] = list(set(common.GOOGLE_HOSTS))
        elif not common.PROXY_ENABLE:
            logging.info('resolve common.GOOGLE_HOSTS domain=%r to iplist', common.GOOGLE_HOSTS)
            if common.GAE_PROFILE == 'google_cn':
                hosts = ('www.google.cn', 'www.g.cn')
                iplist = []
                for host in hosts:
                    try:
                        if common.DNS_ENABLE:
                            ips = DNSUtil.remote_resolve('114.114.114.114', host)
                        else:
                            ips = socket.gethostbyname_ex(host)[-1]
                        if len(ips) > 1:
                            iplist += ips
                    except (socket.error, OSError) as e:
                        logging.error('socket.gethostbyname_ex(host=%r) failed:%s', host, e)
                prefix = re.sub(r'\d+\.\d+$', '', random.choice(common.GOOGLE_HOSTS))
                iplist = [x for x in iplist if x.startswith(prefix) and re.match(r'\d+\.\d+\.\d+\.\d+', x)]
                if iplist and len(iplist) > len(hosts):
                    common.GOOGLE_HOSTS = list(set(iplist))
                # OK, let's test google_cn iplist and decide whether to switch
                need_switch = False
                sample_hosts = random.sample(list(common.GOOGLE_HOSTS), min(4, len(common.GOOGLE_HOSTS)))
                connect_timing = 0
                for host in sample_hosts:
                    try:
                        start = time.time()
                        socket.create_connection((host, 443), timeout=2).close()
                        end = time.time()
                        connect_timing += end - start
                    except (socket.error, OSError):
                        # connect failed, need switch
                        connect_timing += 2
                        need_switch = True
                        break
                average_timing = 1000 * connect_timing / len(sample_hosts)
                if average_timing > 768:
                    # avg connect time large than 768 ms, need switch
                    need_switch = True
                logging.info('speedtest google_cn iplist average_timing=%0.2f ms, need_switch=%r', average_timing, need_switch)
                if need_switch:
                    common.GAE_PROFILE = 'google_hk'
                    common.GOOGLE_MODE = 'https'
                    common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                    http_util.max_window = common.GOOGLE_WINDOW = common.CONFIG.getint('google_hk', 'window')
                    common.GOOGLE_HOSTS = list(set(x for x in common.CONFIG.get(common.GAE_PROFILE, 'hosts').split('|') if x))
                    common.GOOGLE_WITHGAE = tuple(common.CONFIG.get('google_hk', 'withgae').split('|'))
            self._update_google_iplist()

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
        self.parsed_url = urlparse.urlparse(self.path)

        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING

        ### rules match algorithm, need_forward= True or False
        need_forward = False
        if common.HOSTS_MATCH and any(x(self.path) for x in common.HOSTS_MATCH) or self.command not in ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH'):
            need_forward = True
        elif host.endswith(common.GOOGLE_SITES) and not host.endswith(common.GOOGLE_WITHGAE):
            if self.path.startswith(('http://www.google.com/url', 'http://www.google.com.hk/url', 'https://www.google.com/url', 'https://www.google.com.hk/url')):
                urls = urlparse.parse_qs(self.parsed_url.query).get('url')
                if urls:
                    logging.debug('google search redirect to %s', urls[0])
                    self.wfile.write(('HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % urls[0]).encode())
                    return
            elif self.path.startswith(common.GOOGLE_FORCEHTTPS):
                self.wfile.write(('HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % self.path.replace('http://', 'https://', 1)).encode())
                return
            else:
                if host not in http_util.dns:
                    #http_util.dns[host] = http_util.dns.default_factory(http_util.dns_resolve(host))
                    http_util.dns[host] = list(set(common.GOOGLE_HOSTS))
                need_forward = True

        if need_forward:
            self.do_METHOD_FWD()
        else:
            self.do_METHOD_GAE()

    def do_METHOD_FWD(self):
        """Direct http forward"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            payload = self.rfile.read(content_length) if content_length else b''
            if common.HOSTS_MATCH and any(x(self.path) for x in common.HOSTS_MATCH):
                realhost = next(common.HOSTS_MATCH[x] for x in common.HOSTS_MATCH if x(self.path)) or re.sub(r':\d+$', '', self.parsed_url.netloc)
                logging.debug('hosts pattern mathed, url=%r realhost=%r', self.path, realhost)
                response = http_util.request(self.command, self.path, payload, self.headers, realhost=realhost, crlf=common.GAE_CRLF)
            else:
                response = http_util.request(self.command, self.path, payload, self.headers, crlf=common.GAE_CRLF)
            if not response:
                return
            logging.info('%s "FWD %s %s HTTP/1.1" %s %s', self.address_string(), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
            if response.status in (400, 405):
                common.GAE_CRLF = 0
            self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
            while 1:
                data = response.read(8192)
                if not data:
                    break
                self.wfile.write(data)
            response.close()
        except NetWorkIOError as e:
            if e.args[0] in (errno.ECONNRESET, 10063, errno.ENAMETOOLONG):
                logging.warn('http_util.request "%s %s" failed:%s, try addto `withgae`', self.command, self.path, e)
                common.GOOGLE_WITHGAE = tuple(list(common.GOOGLE_WITHGAE)+[re.sub(r':\d+$', '', self.parsed_url.netloc)])
            elif e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
                raise
        except Exception as e:
            host = self.headers.get('Host', '')
            logging.warn('GAEProxyHandler direct(%s) Error', host)
            raise

    def do_METHOD_GAE(self):
        """GAE http urlfetch"""
        request_headers = dict((k.title(), v) for k, v in self.headers.items())
        host = request_headers.get('Host', '')
        path = self.parsed_url.path
        range_in_query = 'range=' in self.parsed_url.query
        special_range = (any(x(host) for x in common.AUTORANGE_HOSTS_MATCH) or path.endswith(common.AUTORANGE_ENDSWITH)) and not path.endswith(common.AUTORANGE_NOENDSWITH)
        if 'Range' in request_headers:
            m = re.search('bytes=(\d+)-', request_headers['Range'])
            start = int(m.group(1) if m else 0)
            request_headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            logging.info('autorange range=%r match url=%r', request_headers['Range'], self.path)
        elif not range_in_query and special_range:
            logging.info('Found [autorange]endswith match url=%r', self.path)
            m = re.search('bytes=(\d+)-', request_headers.get('Range', ''))
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
        fetchserver = common.GAE_FETCHSERVER
        if range_in_query and special_range:
            fetchserver = re.sub(r'//\w+\.appspot\.com', '//%s.appspot.com' % random.choice(common.GAE_APPIDS), fetchserver)
        for retry in range(common.FETCHMAX_LOCAL):
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
                if response.app_status in (400, 504) or (response.app_status == 502 and common.GAE_PROFILE == 'google_cn'):
                    common.GOOGLE_MODE = 'https'
                    common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                    continue
                # appid not exists, try remove it from appid
                if response.app_status == 404:
                    if len(common.GAE_APPIDS) > 1:
                        appid = common.GAE_APPIDS.pop(0)
                        common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                        http_util.dns[urlparse.urlparse(common.GAE_FETCHSERVER).netloc] = common.GOOGLE_HOSTS
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
                        common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                        http_util.dns[urlparse.urlparse(common.GAE_FETCHSERVER).netloc] = common.GOOGLE_HOSTS
                        logging.info('Current APPID Over Quota,Auto Switch to [%s], Retrying…' % (common.GAE_APPIDS[0]))
                        self.do_METHOD_GAE()
                        return
                    else:
                        logging.error('All APPID Over Quota')
                # bad request, disable CRLF injection
                if response.app_status in (400, 405):
                    http_util.crlf = 0
                    continue
                if response.app_status == 500 and range_in_query and special_range:
                    fetchserver = re.sub(r'//\w+\.appspot\.com', '//%s.appspot.com' % random.choice(common.GAE_APPIDS), fetchserver)
                    logging.warning('500 with range in query, trying another APPID')
                    # logging.warning('Temporary fetchserver: %s -> %s' % (common.GAE_FETCHSERVER, fetchserver))
                    # retry -= 1
                    # logging.warning('retry: %s' % retry)
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
                        fetchservers = [re.sub(r'//\w+\.appspot\.com', '//%s.appspot.com' % appid, common.GAE_FETCHSERVER) for appid in common.GAE_APPIDS]
                        rangefetch = RangeFetch(self.wfile, response, self.command, self.path, self.headers, payload, fetchservers, common.GAE_PASSWORD, maxsize=common.AUTORANGE_MAXSIZE, bufsize=common.AUTORANGE_BUFSIZE, waitsize=common.AUTORANGE_WAITSIZE, threads=common.AUTORANGE_THREADS)
                        return rangefetch.fetch()
                    if response.getheader('Set-Cookie'):
                        response_replace_header(response, 'Set-Cookie', self.normcookie(response.getheader('Set-Cookie')))
                    if response.getheader('Content-Disposition') and '"' not in response.getheader('Content-Disposition'):
                        response_replace_header(response, 'Content-Disposition', self.normattachment(response.getheader('Content-Disposition')))
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
                while 1:
                    data = response.read(8192)
                    if not data:
                        response.close()
                        return
                    start += len(data)
                    self.wfile.write(data)
                    if start >= end:
                        response.close()
                        return
            except Exception as e:
                errors.append(e)
                if response:
                    response.close()
                if e.args[0] in (errno.ECONNABORTED, errno.EPIPE):
                    logging.debug('GAEProxyHandler.do_METHOD_GAE return %r', e)
                elif e.args[0] in (errno.ECONNRESET, errno.ETIMEDOUT, errno.ENETUNREACH, 11004):
                    # connection reset or timeout, switch to https
                    common.GOOGLE_MODE = 'https'
                    common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                elif e.args[0] == errno.ETIMEDOUT or isinstance(e.args[0], str) and 'timed out' in e.args[0]:
                    if content_length and accept_ranges == 'bytes':
                        # we can retry range fetch here
                        logging.warn('GAEProxyHandler.do_METHOD_GAE timed out, url=%r, content_length=%r, try again', self.path, content_length)
                        self.headers['Range'] = 'bytes=%d-%d' % (start, end)
                elif isinstance(e, NetWorkIOError) and 'bad write retry' in e.args[-1]:
                    logging.info('GAEProxyHandler.do_METHOD_GAE url=%r return %r, abort.', self.path, e)
                    return
                else:
                    logging.exception('GAEProxyHandler.do_METHOD_GAE %r return %r, try again', self.path, e)

    def do_CONNECT(self):
        """handle CONNECT cmmand, socket forward or deploy a fake cert"""
        host, _, port = self.path.rpartition(':')
        if common.HOSTS_CONNECT_MATCH and any(x(self.path) for x in common.HOSTS_CONNECT_MATCH):
            if host.endswith(common.GOOGLE_SITES) and not host.endswith(common.GOOGLE_WITHGAE):
                http_util.dns.pop(host, None)
            realhost = next(common.HOSTS_CONNECT_MATCH[x] for x in common.HOSTS_CONNECT_MATCH if x(self.path))
            if realhost:
                http_util.dns[host] = list(set(sum([socket.gethostbyname_ex(x)[-1] for x in realhost.split('|')], [])))
            self.do_CONNECT_FWD()
        elif host.endswith(common.GOOGLE_SITES) and not host.endswith(common.GOOGLE_WITHGAE):
            http_util.dns[host] = common.GOOGLE_HOSTS
            self.do_CONNECT_FWD()
        else:
            self.do_CONNECT_AGENT()

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
                    timeout = 4
                    remote = http_util.create_connection((host, port), timeout)
                    if remote is not None and data:
                        remote.sendall(data)
                        break
                    elif i == 0:
                        # only print first create_connection error
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
            remote = http_util.create_connection_withproxy((hostip, int(port)), proxy=common.proxy)
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


def paas_urlfetch(method, url, headers, payload, fetchserver, **kwargs):
    if payload:
        if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers['Content-Encoding'] = 'deflate'
        headers['Content-Length'] = str(len(payload))
    skip_headers = http_util.skip_headers
    if common.PAAS_VALIDATE:
        kwargs['validate'] = 1
    metadata = 'G-Method:%s\nG-Url:%s\n%s%s' % (method, url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v), ''.join('%s:%s\n' % (k, v) for k, v in headers.items() if k not in skip_headers))
    metadata = zlib.compress(metadata)[2:-4]
    app_payload = b''.join((struct.pack('!h', len(metadata)), metadata, payload))
    fetchserver += '?%s' % random.random()
    crlf = 0 if fetchserver.startswith('https') else common.PAAS_CRLF
    response = http_util.request('POST', fetchserver, app_payload, {'Content-Length': len(app_payload)}, crlf=crlf)
    if not response:
        raise socket.error(errno.ECONNRESET, 'urlfetch %r return None' % url)
    response.app_status = response.status
    if response.status != 200:
        if response.status in (400, 405):
            # filter by some firewall
            common.PAAS_CRLF = 0
        return response
    data = response.read(4)
    if len(data) < 4:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short leadtype data=' + data)
        return response
    response.status, headers_length = struct.unpack('!hh', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short headers data=' + data)
        return response
    response.msg = httplib.HTTPMessage(io.BytesIO(zlib.decompress(data, -zlib.MAX_WBITS)))
    return response


class PAASProxyHandler(GAEProxyHandler):

    urlfetch = staticmethod(paas_urlfetch)
    first_run_lock = threading.Lock()

    def first_run(self):
        if not common.PROXY_ENABLE:
            fetchhost = re.sub(r':\d+$', '', urlparse.urlparse(common.PAAS_FETCHSERVER).netloc)
            logging.info('resolve common.PAAS_FETCHSERVER domain=%r to iplist', fetchhost)
            fethhost_iplist = http_util.dns_resolve(fetchhost)
            if len(fethhost_iplist) == 0:
                logging.error('resolve %s domain return empty! please use ip list to replace domain list!', common.GAE_PROFILE)
                sys.exit(-1)
            http_util.dns[fetchhost] = list(set(fethhost_iplist))
            logging.info('resolve common.PAAS_FETCHSERVER domain to iplist=%r', fethhost_iplist)
        return True

    def setup(self):
        if isinstance(self.__class__.first_run, collections.Callable):
            try:
                with self.__class__.first_run_lock:
                    if isinstance(self.__class__.first_run, collections.Callable):
                        self.first_run()
                        self.__class__.first_run = None
            except NetWorkIOError as e:
                logging.error('PAASProxyHandler.first_run() return %r', e)
            except Exception as e:
                logging.exception('PAASProxyHandler.first_run() return %r', e)
        self.__class__.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        self.__class__.do_GET = self.__class__.do_METHOD
        self.__class__.do_PUT = self.__class__.do_METHOD
        self.__class__.do_POST = self.__class__.do_METHOD
        self.__class__.do_HEAD = self.__class__.do_METHOD
        self.__class__.do_DELETE = self.__class__.do_METHOD
        self.__class__.do_OPTIONS = self.__class__.do_METHOD
        self.__class__.do_CONNECT = GAEProxyHandler.do_CONNECT_AGENT
        self.setup()

    def do_METHOD(self):
        try:
            headers = dict((k.title(), v) for k, v in self.headers.items())
            host = headers.get('Host', '')
            payload = b''
            if 'Content-Length' in headers:
                try:
                    payload = self.rfile.read(int(headers.get('Content-Length', 0)))
                except NetWorkIOError as e:
                    logging.error('handle_method read payload failed:%s', e)
                    return
            response = None
            errors = []
            for _ in range(common.FETCHMAX_LOCAL):
                try:
                    kwargs = {}
                    if common.PAAS_PASSWORD:
                        kwargs['password'] = common.PAAS_PASSWORD
                    if common.PAAS_VALIDATE:
                        kwargs['validate'] = 1
                    if common.CONFIG.has_option('hosts', host):
                        kwargs['hostip'] = random.choice(http_util.dns_resolve(host))
                    response = self.urlfetch(self.command, self.path, headers, payload, common.PAAS_FETCHSERVER, **kwargs)
                    if response:
                        break
                except Exception as e:
                    errors.append(e)

            if response is None:
                html = message_html('502 PAAS URLFetch failed', 'Local PAAS URLFetch %r failed' % self.path, str(errors))
                self.wfile.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n' + html.encode('utf-8'))
                return

            logging.info('%s "PAAS %s %s HTTP/1.1" %s -', self.address_string(), self.command, self.path, response.status)
            if response.app_status in (400, 405):
                http_util.crlf = 0

            if response.getheader('Set-Cookie'):
                response_replace_header(response, 'Set-Cookie', self.normcookie(response.getheader('Set-Cookie')))
            self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))

            while 1:
                data = response.read(8192)
                if not data:
                    break
                self.wfile.write(data)
            response.close()

        except NetWorkIOError as e:
            # Connection closed before proxy return
            if e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
                raise


class PACServerHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    pacfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), common.PAC_FILE)
    onepixel = b'GIF89a\x01\x00\x01\x00\x80\xff\x00\xc0\xc0\xc0\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

    def do_CONNECT(self):
        self.wfile.write(b'HTTP/1.1 403\r\nConnection: close\r\n\r\n')

    def do_GET(self):
        filename = os.path.normpath('./' + urlparse.urlparse(self.path).path)
        if self.path.startswith(('http://', 'https://')):
            data = b'HTTP/1.1 200\r\nCache-Control: max-age=86400\r\nExpires:Oct, 01 Aug 2100 00:00:00 GMT\r\nConnection: close\r\n'
            if filename.endswith(('.jpg', '.gif', '.jpeg', '.bmp')):
                data += b'Content-Type: image/gif\r\n\r\n' + self.onepixel
            else:
                data += b'\r\n'
            self.wfile.write(data)
            logging.info('%s "%s %s HTTP/1.1" 200 -', self.address_string(), self.command, self.path)
        elif os.path.isfile(filename):
            if filename.endswith('.pac'):
                mimetype = 'text/plain'
            else:
                mimetype = 'application/octet-stream'
            if self.path.endswith('.pac?flush'):
                thread.start_new_thread(PacUtil.update_pacfile, (self.pacfile,))
            elif time.time() - os.path.getmtime(self.pacfile) > common.PAC_EXPIRED:
                thread.start_new_thread(lambda: os.utime(self.pacfile, (time.time(), time.time())) or PacUtil.update_pacfile(self.pacfile), tuple())
            self.send_file(filename, mimetype)
        else:
            self.wfile.write(b'HTTP/1.1 404\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n404 Not Found')
            logging.info('%s "%s %s HTTP/1.1" 404 -', self.address_string(), self.command, self.path)

    def send_file(self, filename, mimetype):
        logging.info('%s "%s %s HTTP/1.1" 200 -', self.address_string(), self.command, self.path)
        data = ''
        with open(filename, 'rb') as fp:
            data = fp.read()
        if data:
            self.wfile.write(('HTTP/1.1 200\r\nContent-Type: %s\r\nContent-Length: %s\r\n\r\n' % (mimetype, len(data))).encode())
            self.wfile.write(data)


class DNSServer(gevent.server.DatagramServer if gevent and hasattr(gevent.server, 'DatagramServer') else object):
    """DNS TCP Proxy based on gevent/dnslib"""

    blacklist = set(['1.1.1.1',
                     '255.255.255.255',
                     # for google+
                     '74.125.127.102',
                     '74.125.155.102',
                     '74.125.39.102',
                     '74.125.39.113',
                     '209.85.229.138',
                     # other ip list
                     '4.36.66.178',
                     '8.7.198.45',
                     '37.61.54.158',
                     '46.82.174.68',
                     '59.24.3.173',
                     '64.33.88.161',
                     '64.33.99.47',
                     '64.66.163.251',
                     '65.104.202.252',
                     '65.160.219.113',
                     '66.45.252.237',
                     '72.14.205.104',
                     '72.14.205.99',
                     '78.16.49.15',
                     '93.46.8.89',
                     '128.121.126.139',
                     '159.106.121.75',
                     '169.132.13.103',
                     '192.67.198.6',
                     '202.106.1.2',
                     '202.181.7.85',
                     '203.161.230.171',
                     '203.98.7.65',
                     '207.12.88.98',
                     '208.56.31.43',
                     '209.145.54.50',
                     '209.220.30.174',
                     '209.36.73.33',
                     '209.85.229.138',
                     '211.94.66.147',
                     '213.169.251.35',
                     '216.221.188.182',
                     '216.234.179.13',
                     '243.185.187.3',
                     '243.185.187.39'])
    dnsservers = ['8.8.8.8', '114.114.114.114']
    timeout = 2
    max_cache_size = 2000

    def __init__(self, *args, **kwargs):
        super(DNSServer, self).__init__(*args, **kwargs)
        self.dns_cache = {}

    def _dns_resolver(self, qname, qtype, qdata, dnsserver, result_queue):
        sock = gevent.socket.socket(socket.AF_INET6 if qtype == dnslib.QTYPE.AAAA else socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(qdata, (dnsserver, 53))
        sock.sendto(qdata, (dnsserver, 53))
        for _ in xrange(2):
            data, _ = sock.recvfrom(512)
            reply = dnslib.DNSRecord.parse(data)
            if any(str(x.rdata) in self.blacklist for x in reply.rr):
                logging.warning('query %r return bad rdata=%r', qname, [str(x.rdata) for x in reply.rr])
            else:
                result_queue.put(data)
                sock.close()
                break

    def handle(self, data, address):
        logging.debug('receive from %r data=%r', address, data)
        request = dnslib.DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = request.q.qtype
        if len(self.dns_cache) > self.max_cache_size:
            self.dns_cache.clear()
        reply_data = self.dns_cache.get((qname, qtype))
        if not reply_data:
            result_queue = gevent.queue.Queue()
            for dnsserver in self.dnsservers:
                gevent.spawn(self._dns_resolver, qname, qtype, data, dnsserver, result_queue)
            while True:
                try:
                    data = result_queue.get(timeout=self.timeout)
                    reply_data = self.dns_cache[(qname, qtype)] = data
                    break
                except gevent.queue.Empty:
                    logging.warning('query %r timed out', qname)
                    return
        return self.sendto(data[:2] + reply_data[2:], address)


def pre_start():
    # GAEProxy Patch
    if common.GAE_APPIDS[0] == 'goagent':
        logging.critical('please edit %s to add your appid to [gae] !', common.CONFIG_FILENAME)
        sys.exit(-1)
    if common.PAC_ENABLE:
        pac_ip = ProxyUtil.get_listen_ip() if common.PAC_IP in ('', '::', '0.0.0.0') else common.PAC_IP
        url = 'http://%s:%d/%s' % (pac_ip, common.PAC_PORT, common.PAC_FILE)
        spawn_later(600, lambda x: urllib2.build_opener(urllib2.ProxyHandler({})).open(x), url)
    if common.DNS_ENABLE:
        if dnslib is None or gevent.version_info[0] < 1:
            logging.critical('GoAgent DNSServer requires dnslib and gevent 1.0')
            sys.exit(-1)
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

    if common.PAC_ENABLE:
        server = LocalProxyServer((common.PAC_IP, common.PAC_PORT), PACServerHandler)
        thread.start_new_thread(server.serve_forever, tuple())

    if common.DNS_ENABLE:
        host, port = common.DNS_LISTEN.split(':')
        server = DNSServer((host, int(port)))
        server.dnsservers = common.DNS_REMOTE.split('|')
        server.timeout = common.DNS_TIMEOUT
        server.max_cache_size = common.DNS_CACHESIZE
        thread.start_new_thread(server.serve_forever, tuple())

    # GAEProxy Patch
    if common.LIGHT_ENABLE:
        host, port = common.LIGHT_LISTEN.split(':')
        server = LocalProxyServer((host, int(port)), LightProxyHandler())
        server.serve_forever()
    elif common.PAAS_ENABLE:
        host, port = common.PAAS_LISTEN.split(':')
        server = LocalProxyServer((host, int(port)), PAASProxyHandler)
        server.serve_forever()
    else:
        server = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GAEProxyHandler)
        server.serve_forever()

if __name__ == '__main__':
    main()
