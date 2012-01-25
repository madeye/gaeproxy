#!/usr/bin/env python
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = '1.7.8'
__author__ = "{phus.lu,hewigovens}@gmail.com (Phus Lu and Hewig Xu)"

import sys, os, re, time, errno, binascii, zlib
import struct, random, hashlib
import fnmatch, base64, logging, ConfigParser
import thread, threading
import socket, ssl, select
import httplib, urllib2, urlparse
import BaseHTTPServer, SocketServer
try:
    import ctypes
except ImportError:
    ctypes = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

# GAEProxy Patch
logging.basicConfig(level=logging.ERROR, format='%(levelname)s - - %(asctime)s %(message)s', datefmt='[%d/%b/%Y %H:%M:%S]')

class Common(object):
    '''global config module'''
    def __init__(self):
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
		# GAEProxy Patch
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG.read('/data/data/org.gaeproxy/proxy.ini')

        self.LISTEN_IP            = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT          = self.CONFIG.getint('listen', 'port')
        self.LISTEN_VISIBLE       = self.CONFIG.getint('listen', 'visible')

        self.GAE_ENABLE           = self.CONFIG.getint('gae', 'enable')
        self.GAE_APPIDS           = self.CONFIG.get('gae', 'appid').replace('.appspot.com', '').split('|')
        self.GAE_PASSWORD         = self.CONFIG.get('gae', 'password').strip()
        self.GAE_DEBUGLEVEL       = self.CONFIG.getint('gae', 'debuglevel')
        self.GAE_PATH             = self.CONFIG.get('gae', 'path')

        self.PHP_ENABLE           = self.CONFIG.getint('php', 'enable')
        self.PHP_IP               = self.CONFIG.get('php', 'ip')
        self.PHP_PORT             = self.CONFIG.getint('php', 'port')
        self.PHP_FETCHSERVER      = self.CONFIG.get('php', 'fetchserver')

        self.PROXY_ENABLE         = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_HOST           = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT           = self.CONFIG.getint('proxy', 'port')
        self.PROXY_USERNAME       = self.CONFIG.get('proxy', 'username')
        self.PROXY_PASSWROD       = self.CONFIG.get('proxy', 'password')

        self.GOOGLE_MODE          = self.CONFIG.get('google', 'mode')
        self.GOOGLE_SITES         = tuple(self.CONFIG.get('google', 'sites').split('|'))
        self.GOOGLE_FORCEHTTPS    = frozenset(self.CONFIG.get('google', 'forcehttps').split('|'))
        self.GOOGLE_WITHGAE       = frozenset(self.CONFIG.get('google', 'withgae').split('|'))
        self.GOOGLE_HOSTS_CN      = tuple(self.CONFIG.get('google', 'cn').split('|'))
        self.GOOGLE_HOSTS_HK      = tuple(self.CONFIG.get('google', 'hk').split('|'))
        self.GOOGLE_HOSTS_IPV6    = tuple(self.CONFIG.get('google', 'ipv6').split('|'))
        self.GOOGLE_APPSPOT       = {'cn':self.GOOGLE_HOSTS_CN,'hk':self.GOOGLE_HOSTS_HK,'ipv6':self.GOOGLE_HOSTS_IPV6}[self.CONFIG.get('google', 'appspot')]
        self.GOOGLE_HOSTS         = {'cn':self.GOOGLE_HOSTS_CN,'hk':self.GOOGLE_HOSTS_HK,'ipv6':self.GOOGLE_HOSTS_IPV6}[self.CONFIG.get('google', 'hosts')]

        self.FETCHMAX_LOCAL       = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER      = self.CONFIG.get('fetchmax', 'server')

        self.AUTORANGE_HOSTS      = tuple(self.CONFIG.get('autorange', 'hosts').split('|'))
        self.AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in self.AUTORANGE_HOSTS)
        self.AUTORANGE_ENDSWITH   = tuple(self.CONFIG.get('autorange', 'endswith').split('|'))
        self.AUTORANGE_MAXSIZE    = self.CONFIG.getint('autorange', 'maxsize')

        self.USERAGENT_ENABLE     = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING     = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE          = self.CONFIG.getint('love','enable')
        self.LOVE_TIMESTAMP       = self.CONFIG.get('love', 'timestamp')
        self.LOVE_TIP             = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m:unichr(int(m.group(1),16)), self.CONFIG.get('love','tip')).split('|')

        self.HOSTS                = dict((k, v) for k, v in self.CONFIG.items('hosts') if not k.startswith('.'))
        self.HOSTS_ENDSWITH_DICT  = dict((k, v) for k, v in self.CONFIG.items('hosts') if k.startswith('.'))
        self.HOSTS_ENDSWITH_TUPLE = tuple(k for k, v in self.CONFIG.items('hosts') if k.startswith('.'))

        self.build_gae_fetchserver()
        self.PHP_FETCHHOST        = re.sub(':\d+$', '', urlparse.urlparse(self.PHP_FETCHSERVER).netloc)

    def build_gae_fetchserver(self):
        self.GAE_FETCHHOST = '%s.appspot.com' % self.GAE_APPIDS[0]
        if not self.PROXY_ENABLE:
            # append '?' to url, it can avoid china telicom/unicom AD
            self.GAE_FETCHSERVER = '%s://%s%s?' % (self.GOOGLE_MODE, self.GAE_FETCHHOST, self.GAE_PATH)
        else:
            self.GAE_FETCHSERVER = '%s://%s%s?' % (self.GOOGLE_MODE, random.choice(self.GOOGLE_APPSPOT), self.GAE_PATH)

    def proxy_basic_auth_header(self):
        return 'Proxy-Authorization: Basic %s' + base64.b64encode('%s:%s'%(self.PROXY_USERNAME, self.PROXY_PASSWROD))

    def install_opener(self):
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
        info += 'GoAgent Version : %s (python/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
        info += 'Listen Address  : %s:%d\n' % (self.LISTEN_IP,self.LISTEN_PORT)
        info += 'Local Proxy     : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug Level     : %s\n' % self.GAE_DEBUGLEVEL if self.GAE_DEBUGLEVEL else ''
        info += 'GAE Mode        : %s\n' % self.GOOGLE_MODE if self.GAE_ENABLE else ''
        info += 'GAE Area        : %s\n' % self.CONFIG.get('google', 'appspot')
        info += 'GAE APPID       : %s\n' % '|'.join(self.GAE_APPIDS)
        info += 'PHP Mode Listen : %s:%d\n' % (self.PHP_IP, self.PHP_PORT) if self.PHP_ENABLE else ''
        info += 'PHP FetchServer : %s\n' % self.PHP_FETCHSERVER if self.PHP_ENABLE else ''
        info += '------------------------------------------------------\n'
        return info

common = Common()

class MultiplexConnection(object):
    '''multiplex tcp connection class'''

    retry = 3
    timeout = 5
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
            for host in hosts:
                sock_family = socket.AF_INET6 if ':' in host else socket.AF_INET
                sock = socket.socket(sock_family, socket.SOCK_STREAM)
                sock.setblocking(0)
                #logging.debug('MultiplexConnection connect_ex (%r, %r)', host, port)
                err = sock.connect_ex((host, port))
                self._sockets.add(sock)
                socks.append(sock)
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
                break
            else:
                logging.warning('MultiplexConnection Cannot hosts %r:%r, window=%d', hosts, port, window)
        else:
            MultiplexConnection.window = min(int(round(window*1.5)), len(hostlist), self.window_max)
            MultiplexConnection.window_ack = 0
            raise RuntimeError(r'MultiplexConnection Connect hosts %s:%s fail %d times!' % (hosts, port, MultiplexConnection.retry))
    def close(self):
        for sock in self._sockets:
            try:
                sock.close()
                del sock
            except:
                pass
        del self._sockets

def socket_create_connection((host, port), timeout=None, source_address=None):
    logging.debug('socket_create_connection connect (%r, %r)', host, port)
    if host == common.GAE_FETCHHOST:
        msg = 'socket_create_connection returns an empty list'
        try:
            conn = MultiplexConnection(common.GOOGLE_APPSPOT, port)
            sock = conn.socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            return sock
        except socket.error, msg:
            logging.error('socket_create_connection connect fail: (%r, %r)', common.GOOGLE_APPSPOT, port)
            sock = None
        if not sock:
            raise socket.error, msg
    else:
        msg = 'getaddrinfo returns an empty list'
        host = common.HOSTS.get(host) or host
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
            except socket.error, msg:
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
                    except Exception, e:
                        logging.warning('socket_forward idlecall fail:%s', e)
                    finally:
                        idlecall = None
    except Exception, ex:
        logging.warning('socket_forward error=%s', ex)
        raise
    finally:
        if idlecall:
            idlecall()

_httplib_HTTPConnection_putrequest = httplib.HTTPConnection.putrequest
def httplib_HTTPConnection_putrequest(self, method, url, skip_host=0, skip_accept_encoding=1):
    return _httplib_HTTPConnection_putrequest(self, method, url, skip_host, skip_accept_encoding)
httplib.HTTPConnection.putrequest = httplib_HTTPConnection_putrequest

class CertUtil(object):
    '''CertUtil module, based on WallProxy 0.4.0'''

    CA = None
    CALock = threading.Lock()

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
    def createCertificate(req, (issuerKey, issuerCert), serial, (notBefore, notAfter), digest='sha1'):
        cert = OpenSSL.crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
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
        cert = CertUtil.createCertificate(req, (cakey, cacrt), serial, (0, 60*60*24*7305))
        return (CertUtil.dumpPEM(pkey, 0), CertUtil.dumpPEM(cert, 2))

    # GAEProxy Patch
    @staticmethod
    def getCertificate(host):
        basedir = '/data/data/org.gaeproxy'
        keyFile = os.path.join(basedir, 'LocalProxyServer.key')
        crtFile = os.path.join(basedir, 'LocalProxyServer.cert')
        return (keyFile, crtFile)

def urlfetch(url, payload, method, headers, fetchhost, fetchserver, dns=None, on_error=None):
    errors = []
    params = {'url':url, 'method':method, 'headers':headers, 'payload':payload}
    logging.debug('urlfetch params %s', params)
    if common.GAE_PASSWORD:
        params['password'] = common.GAE_PASSWORD
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
                data['headers'] = dict((k.title(), binascii.a2b_hex(v)) for k, _, v in (x.partition('=') for x in response.read(hlen).split('&')))
                data['response'] = response
            elif compressed == '1':
                rawdata = zlib.decompress(response.read())
                data['code'], hlen, clen = struct.unpack('>3I', rawdata[:12])
                data['headers'] = dict((k.title(), binascii.a2b_hex(v)) for k, _, v in (x.partition('=') for x in rawdata[12:12+hlen].split('&')))
                data['content'] = rawdata[12+hlen:12+hlen+clen]
                response.close()
            else:
                raise ValueError('Data format not match(%s)' % url)

            return (0, data)
        except Exception, e:
            if on_error:
                logging.info('urlfetch error=%s on_error=%s', str(e), str(on_error))
                data = on_error(e)
                if data:
                    fetchhost = data.get('fetchhost', fetchhost)
                    fetchserver = data.get('fetchserver', fetchserver)
            errors.append(str(e))
            time.sleep(i+1)
            continue
    return (-1, errors)

class SimpleMessageClass(object):

    def __init__(self, fp, seekable = 0):
        self.fp = fp
        self.dict = dict = {}
        readline = fp.readline
        while 1:
            line = readline(8192)
            if not line or line == '\r\n':
                break
            key, _, value = line.partition(':')
            if value:
                dict[key.title()] = value.strip()

    def getheader(self, name, default=None):
        return self.dict.get(name.title(), default)

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
        self.dict[name.title()] = value

    def __delitem__(self, name):
        del self.dict[name.title()]

    def __contains__(self, name):
        return name.title() in self.dict

    def __len__(self):
        return len(self.dict)

    def __iter__(self):
        return iter(self.dict)

    def __str__(self):
        return ''.join('%s: %s\r\n' % (k, v) for k, v in self.dict.iteritems())

class LocalProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    skip_headers = frozenset(['Host', 'Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'Keep-Alive'])
    SetupLock = threading.Lock()
    MessageClass = SimpleMessageClass
    rangefetch_bufsize = 8192

    def handle_fetch_error(self, error):
        if isinstance(error, urllib2.HTTPError):
            # seems that current appid is over qouta, swith to next appid
            if error.code == 503:
                common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                logging.info('APPSPOT 503 Error, switch to next fetchserver: %r', common.GAE_APPIDS[0])
            # seems that www.google.cn:80 is down, switch to https
            if error.code in (502, 504):
                common.GOOGLE_MODE = 'https'
        elif isinstance(error, urllib2.URLError):
            if error.reason[0] in (11004, 10051, 10054, 10060, 'timed out'):
                # it seems that google.cn is reseted, switch to https
                common.GOOGLE_MODE = 'https'
        elif isinstance(error, httplib.HTTPException):
            common.GOOGLE_MODE = 'https'
        else:
            logging.warning('LocalProxyHandler.handle_fetch_error Exception %s', error, exc_info=True)
            return {}
        common.build_gae_fetchserver()
        sys.stdout.write(common.info())
        return {'fetchhost':common.GAE_FETCHHOST, 'fetchserver':common.GAE_FETCHSERVER}

    def fetch(self, url, payload, method, headers):
        return urlfetch(url, payload, method, headers, common.GAE_FETCHHOST, common.GAE_FETCHSERVER, on_error=self.handle_fetch_error)

    def rangefetch(self, m, data):
        m = map(int, m.groups())
        start = m[1] + 1
        end   = m[2] - 1
        if m[0] == 0:
            data['code'] = 200
            del data['headers']['Content-Range']
            data['headers']['Content-Length'] = m[2]
        elif 'Range' in self.headers:
            req_range = re.search(r'(\d+)?-(\d+)?', self.headers['Range'])
            if req_range:
                req_range = [u and int(u) for u in req_range.groups()]
                if req_range[0] is None and req_range[1] is not None:
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
            data['headers']['Content-Range'] = 'bytes %d-%d/%d' % (start,  m[2]-1, m[2])
        else:
            pass

        self.connection.sendall('%s %d %s\r\n%s\r\n' % (self.protocol_version, data['code'], 'OK', ''.join('%s: %s\r\n' % (k, v) for k, v in data['headers'].iteritems())))
        if 'response' in data:
            response = data['response']
            bufsize = -1 if data['headers'].get('Content-Type', '').startswith('video/') else self.rangefetch_bufsize
            #logging.debug('bufsize=%r, Content-Type=%r' % (bufsize, data['headers'].get('Content-Type')))
            while 1:
                content = response.read(bufsize)
                if not content:
                    response.close()
                    break
                self.connection.sendall(content)
        else:
            self.connection.sendall(data['content'])

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
                    content = response.read(self.rangefetch_bufsize)
                    if not content:
                        response.close()
                        break
                    self.connection.sendall(content)
            else:
                self.connection.sendall(data['content'])
        logging.info('>>>>>>>>>>>>>>> Range Fetch ended(%r)', self.headers.get('Host'))
        return True

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

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
        if not common.GAE_ENABLE:
            LocalProxyHandler.do_CONNECT = LocalProxyHandler.do_CONNECT_Direct
            LocalProxyHandler.do_METHOD  = LocalProxyHandler.do_METHOD_Direct
        LocalProxyHandler.do_GET     = LocalProxyHandler.do_METHOD
        LocalProxyHandler.do_POST    = LocalProxyHandler.do_METHOD
        LocalProxyHandler.do_PUT     = LocalProxyHandler.do_METHOD
        LocalProxyHandler.do_DELETE  = LocalProxyHandler.do_METHOD
        LocalProxyHandler.do_OPTIONS = LocalProxyHandler.do_METHOD
        LocalProxyHandler.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(':')
        if host.endswith(common.GOOGLE_SITES) and host not in common.GOOGLE_WITHGAE:
            return self.do_CONNECT_Direct()
        elif host in common.HOSTS:
            return self.do_CONNECT_Direct()
        elif common.HOSTS_ENDSWITH_TUPLE and host.endswith(common.HOSTS_ENDSWITH_TUPLE):
            ip = (ip for p, ip in common.HOSTS_ENDSWITH_DICT.iteritems() if host.endswith(p)).next()
            if not ip and not common.PROXY_ENABLE:
                logging.info('try resolve %r', host)
                ip = socket.gethostbyname(host)
            common.HOSTS[host] = ip
            self.do_CONNECT_Direct()
        else:
            return self.do_CONNECT_Thunnel()

    def do_CONNECT_Direct(self):
        try:
            logging.debug('LocalProxyHandler.do_CONNECT_Directt %s' % self.path)
            host, _, port = self.path.rpartition(':')
            idlecall = None
            if not common.PROXY_ENABLE:
                if host.endswith(common.GOOGLE_SITES):
                    conn = MultiplexConnection(common.GOOGLE_HOSTS, int(port))
                    sock = conn.socket
                    idlecall=conn.close
                else:
                    sock = socket.create_connection((host, int(port)))
                self.log_request(200)
                self.connection.sendall('%s 200 Tunnel established\r\n\r\n' % self.protocol_version)
            else:
                sock = socket.create_connection((common.PROXY_HOST, common.PROXY_PORT))
                if host.endswith(common.GOOGLE_SITES):
                    ip = random.choice(common.GOOGLE_HOSTS)
                else:
                    ip = random.choice(common.HOSTS.get(host, host)[0])
                data = '%s %s:%s %s\r\n' % (self.command, ip, port, self.protocol_version)
                data += ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.iteritems() if k != 'Host')
                if common.PROXY_USERNAME:
                    data += '%s\r\n' % common.proxy_basic_auth_header()
                data += '\r\n'
                sock.sendall(data)
            socket_forward(self.connection, sock, idlecall=idlecall)
        except:
            logging.exception('LocalProxyHandler.do_CONNECT_Direct Error')
        finally:
            try:
                sock.close()
                del sock
            except:
                pass

    def do_CONNECT_Thunnel(self):
        # for ssl proxy
        host, _, port = self.path.rpartition(':')
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
                self.path = 'https://%s%s' % (self._realpath, self.path)
                self.requestline = '%s %s %s' % (self.command, self.path, self.protocol_version)
            self.do_METHOD_Thunnel()
        except socket.error, e:
            logging.exception('do_CONNECT_Thunnel socket.error: %s', e)
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
            return self.do_METHOD_Direct()
        elif host in common.HOSTS:
            return self.do_METHOD_Direct()
        elif common.HOSTS_ENDSWITH_TUPLE and host.endswith(common.HOSTS_ENDSWITH_TUPLE):
            ip = (ip for p, ip in common.HOSTS_ENDSWITH_DICT.iteritems() if host.endswith(p)).next()
            if not ip and not common.PROXY_ENABLE:
                ip = socket.gethostbyname(host)
            common.HOSTS[host] = ip
            self.do_METHOD_Direct()
        else:
            return self.do_METHOD_Thunnel()

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
                if host.endswith(common.GOOGLE_SITES):
                    conn = MultiplexConnection(common.GOOGLE_HOSTS, port)
                    sock = conn.socket
                    idlecall = conn.close
                else:
                    sock = socket.create_connection((host, port))
                self.headers['Connection'] = 'close'
                data = '%s %s %s\r\n'  % (self.command, urlparse.urlunparse(('', '', path, params, query, '')), self.request_version)
                data += ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.iteritems() if not k.startswith('Proxy-'))
                data += '\r\n'
            else:
                sock = socket.create_connection((common.PROXY_HOST, common.PROXY_PORT))
                if host.endswith(common.GOOGLE_SITES):
                    host = random.choice(common.GOOGLE_HOSTS)
                else:
                    host = common.HOSTS.get(host, host)
                url = urlparse.urlunparse((scheme, host + ('' if port == 80 else ':%d' % port), path, params, query, ''))
                data ='%s %s %s\r\n'  % (self.command, url, self.request_version)
                data += ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.iteritems() if k != 'Host')
                data += 'Host: %s\r\n' % netloc
                if common.PROXY_USERNAME:
                    data += '%s\r\n' % common.proxy_basic_auth_header()
                data += 'Proxy-Connection: close\r\n'
                data += '\r\n'

            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                data += self.rfile.read(content_length)
            sock.sendall(data)
            socket_forward(self.connection, sock, idlecall=idlecall)
        except Exception, ex:
            logging.exception('LocalProxyHandler.do_GET Error, %s', ex)
        finally:
            try:
                sock.close()
                del sock
            except:
                pass

    def do_METHOD_Thunnel(self):
        headers = self.headers
        host = headers.get('Host') or urlparse.urlparse(self.path).netloc.partition(':')[0]
        if self.path[0] == '/':
            self.path = 'http://%s%s' % (host, self.path)
        payload_len = int(headers.get('Content-Length', 0))
        if payload_len > 0:
            payload = self.rfile.read(payload_len)
        else:
            payload = ''

        if common.USERAGENT_ENABLE:
            headers['User-Agent'] = common.USERAGENT_STRING

        if host.endswith(common.AUTORANGE_HOSTS_TAIL):
            for pattern in common.AUTORANGE_HOSTS:
                if host.endswith(pattern) or fnmatch.fnmatch(host, pattern):
                    logging.debug('autorange pattern=%r match url=%r', pattern, self.path)
                    m = re.search('bytes=(\d+)-', headers.get('Range', ''))
                    start = int(m.group(1) if m else 0)
                    headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
                    break

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
            content = '%s %d %s\r\n%s\r\n' % (self.protocol_version, code, self.responses.get(code, ('GoAgent Notify', ''))[0], ''.join('%s: %s\r\n' % (k, v) for k, v in headers.iteritems()))
            self.connection.sendall(content)
            try:
                self.connection.sendall(data['content'])
            except KeyError:
                #logging.info('OOPS, KeyError! Content-Type=%r', headers.get('Content-Type'))
                response = data['response']
                while 1:
                    content = response.read(self.rangefetch_bufsize)
                    if not content:
                        response.close()
                        break
                    self.connection.sendall(content)
            if 'close' == headers.get('Connection',''):
                self.close_connection = 1
        except socket.error, (err, _):
            # Connection closed before proxy return
            if err in (10053, errno.EPIPE):
                return

class PHPProxyHandler(LocalProxyHandler):

    def handle_fetch_error(self, error):
        logging.error('PHPProxyHandler handle_fetch_error %s', error)

    def fetch(self, url, payload, method, headers):
        dns = common.HOSTS.get(self.headers.get('Host'))
        return urlfetch(url, payload, method, headers, common.PHP_FETCHHOST, common.PHP_FETCHSERVER, dns=dns, on_error=self.handle_fetch_error)

    def setup(self):
        if common.PROXY_ENABLE:
            logging.info('Local Proxy is enable, PHPProxyHandler dont resole DNS')
        else:
            logging.info('PHPProxyHandler.setup check %s is in common.HOSTS', common.PHP_FETCHHOST)
            if common.PHP_FETCHHOST not in common.HOSTS:
                with LocalProxyHandler.SetupLock:
                    if common.PHP_FETCHHOST not in common.HOSTS:
                        try:
                            logging.info('Resole php fetchserver address.')
                            common.HOSTS[common.PHP_FETCHHOST] = socket.gethostbyname(common.PHP_FETCHHOST)
                            logging.info('Resole php fetchserver address OK. %s', common.HOSTS[common.PHP_FETCHHOST])
                        except Exception, e:
                            logging.exception('PHPProxyHandler.setup resolve fail: %s', e)
        PHPProxyHandler.do_CONNECT = LocalProxyHandler.do_CONNECT_Thunnel
        PHPProxyHandler.do_GET     = LocalProxyHandler.do_METHOD_Thunnel
        PHPProxyHandler.do_POST    = LocalProxyHandler.do_METHOD_Thunnel
        PHPProxyHandler.do_PUT     = LocalProxyHandler.do_METHOD_Thunnel
        PHPProxyHandler.do_DELETE  = LocalProxyHandler.do_METHOD_Thunnel
        PHPProxyHandler.setup      = BaseHTTPServer.BaseHTTPRequestHandler.setup
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

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
            with open('proxy.ini', 'w') as fp:
                common.CONFIG.set('love', 'timestamp', int(time.time()))
                common.CONFIG.write(fp)
        if time.time() - common.LOVE_TIMESTAMP > 86400 and random.randint(1,10) > 5:
            title = ctypes.create_unicode_buffer(1024)
            GetConsoleTitleW(ctypes.byref(title), len(title)-1)
            SetConsoleTitleW(u'%s %s' % (title.value, random.choice(common.LOVE_TIP)))
            with open('proxy.ini', 'w') as fp:
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
        
    if ctypes and os.name == 'nt':
        ctypes.windll.kernel32.SetConsoleTitleW(u'GoAgent v%s' % __version__)
        if not common.LOVE_TIMESTAMP.strip():
            print(u'\u53cc\u51fb addto-startup.vbs \u53ef\u4ee5\u628agoagent.exe\u52a0\u5165\u5230\u542f\u52a8\u9879\u3002'.encode('mbcs'))
        try_show_love()
        if not common.LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    if common.GAE_DEBUGLEVEL:
        logging.root.setLevel(logging.DEBUG)
        
    # GAEProxy Patch
    # CertUtil.checkCA()
    
    common.install_opener()
    sys.stdout.write(common.info())
    LocalProxyServer.address_family = (socket.AF_INET, socket.AF_INET6)[':' in common.LISTEN_IP]

    # GAEProxy Patch
    pid = str(os.getpid())
    f = open('/data/data/org.gaeproxy/python.pid','a')
    f.write(" ")
    f.write(pid)
    f.close()

    if common.PHP_ENABLE:
        httpd = LocalProxyServer((common.PHP_IP, common.PHP_PORT), PHPProxyHandler)
        thread.start_new_thread(httpd.serve_forever, ())
    httpd = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), LocalProxyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
   try:
       main()
   except KeyboardInterrupt:
       pass