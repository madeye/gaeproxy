#! /usr/bin/env python
# coding=utf-8
#############################################################################
#                                                                           #
#   File: common.py                                                         #
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

import os, sys

def we_are_frozen():
    """Returns whether we are frozen via py2exe.
    This will affect how we find out where we are located."""

    return hasattr(sys, "frozen")

def module_path():
    """ This will get us the program's directory,
    even if we are frozen using py2exe"""

    if we_are_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(__file__)

dir = module_path()

VERSION = "2.0.0"

LOAD_BALANCE = 'http://gappproxy-center.appspot.com/available_fetchserver.py'
GOOGLE_PROXY = 'www.google.cn:80'

DEF_LISTEN_PORT = 8000
DEF_LOCAL_PROXY = ''
DEF_FETCH_SERVER = ''
DEF_CONF_FILE = os.path.join(dir, 'proxy.conf')
DEF_CERT_FILE = os.path.join(dir, 'LocalProxyServer.cert')
DEF_KEY_FILE  = os.path.join(dir, 'LocalProxyServer.key')

class GAppProxyError(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return '<GAppProxy Error: %s>' % self.reason
