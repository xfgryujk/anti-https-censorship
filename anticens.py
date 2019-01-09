# -*- coding: utf-8 -*-

import socket
import ssl
from typing import Iterable

import OpenSSL.SSL
import requests

_real_wrap_bio = ssl.SSLContext.wrap_bio
_real_set_tlsext_host_name = OpenSSL.SSL.Connection.set_tlsext_host_name
_real_getaddrinfo = socket.getaddrinfo

_hosts = set()


def add_hosts(hosts: Iterable[str]):
    _hosts.update((host.lower() for host in hosts))


def enable():
    ssl.SSLContext.wrap_bio = _my_wrap_bio
    OpenSSL.SSL.Connection.set_tlsext_host_name = _my_set_tlsext_host_name
    socket.getaddrinfo = _my_getaddrinfo


def disable():
    socket.getaddrinfo = _real_getaddrinfo
    OpenSSL.SSL.Connection.set_tlsext_host_name = _real_set_tlsext_host_name
    ssl.SSLContext.wrap_bio = _real_wrap_bio


# For ssl (used by aiohttp)
def _my_wrap_bio(self: ssl.SSLContext, incoming, outgoing, server_side=False,
                 server_hostname: str=None, session=None):
    if server_hostname.lower() in _hosts:
        # Don't send SNI
        server_hostname = None
        self.check_hostname = False
    return _real_wrap_bio(self, incoming, outgoing, server_side, server_hostname, session)


# For OpenSSL (used by requests)
def _my_set_tlsext_host_name(self: OpenSSL.SSL.Connection, name: bytes):
    if name.decode().lower() not in _hosts:
        _real_set_tlsext_host_name(self, name)
    # Otherwise don't send SNI


def _my_getaddrinfo(host: str, port, family=0, type=0, proto=0, flags=0):
    if host not in _hosts or host == 'cloudflare-dns.com':
        return _real_getaddrinfo(host, port, family, type, proto, flags)

    # TODO Improve it. It's just a PoC now
    # DNS anti-poisoning
    # https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
    rsp = requests.get('https://cloudflare-dns.com/dns-query',
                       {'name': host, 'type': 'A'},
                       headers={'accept': 'application/dns-json'}
                       ).json()
    for ans in rsp['Answer']:
        if ans['type'] == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
                    (ans['data'], port))]
    return []
