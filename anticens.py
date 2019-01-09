# -*- coding: utf-8 -*-

import socket
import ssl
import time
from typing import Iterable, Dict, List

import OpenSSL.SSL
import requests

_real_wrap_bio = ssl.SSLContext.wrap_bio
_real_set_tlsext_host_name = OpenSSL.SSL.Connection.set_tlsext_host_name
_real_getaddrinfo = socket.getaddrinfo

_hosts = set()


class _DnsCache:
    def __init__(self, address, ttl):
        self.address = address
        self.ttl = ttl
        self.timestamp = time.time()

    @property
    def is_expired(self):
        return time.time() - self.timestamp > self.ttl


class _DnsCaches:
    def __init__(self):
        # lower case host -> caches -> _DnsCache
        self._caches: Dict[str, List[_DnsCache]] = {}

    def update(self, host, addresses, ttls):
        caches = [_DnsCache(address, ttl) for address, ttl in zip(addresses, ttls)]
        self._caches[host.lower()] = caches

    def get_addresses(self, host):
        caches = self._caches.get(host.lower(), [])
        return [cache.address for cache in caches if not cache.is_expired]


_dns_caches = _DnsCaches()


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
    if server_hostname is not None and server_hostname.lower() in _hosts:
        # Don't send SNI
        server_hostname = None
        self.check_hostname = False
    return _real_wrap_bio(self, incoming, outgoing, server_side, server_hostname, session)


# For OpenSSL (used by requests)
def _my_set_tlsext_host_name(self: OpenSSL.SSL.Connection, name: bytes):
    if name.decode().lower() not in _hosts:
        _real_set_tlsext_host_name(self, name)
    # Otherwise don't send SNI


# DNS anti-poisoning
def _my_getaddrinfo(host: str, port, family=0, type=0, proto=0, flags=0):
    if host not in _hosts or host == 'cloudflare-dns.com':
        return _real_getaddrinfo(host, port, family, type, proto, flags)

    assert isinstance(port, int)

    res = []
    addresses = _dns_caches.get_addresses(host)
    if not addresses:
        # https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/
        rsp = requests.get('https://cloudflare-dns.com/dns-query',
                           {'name': host, 'type': 'A'},
                           headers={'accept': 'application/dns-json'}
                           ).json()
        addresses = []
        ttls = []
        for ans in rsp['Answer']:
            if ans['type'] in (1, 28):
                addresses.append(ans['data'])
                ttls.append(ans['TTL'])

                if ans['type'] == 1:  # A record (IPv4)
                    if family in (socket.AF_INET, socket.AF_UNSPEC):
                        res.append((socket.AF_INET, type, proto, '', (ans['data'], port)))
                    addresses.append(ans['data'])
                else:  # AAAA record (IPv6)
                    if family in (socket.AF_INET6, socket.AF_UNSPEC):
                        res.append((socket.AF_INET6, type, proto, '', (ans['data'], port, 0, 0)))
                    addresses.append(ans['data'])
        _dns_caches.update(host, addresses, ttls)
    else:
        for address in addresses:
            if ':' not in address:  # IPv4
                if family in (socket.AF_INET, socket.AF_UNSPEC):
                    res.append((socket.AF_INET, type, proto, '', (address, port)))
            else:  # IPv6
                if family in (socket.AF_INET6, socket.AF_UNSPEC):
                    res.append((socket.AF_INET6, type, proto, '', (address, port, 0, 0)))
    return res
