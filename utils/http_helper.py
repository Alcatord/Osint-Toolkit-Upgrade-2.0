#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import socket

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def get_session(proxy=None):
    s = requests.Session()
    s.headers.update(HEADERS)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def http_get(url, timeout=10, proxy=None, headers=None):
    s = get_session(proxy)
    if headers:
        s.headers.update(headers)
    try:
        return s.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None


def http_get_json(url, timeout=10, proxy=None):
    r = http_get(url, timeout=timeout, proxy=proxy,
                 headers={"Accept": "application/json"})
    if r and r.status_code == 200:
        try:
            return r.json()
        except Exception:
            return None
    return None


def check_url_exists(url, timeout=8, proxy=None):
    s = get_session(proxy)
    try:
        r = s.head(url, timeout=timeout, allow_redirects=True)
        return r.status_code, r.url
    except Exception:
        pass
    try:
        r = s.get(url, timeout=timeout, allow_redirects=True, stream=True)
        return r.status_code, r.url
    except Exception:
        return None, None


def resolve_hostname(hostname, timeout=5):
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(hostname, None)
        return list(set(r[4][0] for r in results))
    except Exception:
        return []