#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import ipaddress


class InputDetector:
    def detect(self, target: str) -> str:
        t = target.strip()
        if re.match(r"https?://", t, re.I):
            return "url"
        if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", t):
            return "email"
        try:
            ipaddress.ip_address(t)
            return "ip"
        except ValueError:
            pass
        if re.match(r"^[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+$", t) and " " not in t:
            return "domain"
        if " " in t and re.search(r"[a-zA-Z\u0600-\u06FF]", t):
            return "person"
        if re.match(r"^[a-zA-Z0-9_.\-]+$", t) and len(t) >= 2:
            return "username"
        return "username"