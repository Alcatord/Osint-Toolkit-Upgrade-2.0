#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
محلل النطاقات
- DNS Records (A, MX, NS, TXT)
- WHOIS عبر RDAP (بدون مكتبة خارجية)
- SSL/TLS معلومات الشهادة
- اكتشاف النطاقات الفرعية عبر crt.sh
- Wayback Machine (أرشيف)
- IP Geolocation
"""

import socket
import ssl
import json
import re
from datetime import datetime
from urllib.parse import urlparse
from utils.http_helper import http_get_json, http_get, resolve_hostname


class DomainAnalyzer:
    def __init__(self, display, config):
        self.display = display
        self.config  = config
        self.timeout = config.get("timeout", 10)
        self.proxy   = config.get("proxy")
        self.verbose = config.get("verbose", False)

    def analyze(self, target: str) -> dict:
        d      = self.display
        domain = self._extract_domain(target)
        d.section(f"تحليل النطاق: {domain}")

        results = {
            "domain":      domain,
            "found_count": 0,
            "dns":         {},
            "whois":       {},
            "ssl":         {},
            "subdomains":  [],
            "geo":         {},
            "wayback":     {},
            "tech_hints":  [],
        }

        # 1. DNS Resolution
        d.info("حل DNS وجلب الـ IP...")
        dns = self._get_dns(domain)
        results["dns"] = dns
        if dns.get("a_records"):
            d.success(f"IP: {', '.join(dns['a_records'])}")
            results["found_count"] += 1
        else:
            d.warning("تعذر حل DNS للنطاق")

        # 2. DNS Records (MX, NS, TXT)
        d.info("جلب سجلات DNS (MX, NS, TXT)...")
        extra_dns = self._get_extra_dns(domain)
        results["dns"].update(extra_dns)
        if extra_dns.get("mx"):
            d.success(f"MX: {', '.join(extra_dns['mx'][:2])}")
        if extra_dns.get("ns"):
            d.success(f"NS: {', '.join(extra_dns['ns'][:2])}")

        # 3. WHOIS via RDAP
        d.info("جلب بيانات WHOIS (RDAP)...")
        whois = self._get_whois_rdap(domain)
        results["whois"] = whois
        if whois.get("registrar"):
            d.success(f"المُسجِّل: {whois['registrar']}")
            d.key_value("  تاريخ التسجيل", whois.get("created", "؟"), indent=1)
            d.key_value("  تاريخ الانتهاء", whois.get("expires", "؟"), indent=1)
            results["found_count"] += 1
        else:
            d.warning("تعذر جلب بيانات WHOIS")

        # 4. SSL Certificate
        d.info("فحص شهادة SSL...")
        ssl_info = self._get_ssl_info(domain)
        results["ssl"] = ssl_info
        if ssl_info.get("valid"):
            d.success(f"SSL صالحة — تنتهي: {ssl_info.get('expires','؟')}")
            d.key_value("  الجهة المُصدِرة", ssl_info.get("issuer", "؟"), indent=1)
            results["found_count"] += 1
        elif ssl_info.get("error"):
            d.warning(f"SSL: {ssl_info['error']}")
        else:
            d.not_found("لا توجد شهادة SSL")

        # 5. Subdomains via crt.sh
        d.info("اكتشاف النطاقات الفرعية (crt.sh)...")
        subdomains = self._get_subdomains(domain)
        results["subdomains"] = subdomains
        if subdomains:
            d.success(f"تم اكتشاف {len(subdomains)} نطاق فرعي")
            results["found_count"] += len(subdomains)
        else:
            d.not_found("لم يتم اكتشاف نطاقات فرعية")

        # 6. Geo للـ IP الرئيسي
        if dns.get("a_records"):
            d.info("جلب الموقع الجغرافي للـ IP...")
            geo = self._get_ip_geo(dns["a_records"][0])
            results["geo"] = geo
            if geo.get("country"):
                d.success(f"الموقع: {geo.get('city','?')}, {geo.get('country','?')}")

        # 7. Wayback Machine
        d.info("فحص أرشيف Wayback Machine...")
        wayback = self._get_wayback(domain)
        results["wayback"] = wayback
        if wayback.get("available"):
            d.success(f"متوفر في الأرشيف — آخر نسخة: {wayback.get('last_snapshot','؟')}")
            results["found_count"] += 1
        else:
            d.not_found("غير متوفر في أرشيف Wayback")

        # ── جدول ملخص ────────────────────────────────────
        d.section("ملخص النطاق")
        rows = [
            ["IP الرئيسي",    dns.get("a_records", ["؟"])[0] if dns.get("a_records") else "؟"],
            ["المُسجِّل",      whois.get("registrar", "؟")],
            ["تاريخ التسجيل", whois.get("created", "؟")],
            ["تاريخ الانتهاء",whois.get("expires", "؟")],
            ["SSL",           "✓ صالحة" if ssl_info.get("valid") else "✗ غير متاحة"],
            ["النطاقات الفرعية", str(len(subdomains))],
            ["أرشيف",         "✓ متوفر" if wayback.get("available") else "✗"],
        ]
        d.table(["العنصر", "القيمة"], rows)

        if subdomains:
            d.section(f"النطاقات الفرعية ({len(subdomains)})")
            rows = [[s] for s in subdomains[:20]]
            d.table(["النطاق الفرعي"], rows)
            if len(subdomains) > 20:
                d.info(f"... و {len(subdomains)-20} نطاق فرعي إضافي في التقرير")

        return {"domain_analysis": results}

    # ──────────────────────────────────────────────────────
    def _extract_domain(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return parsed.netloc.split(":")[0]
        return target.strip().split("/")[0].split(":")[0]

    def _get_dns(self, domain: str) -> dict:
        result = {"a_records": [], "ipv6": []}
        try:
            # IPv4
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            result["a_records"] = list(set(i[4][0] for i in infos))
        except Exception:
            pass
        try:
            # IPv6
            infos6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
            result["ipv6"] = list(set(i[4][0] for i in infos6))
        except Exception:
            pass
        return result

    def _get_extra_dns(self, domain: str) -> dict:
        result = {"mx": [], "ns": [], "txt": []}
        # DNS over HTTPS - Google
        base = "https://dns.google/resolve"

        for rtype, key in [("MX", "mx"), ("NS", "ns"), ("TXT", "txt")]:
            data = http_get_json(
                f"{base}?name={domain}&type={rtype}",
                timeout=self.timeout,
                proxy=self.proxy
            )
            if data and data.get("Answer"):
                records = []
                for ans in data["Answer"]:
                    val = ans.get("data", "").strip().rstrip(".")
                    # MX: أخذ الجزء الثاني فقط (الاسم بدون الأولوية)
                    if rtype == "MX":
                        parts = val.split()
                        val   = parts[1].rstrip(".") if len(parts) >= 2 else val
                    if val and val not in records:
                        records.append(val)
                result[key] = records[:5]

        return result

    def _get_whois_rdap(self, domain: str) -> dict:
        result = {}
        # RDAP - لا يحتاج مكتبة خارجية
        tld    = domain.split(".")[-1]
        endpoints = [
            f"https://rdap.org/domain/{domain}",
            f"https://rdap.verisign.com/com/v1/domain/{domain}",
        ]

        for endpoint in endpoints:
            data = http_get_json(endpoint, timeout=self.timeout, proxy=self.proxy)
            if not data:
                continue

            # استخراج المُسجِّل
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if vcard and len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                result["registrar"] = item[3]
                                break

            # استخراج التواريخ
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date   = event.get("eventDate", "")
                if "registration" in action:
                    result["created"] = date[:10] if date else ""
                elif "expiration" in action:
                    result["expires"] = date[:10] if date else ""
                elif "last changed" in action or "last update" in action:
                    result["updated"] = date[:10] if date else ""

            # DNSSEC
            result["dnssec"] = data.get("secureDNS", {}).get("delegationSigned", False)

            # حالة النطاق
            result["status"] = data.get("status", [])

            if result:
                break

        return result

    def _get_ssl_info(self, domain: str) -> dict:
        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=self.timeout),
                server_hostname=domain
            )
            cert = conn.getpeercert()
            conn.close()

            # تاريخ الانتهاء
            expires_str = cert.get("notAfter", "")
            expires     = ""
            if expires_str:
                try:
                    dt      = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
                    expires = dt.strftime("%Y-%m-%d")
                    valid   = dt > datetime.now()
                except Exception:
                    valid   = True

            # الجهة المُصدِرة
            issuer = {}
            for item in cert.get("issuer", []):
                if item:
                    issuer[item[0][0]] = item[0][1]

            # SANs (Subject Alternative Names)
            sans = []
            for ext in cert.get("subjectAltName", []):
                if ext[0] == "DNS":
                    sans.append(ext[1])

            return {
                "valid":   valid,
                "expires": expires,
                "issuer":  issuer.get("organizationName", issuer.get("O", "؟")),
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "sans":    sans[:10],
            }
        except ssl.SSLError as e:
            return {"valid": False, "error": str(e)}
        except ConnectionRefusedError:
            return {"valid": False, "error": "المنفذ 443 مغلق"}
        except socket.timeout:
            return {"valid": False, "error": "انتهت مهلة الاتصال"}
        except Exception as e:
            return {"valid": False, "error": str(e)[:80]}

    def _get_subdomains(self, domain: str) -> list:
        subdomains = set()

        # crt.sh — شهادات SSL العامة
        data = http_get_json(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=self.timeout,
            proxy=self.proxy
        )
        if data and isinstance(data, list):
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        subdomains.add(sub)

        # HackerTarget (مجاني)
        r = http_get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=self.timeout,
            proxy=self.proxy
        )
        if r and r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split("\n"):
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if sub.endswith(f".{domain}") and sub != domain:
                        subdomains.add(sub)

        return sorted(list(subdomains))

    def _get_ip_geo(self, ip: str) -> dict:
        data = http_get_json(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,regionName,isp,org",
            timeout=self.timeout,
            proxy=self.proxy
        )
        if data and data.get("status") == "success":
            return data
        return {}

    def _get_wayback(self, domain: str) -> dict:
        data = http_get_json(
            f"https://archive.org/wayback/available?url={domain}",
            timeout=self.timeout,
            proxy=self.proxy
        )
        if data and data.get("archived_snapshots"):
            snap = data["archived_snapshots"].get("closest", {})
            if snap.get("available"):
                return {
                    "available":     True,
                    "last_snapshot": snap.get("timestamp", "")[:8],
                    "url":           snap.get("url", ""),
                }
        return {"available": False}
