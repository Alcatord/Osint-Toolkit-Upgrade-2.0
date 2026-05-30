#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
محلل عناوين IP
- الموقع الجغرافي
- ASN والمشغل
- Reverse DNS
- فحص القوائم السوداء
- فحص المنافذ الشائعة
"""

import socket
import concurrent.futures
from utils.http_helper import http_get_json, http_get, resolve_hostname


class IPAnalyzer:
    def __init__(self, display, config):
        self.display = display
        self.config  = config
        self.timeout = config.get("timeout", 10)
        self.proxy   = config.get("proxy")
        self.verbose = config.get("verbose", False)

    def analyze(self, target: str) -> dict:
        d = self.display
        d.section(f"تحليل عنوان IP: {target}")

        results = {
            "ip":          target,
            "found_count": 0,
            "geo":         {},
            "asn":         {},
            "rdns":        {},
            "blacklists":  [],
            "ports":       [],
            "shodan_hint": {}
        }

        # 1. Geolocation via ip-api.com (مجاني بدون مفتاح)
        d.info("جلب الموقع الجغرافي...")
        geo = self._get_geo(target)
        results["geo"] = geo
        if geo.get("country"):
            d.success(f"الموقع: {geo.get('city','?')}, {geo.get('country','?')}")
            d.key_value("  المنطقة",   geo.get("regionName", "?"), indent=1)
            d.key_value("  ISP",        geo.get("isp", "?"), indent=1)
            d.key_value("  المنظمة",   geo.get("org", "?"), indent=1)
            d.key_value("  المنطقة الزمنية", geo.get("timezone", "?"), indent=1)
            results["found_count"] += 1
        else:
            d.warning("تعذر الحصول على الموقع الجغرافي")

        # 2. ASN Info via bgpview.io
        d.info("جلب معلومات ASN...")
        asn = self._get_asn(target)
        results["asn"] = asn
        if asn.get("asn"):
            d.success(f"ASN: {asn['asn']} — {asn.get('name','?')}")
            results["found_count"] += 1

        # 3. Reverse DNS
        d.info("Reverse DNS lookup...")
        rdns = self._reverse_dns(target)
        results["rdns"] = rdns
        if rdns.get("hostname"):
            d.success(f"rDNS: {rdns['hostname']}")
            results["found_count"] += 1
        else:
            d.not_found("لا يوجد Reverse DNS")

        # 4. Blacklist check
        d.info("فحص القوائم السوداء...")
        blacklists = self._check_blacklists(target)
        results["blacklists"] = blacklists
        listed = [b for b in blacklists if b["listed"]]
        if listed:
            d.warning(f"IP مُدرج في {len(listed)} قائمة سوداء!")
            for b in listed:
                d.warning(f"  ← {b['list']}")
        else:
            d.success("IP غير مُدرج في القوائم السوداء المعروفة")

        # 5. Common port scan
        d.info("فحص المنافذ الشائعة...")
        ports = self._scan_ports(target)
        results["ports"] = ports
        open_ports = [p for p in ports if p["status"] == "مفتوح"]
        if open_ports:
            d.success(f"منافذ مفتوحة: {', '.join(str(p['port']) for p in open_ports)}")
            results["found_count"] += len(open_ports)
        else:
            d.not_found("لا توجد منافذ مفتوحة شائعة")

        # 6. Shodan hint (بدون API)
        results["shodan_hint"] = {
            "url":  f"https://www.shodan.io/host/{target}",
            "note": "افتح الرابط يدوياً للحصول على تفاصيل إضافية"
        }
        d.info(f"Shodan (يدوي): https://www.shodan.io/host/{target}")

        # ── جدول ملخص ────────────────────────────────────
        d.section("ملخص IP")
        rows = [
            ["الدولة",       geo.get("country", "؟")],
            ["المدينة",      geo.get("city", "؟")],
            ["ISP",          geo.get("isp", "؟")],
            ["ASN",          asn.get("asn", "؟")],
            ["rDNS",         rdns.get("hostname", "لا يوجد")],
            ["القوائم السوداء", f"{len(listed)} قائمة" if listed else "نظيف ✓"],
            ["المنافذ المفتوحة", ", ".join(str(p["port"]) for p in open_ports) or "لا شيء"],
        ]
        d.table(["العنصر", "القيمة"], rows)

        return {"ip_analysis": results}

    # ──────────────────────────────────────────────────────
    def _get_geo(self, ip: str) -> dict:
        # المصدر الأول: ip-api.com
        data = http_get_json(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
            f"regionName,city,lat,lon,timezone,isp,org,as,query",
            timeout=self.timeout,
            proxy=self.proxy
        )
        if data and data.get("status") == "success":
            return data

        # المصدر الثاني: ipinfo.io
        data2 = http_get_json(
            f"https://ipinfo.io/{ip}/json",
            timeout=self.timeout,
            proxy=self.proxy
        )
        if data2 and "country" in data2:
            loc = data2.get("loc", ",").split(",")
            return {
                "country":    data2.get("country", ""),
                "city":       data2.get("city", ""),
                "regionName": data2.get("region", ""),
                "isp":        data2.get("org", ""),
                "org":        data2.get("org", ""),
                "timezone":   data2.get("timezone", ""),
                "lat":        loc[0] if len(loc) > 0 else "",
                "lon":        loc[1] if len(loc) > 1 else "",
            }

        return {}

    def _get_asn(self, ip: str) -> dict:
        data = http_get_json(
            f"https://api.bgpview.io/ip/{ip}",
            timeout=self.timeout,
            proxy=self.proxy
        )
        if data and data.get("status") == "ok":
            prefixes = data.get("data", {}).get("prefixes", [])
            if prefixes:
                asn_info = prefixes[0].get("asn", {})
                return {
                    "asn":         f"AS{asn_info.get('asn', '')}",
                    "name":        asn_info.get("name", ""),
                    "description": asn_info.get("description", ""),
                    "country":     asn_info.get("country_code", ""),
                }
        return {}

    def _reverse_dns(self, ip: str) -> dict:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {"hostname": hostname}
        except Exception:
            return {"hostname": None}

    def _check_blacklists(self, ip: str) -> list:
        """
        فحص DNSBL (DNS-based Blackhole Lists)
        يعكس أوكتيتات IP ثم يستعلم عن النطاقات
        """
        DNSBL_LISTS = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "b.barracudacentral.org",
            "dnsbl.sorbs.net",
            "spam.dnsbl.sorbs.net",
            "http.dnsbl.sorbs.net",
            "xbl.spamhaus.org",
            "sbl.spamhaus.org",
        ]

        # عكس الـ IP: 1.2.3.4 → 4.3.2.1
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
        except Exception:
            return []

        results  = []
        timeout  = min(self.timeout, 5)

        def check_one(dnsbl):
            query = f"{reversed_ip}.{dnsbl}"
            try:
                socket.setdefaulttimeout(timeout)
                socket.gethostbyname(query)
                return {"list": dnsbl, "listed": True}
            except socket.gaierror:
                return {"list": dnsbl, "listed": False}
            except Exception:
                return {"list": dnsbl, "listed": False}

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(check_one, bl): bl for bl in DNSBL_LISTS}
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.append(f.result())
                except Exception:
                    pass

        return results

    def _scan_ports(self, ip: str) -> list:
        COMMON_PORTS = [
            (21,   "FTP"),
            (22,   "SSH"),
            (23,   "Telnet"),
            (25,   "SMTP"),
            (53,   "DNS"),
            (80,   "HTTP"),
            (110,  "POP3"),
            (143,  "IMAP"),
            (443,  "HTTPS"),
            (445,  "SMB"),
            (3306, "MySQL"),
            (3389, "RDP"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (8080, "HTTP-Alt"),
            (8443, "HTTPS-Alt"),
            (27017,"MongoDB"),
        ]

        results = []
        timeout = min(self.timeout, 3)

        def check_port(port_info):
            port, service = port_info
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return {"port": port, "service": service, "status": "مفتوح"}
                else:
                    return {"port": port, "service": service, "status": "مغلق"}
            except Exception:
                return {"port": port, "service": service, "status": "خطأ"}

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check_port, p): p for p in COMMON_PORTS}
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.append(f.result())
                except Exception:
                    pass

        results.sort(key=lambda x: x["port"])
        return results
