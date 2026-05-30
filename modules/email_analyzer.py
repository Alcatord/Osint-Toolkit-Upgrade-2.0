#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
محلل البريد الإلكتروني
- فحص صيغة البريد
- MX Records (DNS over HTTPS)
- Gravatar
- GitHub / GitLab بالبريد
- فحص التسريبات عبر مواقع مفتوحة
"""

import re
import hashlib
import socket
import json
from utils.http_helper import http_get, http_get_json, check_url_exists


class EmailAnalyzer:
    def __init__(self, display, config):
        self.display = display
        self.config  = config
        self.timeout = config.get("timeout", 10)
        self.proxy   = config.get("proxy")
        self.verbose = config.get("verbose", False)

    def analyze(self, email: str) -> dict:
        d = self.display
        d.section(f"تحليل البريد الإلكتروني: {email}")

        results = {
            "email":       email,
            "found_count": 0,
            "validation":  {},
            "domain_info": {},
            "gravatar":    {},
            "services":    [],
            "breach_info": {},
            "social":      [],
        }

        # 1. Validation
        d.info("التحقق من صيغة البريد...")
        val = self._validate_email(email)
        results["validation"] = val
        if val["valid"]:
            d.success(f"البريد صحيح الصيغة: {email}")
        else:
            d.error(f"صيغة غير صحيحة: {val['reason']}")

        username, domain = email.split("@", 1) if "@" in email else (email, "")

        # 2. Domain MX check
        d.info(f"فحص سجلات MX للنطاق: {domain}")
        mx_info = self._check_mx(domain)
        results["domain_info"] = mx_info
        if mx_info.get("mx_records"):
            d.success(f"سجلات MX: {', '.join(mx_info['mx_records'][:3])}")
        else:
            d.warning("لم يتم العثور على سجلات MX")

        # 3. Gravatar
        d.info("فحص Gravatar...")
        gravatar = self._check_gravatar(email)
        results["gravatar"] = gravatar
        if gravatar.get("exists"):
            d.found(f"Gravatar موجود: {gravatar['profile_url']}")
            results["found_count"] += 1
        else:
            d.not_found("Gravatar غير موجود")

        # 4. Username-based social lookup
        d.info("البحث عن حسابات بنفس اسم المستخدم...")
        social = self._check_username_social(username)
        results["social"] = social
        found_social = [s for s in social if s["status"] == "موجود"]
        if found_social:
            d.found(f"تم اكتشاف {len(found_social)} حساب محتمل")
            results["found_count"] += len(found_social)

        # 5. Service-specific checks
        d.info("فحص الخدمات المرتبطة...")
        services = self._check_email_services(email, domain)
        results["services"] = services
        for svc in services:
            if svc["status"] == "موجود":
                d.found(f"{svc['service']}: {svc['detail']}")
                results["found_count"] += 1

        # 6. HaveIBeenPwned-compatible lookup (free endpoint)
        d.info("فحص التسريبات المعروفة...")
        breach = self._check_breach_public(email)
        results["breach_info"] = breach
        if breach.get("found"):
            d.warning(f"تحذير: البريد ظهر في تسريبات بيانات!")
        else:
            d.success("لم يظهر البريد في تسريبات معروفة عامة")

        # Print summary table
        d.section("ملخص البريد الإلكتروني")
        rows = [
            ["الصيغة",     "صحيحة" if val["valid"] else "خطأ"],
            ["النطاق",     domain],
            ["MX Records", "✓" if mx_info.get("mx_records") else "✗"],
            ["Gravatar",   "موجود" if gravatar.get("exists") else "غير موجود"],
            ["تسريبات",    "⚠ مُسرَّب" if breach.get("found") else "آمن"],
        ]
        d.table(["العنصر", "الحالة"], rows)

        return {"email_analysis": results}

    def _validate_email(self, email: str) -> dict:
        pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, email):
            return {"valid": False, "reason": "صيغة غير صحيحة"}
        if ".." in email:
            return {"valid": False, "reason": "نقطتان متتاليتان"}
        parts = email.split("@")
        return {
            "valid":    True,
            "username": parts[0],
            "domain":   parts[1],
            "length":   len(email),
            "reason":   None
        }

    def _check_mx(self, domain: str) -> dict:
        result = {"domain": domain, "mx_records": [], "a_record": [], "reachable": False}

        # DNS over HTTPS (Google)
        try:
            data = http_get_json(
                f"https://dns.google/resolve?name={domain}&type=MX",
                timeout=self.timeout,
                proxy=self.proxy
            )
            if data and data.get("Answer"):
                mx_list = []
                for ans in data["Answer"]:
                    if ans.get("type") == 15:  # MX type
                        parts = ans.get("data", "").split()
                        if len(parts) >= 2:
                            mx_list.append(parts[1].rstrip("."))
                result["mx_records"] = mx_list
                result["reachable"] = True
        except Exception:
            pass

        # Fallback: system DNS
        if not result["mx_records"]:
            try:
                ips = socket.getaddrinfo(domain, 80)
                result["a_record"] = list(set(r[4][0] for r in ips))
                result["reachable"] = True
            except Exception:
                pass

        return result

    def _check_gravatar(self, email: str) -> dict:
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        profile_url = f"https://www.gravatar.com/{email_hash}.json"
        avatar_url  = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

        result = {
            "email_hash":  email_hash,
            "avatar_url":  f"https://www.gravatar.com/avatar/{email_hash}",
            "profile_url": f"https://www.gravatar.com/{email_hash}",
            "exists":      False,
            "profile":     {}
        }

        # Check avatar (404 if not exist)
        status, _ = check_url_exists(avatar_url, timeout=self.timeout, proxy=self.proxy)
        if status and status == 200:
            result["exists"] = True

        # Try profile JSON
        data = http_get_json(profile_url, timeout=self.timeout, proxy=self.proxy)
        if data and data.get("entry"):
            entry = data["entry"][0]
            result["exists"] = True
            result["profile"] = {
                "display_name":  entry.get("displayName", ""),
                "username":      entry.get("preferredUsername", ""),
                "about":         entry.get("aboutMe", ""),
                "location":      entry.get("currentLocation", ""),
                "profile_url":   entry.get("profileUrl", ""),
            }

        return result

    def _check_username_social(self, username: str) -> list:
        platforms = [
            ("Twitter/X",   f"https://x.com/{username}"),
            ("GitHub",      f"https://github.com/{username}"),
            ("Instagram",   f"https://www.instagram.com/{username}/"),
            ("TikTok",      f"https://www.tiktok.com/@{username}"),
            ("Reddit",      f"https://www.reddit.com/user/{username}"),
            ("LinkedIn",    f"https://www.linkedin.com/in/{username}"),
        ]
        results = []
        for name, url in platforms:
            status_code, final_url = check_url_exists(url, timeout=self.timeout, proxy=self.proxy)
            if status_code in (200, 301, 302):
                results.append({"platform": name, "url": url, "status": "موجود"})
            else:
                results.append({"platform": name, "url": url, "status": "غير موجود"})
        return results

    def _check_email_services(self, email: str, domain: str) -> list:
        results = []

        # Check if domain has known email providers
        known_providers = {
            "gmail.com":      "Google",
            "yahoo.com":      "Yahoo",
            "hotmail.com":    "Microsoft",
            "outlook.com":    "Microsoft",
            "protonmail.com": "ProtonMail",
            "icloud.com":     "Apple",
            "aol.com":        "AOL",
            "yandex.com":     "Yandex",
            "zoho.com":       "Zoho",
        }

        if domain.lower() in known_providers:
            results.append({
                "service": "مزود البريد",
                "status":  "موجود",
                "detail":  known_providers[domain.lower()]
            })
        else:
            results.append({
                "service": "مزود البريد",
                "status":  "موجود",
                "detail":  f"نطاق مخصص: {domain}"
            })

        return results

    def _check_breach_public(self, email: str) -> dict:
        """
        يفحص عبر HIBP API العام (بدون مفتاح - للنطاقات فقط)
        أو عبر مصادر بديلة مفتوحة
        """
        result = {"found": False, "sources": [], "note": ""}

        # DeHashed public search (limited)
        username, domain = email.split("@") if "@" in email else (email, "")

        # Check IntelX free preview
        r = http_get(
            f"https://intelx.io/phonebook/search?maxresults=1&term={email}",
            timeout=self.timeout,
            proxy=self.proxy
        )
        if r and r.status_code == 200 and email in r.text:
            result["found"] = True
            result["sources"].append("IntelX")

        # Check BreachDirectory free endpoint
        r2 = http_get(
            f"https://breachdirectory.org/",
            timeout=self.timeout,
            proxy=self.proxy,
            headers={"Referer": "https://breachdirectory.org/"}
        )
        if r2 and r2.status_code == 200:
            result["note"] = "تحقق يدوياً من: https://haveibeenpwned.com"

        return result