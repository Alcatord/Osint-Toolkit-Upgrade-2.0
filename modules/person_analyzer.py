#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
محلل الأشخاص
- Google Dorks (بدون API)
- بحث LinkedIn العام
- بناء متغيرات الاسم
- البحث عن بريد إلكتروني محتمل
- روابط مفيدة للبحث اليدوي
"""

import re
import urllib.parse
from utils.http_helper import http_get, check_url_exists


class PersonAnalyzer:
    def __init__(self, display, config):
        self.display = display
        self.config  = config
        self.timeout = config.get("timeout", 10)
        self.proxy   = config.get("proxy")
        self.verbose = config.get("verbose", False)

    def analyze(self, name: str) -> dict:
        d = self.display
        d.section(f"البحث عن الشخص: {name}")

        results = {
            "name":         name,
            "found_count":  0,
            "name_variants": [],
            "possible_usernames": [],
            "possible_emails": [],
            "search_links":  [],
            "linkedin":      [],
            "social_links":  [],
            "dorks":         [],
        }

        # 1. توليد متغيرات الاسم
        d.info("توليد متغيرات الاسم...")
        variants = self._generate_variants(name)
        results["name_variants"]      = variants["variants"]
        results["possible_usernames"] = variants["usernames"]
        results["possible_emails"]    = variants["emails"]

        d.success(f"تم توليد {len(variants['usernames'])} اسم مستخدم محتمل")
        d.success(f"تم توليد {len(variants['emails'])} بريد إلكتروني محتمل")

        # 2. Google Dorks
        d.info("بناء Google Dorks...")
        dorks = self._build_dorks(name)
        results["dorks"] = dorks
        d.success(f"تم إنشاء {len(dorks)} استعلام Dork")

        # 3. روابط البحث المباشرة
        d.info("بناء روابط البحث...")
        search_links = self._build_search_links(name)
        results["search_links"] = search_links
        d.success(f"تم إنشاء {len(search_links)} رابط بحث")

        # 4. فحص LinkedIn
        d.info("فحص LinkedIn...")
        linkedin_results = self._check_linkedin(name, variants["usernames"])
        results["linkedin"] = linkedin_results
        found_li = [r for r in linkedin_results if r["status"] == "محتمل"]
        if found_li:
            d.found(f"روابط LinkedIn محتملة: {len(found_li)}")
            results["found_count"] += len(found_li)
        else:
            d.not_found("لم يتم العثور على روابط LinkedIn")

        # 5. فحص منصات أخرى بالاسم
        d.info("فحص المنصات الأخرى...")
        social = self._check_social_by_name(name, variants["usernames"])
        results["social_links"] = social
        found_social = [s for s in social if s["status"] == "محتمل"]
        if found_social:
            d.found(f"روابط محتملة على منصات أخرى: {len(found_social)}")
            results["found_count"] += len(found_social)

        # ── عرض الجداول ──────────────────────────────────
        d.section("أسماء المستخدمين المحتملة")
        if variants["usernames"]:
            rows = [[i+1, u] for i, u in enumerate(variants["usernames"])]
            d.table(["#", "اسم المستخدم"], rows)

        d.section("روابط البحث")
        rows = [[s["platform"], s["url"]] for s in search_links[:10]]
        d.table(["المنصة", "الرابط"], rows)

        d.section("Google Dorks — انسخها وابحث بها")
        for i, dork in enumerate(dorks[:8], 1):
            d.key_value(f"  Dork {i}", dork["query"])

        return {"person_analysis": results}

    # ──────────────────────────────────────────────────────
    def _generate_variants(self, name: str) -> dict:
        """توليد متغيرات الاسم وأسماء المستخدمين والبريد"""
        parts = name.strip().split()
        # تحويل الأسماء العربية لأحرف لاتينية أساسية إذا كانت عربية
        # هنا نتعامل مع الأسماء اللاتينية أولاً
        latin_parts = [p for p in parts if re.match(r"[a-zA-Z]", p)]
        if not latin_parts:
            latin_parts = parts  # ابقَ على الأسماء كما هي

        first = latin_parts[0].lower() if latin_parts else ""
        last  = latin_parts[-1].lower() if len(latin_parts) > 1 else ""
        full  = "".join(p.lower() for p in latin_parts)

        usernames = []
        if first and last:
            usernames = [
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{last}{first}",
                f"{last}.{first}",
                f"{first[0]}{last}",
                f"{first}{last[0]}",
                f"{first[0]}.{last}",
                f"{first}-{last}",
                f"{last}_{first}",
                f"{first}{last}1",
                f"{first}{last}123",
                f"_{first}{last}",
                f"{first[0:3]}{last}",
                f"{first}{last[0:3]}",
            ]
        elif first:
            usernames = [first, f"{first}_1", f"{first}01"]

        # إزالة المكررات مع الحفاظ على الترتيب
        seen = set()
        unique_usernames = []
        for u in usernames:
            if u not in seen and u:
                seen.add(u)
                unique_usernames.append(u)

        # بريد إلكتروني محتمل
        common_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"]
        emails = []
        for u in unique_usernames[:5]:
            for domain in common_domains[:3]:
                emails.append(f"{u}@{domain}")

        variants = []
        if latin_parts:
            variants = [
                " ".join(latin_parts),
                ".".join(p.lower() for p in latin_parts),
                "_".join(p.lower() for p in latin_parts),
                "".join(p.capitalize() for p in latin_parts),
            ]

        return {
            "variants":  list(set(variants)),
            "usernames": unique_usernames,
            "emails":    emails,
        }

    def _build_dorks(self, name: str) -> list:
        """بناء Google Dorks للبحث عن الشخص"""
        q    = urllib.parse.quote_plus(f'"{name}"')
        name_raw = name

        dorks = [
            {
                "name":  "بحث عام",
                "query": f'"{name_raw}"',
                "url":   f"https://www.google.com/search?q={q}"
            },
            {
                "name":  "LinkedIn",
                "query": f'site:linkedin.com "{name_raw}"',
                "url":   f'https://www.google.com/search?q=site:linkedin.com+{q}'
            },
            {
                "name":  "Twitter/X",
                "query": f'site:twitter.com OR site:x.com "{name_raw}"',
                "url":   f'https://www.google.com/search?q=site:x.com+{q}'
            },
            {
                "name":  "GitHub",
                "query": f'site:github.com "{name_raw}"',
                "url":   f'https://www.google.com/search?q=site:github.com+{q}'
            },
            {
                "name":  "Facebook",
                "query": f'site:facebook.com "{name_raw}"',
                "url":   f'https://www.google.com/search?q=site:facebook.com+{q}'
            },
            {
                "name":  "Instagram",
                "query": f'site:instagram.com "{name_raw}"',
                "url":   f'https://www.google.com/search?q=site:instagram.com+{q}'
            },
            {
                "name":  "بريد إلكتروني",
                "query": f'"{name_raw}" email OR contact OR "@gmail.com" OR "@yahoo.com"',
                "url":   f'https://www.google.com/search?q={q}+email+OR+contact'
            },
            {
                "name":  "مستندات عامة",
                "query": f'"{name_raw}" filetype:pdf OR filetype:doc',
                "url":   f'https://www.google.com/search?q={q}+filetype:pdf+OR+filetype:doc'
            },
            {
                "name":  "أرشيف إنترنت",
                "query": f'site:web.archive.org "{name_raw}"',
                "url":   f'https://www.google.com/search?q=site:web.archive.org+{q}'
            },
            {
                "name":  "Reddit",
                "query": f'site:reddit.com "{name_raw}"',
                "url":   f'https://www.google.com/search?q=site:reddit.com+{q}'
            },
        ]
        return dorks

    def _build_search_links(self, name: str) -> list:
        """روابط بحث مباشرة على محركات بحث وأدوات OSINT"""
        q = urllib.parse.quote_plus(name)
        return [
            {"platform": "Google",        "url": f"https://www.google.com/search?q={q}"},
            {"platform": "Bing",          "url": f"https://www.bing.com/search?q={q}"},
            {"platform": "DuckDuckGo",    "url": f"https://duckduckgo.com/?q={q}"},
            {"platform": "Yandex",        "url": f"https://yandex.com/search/?text={q}"},
            {"platform": "LinkedIn",      "url": f"https://www.linkedin.com/search/results/people/?keywords={q}"},
            {"platform": "Twitter/X",     "url": f"https://x.com/search?q={q}&f=user"},
            {"platform": "Facebook",      "url": f"https://www.facebook.com/search/people/?q={q}"},
            {"platform": "Instagram",     "url": f"https://www.instagram.com/explore/search/keyword/?q={q}"},
            {"platform": "TikTok",        "url": f"https://www.tiktok.com/search?q={q}"},
            {"platform": "GitHub",        "url": f"https://github.com/search?q={q}&type=users"},
            {"platform": "Reddit",        "url": f"https://www.reddit.com/search/?q={q}&type=user"},
            {"platform": "Pipl (يدوي)",   "url": f"https://pipl.com/search/?q={q}"},
            {"platform": "WebMii",        "url": f"https://webmii.com/people?n={q}"},
            {"platform": "Spokeo",        "url": f"https://www.spokeo.com/{q.replace('+','-')}"},
            {"platform": "That'sThem",    "url": f"https://thatsthem.com/name/{q.replace('+','-')}"},
        ]

    def _check_linkedin(self, name: str, usernames: list) -> list:
        """فحص LinkedIn بمتغيرات الاسم"""
        results = []
        parts   = name.strip().split()
        checks  = []

        # بناء روابط LinkedIn محتملة
        if len(parts) >= 2:
            first = parts[0].lower()
            last  = parts[-1].lower()
            checks = [
                f"https://www.linkedin.com/in/{first}-{last}",
                f"https://www.linkedin.com/in/{first}{last}",
                f"https://www.linkedin.com/in/{first[0]}{last}",
                f"https://www.linkedin.com/in/{first}-{last}-1",
            ]

        for url in checks[:4]:
            status_code, final_url = check_url_exists(url, timeout=self.timeout, proxy=self.proxy)
            if status_code in (200, 999):  # 999 = LinkedIn blocks but page may exist
                results.append({"url": url, "status": "محتمل"})
            elif status_code == 404:
                results.append({"url": url, "status": "غير موجود"})

        return results

    def _check_social_by_name(self, name: str, usernames: list) -> list:
        """فحص منصات بأسماء المستخدم المولدة"""
        results = []
        # فحص أول 3 أسماء مستخدم فقط على منصات رئيسية
        platforms = [
            ("GitHub",    "https://github.com/{}"),
            ("Twitter/X", "https://x.com/{}"),
            ("Medium",    "https://medium.com/@{}"),
        ]

        for username in usernames[:3]:
            for plat_name, url_tpl in platforms:
                url         = url_tpl.format(username)
                status_code, final_url = check_url_exists(url, timeout=self.timeout, proxy=self.proxy)
                if status_code in (200, 301, 302):
                    # تأكد أنه لم يُعاد توجيهه لصفحة خطأ
                    if final_url and any(kw in final_url.lower()
                                        for kw in ["login","signup","404","error","notfound"]):
                        continue
                    results.append({
                        "platform": plat_name,
                        "username": username,
                        "url":      url,
                        "status":   "محتمل"
                    })

        return results
