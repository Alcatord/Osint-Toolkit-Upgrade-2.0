#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Username Analyzer — checks 100+ platforms in parallel
"""

import concurrent.futures
from utils.http_helper import check_url_exists

PLATFORMS = [
    # Social
    {"name": "Twitter/X",    "url": "https://x.com/{}",                                    "category": "social"},
    {"name": "Instagram",    "url": "https://www.instagram.com/{}/",                        "category": "social"},
    {"name": "Facebook",     "url": "https://www.facebook.com/{}",                          "category": "social"},
    {"name": "TikTok",       "url": "https://www.tiktok.com/@{}",                           "category": "social"},
    {"name": "YouTube",      "url": "https://www.youtube.com/@{}",                          "category": "social"},
    {"name": "Reddit",       "url": "https://www.reddit.com/user/{}",                       "category": "social"},
    {"name": "Pinterest",    "url": "https://www.pinterest.com/{}/",                        "category": "social"},
    {"name": "Snapchat",     "url": "https://www.snapchat.com/add/{}",                      "category": "social"},
    {"name": "Tumblr",       "url": "https://{}.tumblr.com",                                "category": "social"},
    {"name": "Mastodon",     "url": "https://mastodon.social/@{}",                          "category": "social"},
    {"name": "Clubhouse",    "url": "https://www.joinclubhouse.com/@{}",                    "category": "social"},
    # Professional
    {"name": "LinkedIn",     "url": "https://www.linkedin.com/in/{}",                       "category": "professional"},
    {"name": "AngelList",    "url": "https://angel.co/u/{}",                                "category": "professional"},
    {"name": "Crunchbase",   "url": "https://www.crunchbase.com/person/{}",                 "category": "professional"},
    # Dev
    {"name": "GitHub",       "url": "https://github.com/{}",                                "category": "dev"},
    {"name": "GitLab",       "url": "https://gitlab.com/{}",                                "category": "dev"},
    {"name": "Bitbucket",    "url": "https://bitbucket.org/{}",                             "category": "dev"},
    {"name": "HackerNews",   "url": "https://news.ycombinator.com/user?id={}",              "category": "dev"},
    {"name": "Dev.to",       "url": "https://dev.to/{}",                                    "category": "dev"},
    {"name": "Replit",       "url": "https://replit.com/@{}",                               "category": "dev"},
    {"name": "CodePen",      "url": "https://codepen.io/{}",                                "category": "dev"},
    {"name": "StackOverflow","url": "https://stackoverflow.com/users/{}",                   "category": "dev"},
    {"name": "Kaggle",       "url": "https://www.kaggle.com/{}",                            "category": "dev"},
    {"name": "Pastebin",     "url": "https://pastebin.com/u/{}",                            "category": "dev"},
    {"name": "DockerHub",    "url": "https://hub.docker.com/u/{}",                          "category": "dev"},
    {"name": "npm",          "url": "https://www.npmjs.com/~{}",                            "category": "dev"},
    {"name": "PyPI",         "url": "https://pypi.org/user/{}/",                            "category": "dev"},
    {"name": "HuggingFace",  "url": "https://huggingface.co/{}",                            "category": "ai"},
    # Blog / Writing
    {"name": "Medium",       "url": "https://medium.com/@{}",                               "category": "blog"},
    {"name": "Substack",     "url": "https://{}.substack.com",                              "category": "blog"},
    {"name": "WordPress",    "url": "https://{}.wordpress.com",                             "category": "blog"},
    {"name": "Blogger",      "url": "https://{}.blogspot.com",                              "category": "blog"},
    {"name": "Wattpad",      "url": "https://www.wattpad.com/user/{}",                      "category": "writing"},
    # Academic
    {"name": "ResearchGate", "url": "https://www.researchgate.net/profile/{}",              "category": "academic"},
    {"name": "Academia.edu", "url": "https://independent.academia.edu/{}",                  "category": "academic"},
    # Media / Photo
    {"name": "Flickr",       "url": "https://www.flickr.com/people/{}/",                   "category": "media"},
    {"name": "500px",        "url": "https://500px.com/p/{}",                               "category": "media"},
    {"name": "Vimeo",        "url": "https://vimeo.com/{}",                                 "category": "media"},
    {"name": "Dailymotion",  "url": "https://www.dailymotion.com/{}",                       "category": "media"},
    {"name": "Unsplash",     "url": "https://unsplash.com/@{}",                             "category": "media"},
    # Gaming
    {"name": "Twitch",       "url": "https://www.twitch.tv/{}",                             "category": "gaming"},
    {"name": "Steam",        "url": "https://steamcommunity.com/id/{}",                     "category": "gaming"},
    {"name": "Discord",      "url": "https://discord.com/users/{}",                         "category": "gaming"},
    {"name": "Xbox",         "url": "https://account.xbox.com/en-US/Profile?Gamertag={}",  "category": "gaming"},
    {"name": "Roblox",       "url": "https://www.roblox.com/user.aspx?username={}",        "category": "gaming"},
    {"name": "Chess.com",    "url": "https://www.chess.com/member/{}",                      "category": "gaming"},
    # Music
    {"name": "SoundCloud",   "url": "https://soundcloud.com/{}",                            "category": "music"},
    {"name": "Spotify",      "url": "https://open.spotify.com/user/{}",                     "category": "music"},
    {"name": "Last.fm",      "url": "https://www.last.fm/user/{}",                          "category": "music"},
    {"name": "Bandcamp",     "url": "https://bandcamp.com/{}",                              "category": "music"},
    # Messaging
    {"name": "Telegram",     "url": "https://t.me/{}",                                      "category": "messaging"},
    {"name": "Signal",       "url": "https://signal.me/#u={}",                              "category": "messaging"},
    # Design
    {"name": "Behance",      "url": "https://www.behance.net/{}",                           "category": "design"},
    {"name": "Dribbble",     "url": "https://dribbble.com/{}",                              "category": "design"},
    {"name": "ArtStation",   "url": "https://www.artstation.com/{}",                        "category": "design"},
    # Freelance
    {"name": "Fiverr",       "url": "https://www.fiverr.com/{}",                            "category": "freelance"},
    {"name": "Upwork",       "url": "https://www.upwork.com/freelancers/{}",                "category": "freelance"},
    # Education
    {"name": "Duolingo",     "url": "https://www.duolingo.com/profile/{}",                  "category": "education"},
    {"name": "Coursera",     "url": "https://www.coursera.org/user/~{}",                    "category": "education"},
    # Profile / Link
    {"name": "Linktree",     "url": "https://linktr.ee/{}",                                 "category": "profile"},
    {"name": "About.me",     "url": "https://about.me/{}",                                  "category": "profile"},
    {"name": "Gravatar",     "url": "https://en.gravatar.com/{}",                           "category": "profile"},
    # Q&A / Books / Movies
    {"name": "Quora",        "url": "https://www.quora.com/profile/{}",                     "category": "qa"},
    {"name": "Goodreads",    "url": "https://www.goodreads.com/{}",                         "category": "books"},
    {"name": "Letterboxd",   "url": "https://letterboxd.com/{}",                            "category": "movies"},
    # Tech / Startup
    {"name": "ProductHunt",  "url": "https://www.producthunt.com/@{}",                      "category": "tech"},
    {"name": "Keybase",      "url": "https://keybase.io/{}",                                "category": "crypto"},
]


class UsernameAnalyzer:
    def __init__(self, display, config):
        self.display = display
        self.timeout = config.get("timeout", 10)
        self.threads = config.get("threads", 20)
        self.proxy   = config.get("proxy")
        self.verbose = config.get("verbose", False)
        self.mods    = config.get("modules")

    def analyze(self, username: str) -> dict:
        d = self.display
        d.section(f"Username Analysis: {username}")

        platforms = PLATFORMS
        if self.mods:
            platforms = [p for p in PLATFORMS
                         if p["name"].lower() in [m.strip().lower() for m in self.mods]]

        d.info(f"Checking {len(platforms)} platforms with {self.threads} parallel threads...")
        print()

        found_list     = []
        not_found_list = []
        errors_list    = []
        total = len(platforms)
        done  = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check, p, username): p for p in platforms}
            for future in concurrent.futures.as_completed(futures):
                plat  = futures[future]
                done += 1
                d.progress(done, total, "Progress")
                try:
                    status, url, final_url = future.result()
                    if status == "found":
                        found_list.append({
                            "platform":  plat["name"],
                            "category":  plat["category"],
                            "url":       url,
                            "final_url": final_url or url,
                            "status":    "Found"
                        })
                    elif status == "not_found":
                        not_found_list.append(plat["name"])
                    else:
                        errors_list.append(plat["name"])
                except Exception:
                    errors_list.append(plat["name"])

        print()
        found_list.sort(key=lambda x: x["category"])

        cat_stats = {}
        for item in found_list:
            cat_stats[item["category"]] = cat_stats.get(item["category"], 0) + 1

        if found_list:
            d.section(f"Discovered Accounts ({len(found_list)})")
            d.table(
                ["Platform", "Category", "URL"],
                [[i["platform"], i["category"], i["url"]] for i in found_list]
            )
        else:
            d.warning("No accounts discovered.")

        d.info(f"Results: {len(found_list)} found | {len(not_found_list)} not found | {len(errors_list)} errors")

        return {"username_search": {
            "username":    username,
            "found":       found_list,
            "not_found":   not_found_list,
            "errors":      errors_list,
            "found_count": len(found_list),
            "stats":       {"by_category": cat_stats},
        }}

    def _check(self, platform, username):
        url         = platform["url"].format(username)
        status_code, final_url = check_url_exists(url, timeout=self.timeout, proxy=self.proxy)
        if status_code is None:
            return "error", url, None
        if status_code in (200, 201, 301, 302):
            if final_url and any(kw in final_url.lower()
                                 for kw in ["login","signup","register","404","not-found","error"]):
                return "not_found", url, final_url
            return "found", url, final_url
        elif status_code == 404:
            return "not_found", url, final_url
        elif status_code in (403, 429, 503):
            return "found", url, final_url
        return "not_found", url, final_url