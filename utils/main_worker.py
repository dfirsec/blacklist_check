import contextlib
import fnmatch
import ipaddress
import json
import logging
import os
import platform
import re
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

import asyncwhois
import coloredlogs
import dns.resolver
import httpx
import requests
import trio
import urllib3
import verboselogs
from bs4 import BeautifulSoup
from requests.structures import CaseInsensitiveDict

from utils.termcolors import Termcolor as Tc

# suppress dnspython feature deprecation warning
warnings.filterwarnings("ignore", category=DeprecationWarning)

# suppress certificate verification
urllib3.disable_warnings()

# Base directory paths
parent = Path(__file__).resolve().parent.parent
blklist = parent.joinpath("resc/blacklist.json")
scnrs = parent.joinpath("resc/scanners.json")
feeds = parent.joinpath("resc/feeds.json")

# Primary logger
logger = verboselogs.VerboseLogger(__name__)
logger.setLevel(logging.INFO)
coloredlogs.install(
    level="DEBUG",
    logger=logger,
    fmt="%(message)s",
    level_styles={
        "notice": {"color": "black", "bright": True},
        "warning": {"color": "yellow"},
        "success": {"color": "white", "bold": True},
        "error": {"color": "red"},
        "critical": {"background": "red"},
    },
)


class DNSBL:
    """Performs functions for updating
    DNS blacklist and returning query results."""

    def __init__(self, host, threads):
        self.host = host
        self.threads = threads
        self.cnt = 0
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1  # type: ignore
        self.resolver.lifetime = 1  # type: ignore

    @staticmethod
    def update_dnsbl():
        """Refreshes DNS Blacklist."""
        url = "https://multirbl.valli.org/list/"
        page = requests.get(url).text
        soup = BeautifulSoup(page, "html.parser")
        table_rows = soup.find("table").find_all("tr")  # type: ignore

        alive = []
        for row in table_rows:
            try:
                data = [i.text for i in row.find_all("td")]
                if "(hidden)" not in data:
                    alive.append(row[2])
            except KeyError:
                continue

        with open(feeds, encoding="utf-8") as feed:
            feeds_dict = json.load(feed)
            feed_list = feeds_dict["DNS Blacklists"]["DNSBL"]

        # Remove contact and nszones items from list
        patterns = ["*.nszones.com", "*contacts*"]
        for pattern in patterns:
            for match in fnmatch.filter(alive, pattern):
                alive.remove(match)

        diff = [x for x in alive if x not in feed_list]
        if len(diff) <= 1:
            return False
        print(f"{Tc.green} [ Updating RBLs ]{Tc.rst}")
        for item in diff:
            if item not in feed_list:
                logger.success(f"[+] Adding {item}")
                feed_list.append(item)

        with open(feeds, "w", encoding="utf-8") as json_file:
            json.dump(feeds_dict, json_file, ensure_ascii=False, indent=4)
        return None

    def resolve_dns(self, qry):
        """Return DNS Resolver."""
        try:
            self.resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
            return self.resolver.resolve(qry, "A")

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.Timeout,
            dns.resolver.NoNameservers,
            dns.resolver.NoAnswer,
        ):
            pass
        except DeprecationWarning:
            pass
        return None

    def dnsbl_query(self, blacklist):
        host = "".join(self.host)

        # Return Codes
        codes = [
            "0.0.0.1",
            "127.0.0.1",
            "127.0.0.2",
            "127.0.0.3",
            "127.0.0.4",
            "127.0.0.5",
            "127.0.0.6",
            "127.0.0.7",
            "127.0.0.9",
            "127.0.0.10",
            "127.0.0.11",
            "127.0.0.39",
            "127.0.0.45",
            "127.0.1.4",
            "127.0.1.5",
            "127.0.1.6",
            "127.0.1.20",
            "127.0.1.103",
            "127.0.1.104",
            "127.0.1.105",
            "127.0.1.106",
            "127.0.1.108",
            "10.0.2.3",
        ]

        try:
            qry = ip_address(host).reverse_pointer.replace(".in-addr.arpa", "") + "." + blacklist
        except Exception:
            qry = f"{host}.{blacklist}"

        answer = self.resolve_dns(qry)

        with contextlib.suppress(Exception):
            if any(str(answer[0]) in s for s in codes):  # type: ignore
                logger.success(f"{Tc.red}\u2716{Tc.rst}  Blacklisted > {blacklist}")
                self.cnt += 1

    def dnsbl_mapper(self, threads=None):
        with open(feeds, encoding="utf-8") as json_file:
            data = json.load(json_file)
        dnsbl = list(data["DNS Blacklists"]["DNSBL"])

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.dnsbl_query, dnsbl)

        if self.cnt:
            host = "".join(self.host)
            logger.warning(f"\n[*] {host} is listed in {self.cnt} block lists")
        else:
            print(Tc.clean)


class ProcessBL:
    @staticmethod
    def clear_screen():
        if platform.system() == "Windows":
            os.system("cls")
        else:
            os.system("clear")

    @staticmethod
    async def fetch(url):
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/89.0"}
        async with httpx.AsyncClient(verify=False) as client:
            try:
                resp = await client.get(url, timeout=10.0, headers=headers, follow_redirects=True)
                resp.raise_for_status()
            except httpx.TimeoutException:
                print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{url}{Tc.rst}")
            except httpx.RequestError:
                print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{url}{Tc.rst}")
            except httpx.HTTPStatusError:
                print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{url}{Tc.rst}")
            else:
                return resp.text

    def get_feeds(self, feed):
        ipv4 = re.compile(r"(?![0])\d+\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")
        with contextlib.suppress(TypeError, OSError):
            results = trio.run(self.fetch, feed)
            return [ip.group() for ip in re.finditer(ipv4, results)]
        return None

    @staticmethod
    def read_list():
        """Returns the name and url for each feed."""
        with open(feeds, encoding="utf-8") as json_file:
            data = json.load(json_file)
            return [[name, url] for name, url in data["Blacklist Feeds"].items()]

    @staticmethod
    def sort_list(data):
        """Sorts lists by name and count."""
        sort_name = sorted((name, ip_cnt) for (name, ip_cnt) in data["Blacklists"].items())
        for num, idx in enumerate(sort_name, start=1):
            try:
                print(f"{Tc.cyan}{num:2}){Tc.rst} {idx[0]:23}: {len(idx[1]):<6,}")
            except TypeError:
                print(f"{Tc.cyan}{num:2}){Tc.rst} {idx[0]:23}: {Tc.gray}[DOWNLOAD error]{Tc.rst}")
                continue

    def list_count(self):
        """Returns a count of IP addresses for each feed."""
        try:
            with open(blklist, encoding="utf-8") as json_file:
                data = json.load(json_file)
                self.clear_screen()
                print(f"\n{Tc.bold}{'Blacklists':28}IP cnt{Tc.rst}")
                print("-" * 35)
                self.sort_list(data)

            print(f"\n{Tc.processing} Last Modified: {self.modified_date(blklist)}")
        except FileNotFoundError:
            self.outdated()

    def update_list(self):
        """Updates the feed list with the latest IP addresses."""
        bl_dict = {}
        print(f"{Tc.green}[ Updating ]{Tc.rst}")
        with open(blklist, "w", encoding="utf-8") as json_file:
            bl_dict["Blacklists"] = {}
            for name, url in self.read_list():
                logger.success(f"  {Tc.processing} {name:20}")
                bl_dict["Blacklists"][name] = self.get_feeds(url)

            # Remove duplicate IP addresses and update
            for name in bl_dict["Blacklists"]:
                try:
                    cleanup = list(set(bl_dict["Blacklists"][name]))
                    bl_dict["Blacklists"].update({name: cleanup})
                except TypeError:
                    continue

            json.dump(bl_dict, json_file, ensure_ascii=False, indent=4)

    def add_feed(self, feed, url):
        """Manually add feed."""
        with open(feeds, encoding="utf-8") as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict["Blacklist Feeds"]
        try:
            if feed_list[feed]:
                sys.exit(f'{Tc.warning} Feed "{feed}" already exists.')
        except KeyError:
            self.update_feeds(feed_list, feed, url, feeds_dict)

    def update_feeds(self, feed_list, feed, url, feeds_dict):
        feed_list.update({feed: url})
        with open(feeds, "w", encoding="utf-8") as json_file:
            json.dump(feeds_dict, json_file, ensure_ascii=False, indent=4)
        print(f'[*] Added feed: "{feed}": "{url}"')

        print(f"\n{Tc.cyan}[ Updating new feed ]{Tc.rst}")
        with open(blklist, encoding="utf-8") as json_file:
            bl_dict = json.load(json_file)
            bl_list = bl_dict["Blacklists"]

        bl_list.update({feed: self.get_feeds(url)})
        with open(blklist, "w", encoding="utf-8") as json_file:
            json.dump(bl_dict, json_file, ensure_ascii=False, indent=4)

        print(f"{Tc.success} {Tc.yellow}{len(bl_list[feed]):,}{Tc.rst} IPs added to '{feed}'")

    @staticmethod
    def remove_feed():
        """Remove a feed item."""
        with open(feeds, encoding="utf-8") as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict["Blacklist Feeds"]
            for num, (key, val) in enumerate(feed_list.items(), start=1):
                print(f"{Tc.cyan}{num:2}){Tc.rst} {key:25}{val}")
        try:
            opt = int(input("\nPlease select your choice by number, or Ctrl-C to cancel: ")) - 1
            choice = list(feed_list)[opt]
            del feed_list[choice]
            with open(feeds, "w", encoding="utf8") as json_file:
                json.dump(feeds_dict, json_file, ensure_ascii=False, indent=4)

            # remove from blacklist
            with open(blklist, encoding="utf8") as json_file:
                bl_dict = json.load(json_file)
                del bl_dict["Blacklists"][choice]
            with open(blklist, "w", encoding="utf-8") as json_file:
                json.dump(bl_dict, json_file, ensure_ascii=False, indent=4)

            print(f'{Tc.success} Successfully removed feed: "{choice}"')

        except KeyboardInterrupt:
            sys.exit()
        except (IndexError, ValueError, KeyError):
            sys.exit(f"{Tc.error} Your selection does not exist.")

    def ip_matches(self, ip_addrs):
        found = []

        print(f"\n{Tc.dotsep}\n{Tc.green}[ Local Blacklist Check ]{Tc.rst}")

        def bls_worker(json_list, list_name, list_type):
            """Checks IP against several blacklists."""
            with open(json_list, encoding="utf-8") as json_file:
                ip_list = json.load(json_file)

            for name, item in ip_list[list_name].items():
                try:
                    matches = set(ip_addrs) & set(item)
                    for ip in matches:
                        print(f"\n{list_type} [{ip}] > {Tc.yellow}{name}{Tc.rst}")
                        print(f"{Tc.bold}{'   Location:':10} {Tc.rst}{self.geo_locate(ip)}{Tc.bold}")
                        print(f"{Tc.bold}{'   Whois:':10} {Tc.rst}{self.whois_ip(ip)[0]}")
                        print(f"{Tc.bold}{'   Abuse Email:':10} {Tc.rst}{self.whois_ip(ip)[1]}")
                        if ip not in found:
                            found.append(ip)

                except KeyboardInterrupt:
                    sys.exit("Exited!")
                except TypeError:
                    continue

        def scs_worker(json_list, list_name, list_type):
            """Performs a check against known internet scanners."""
            with open(json_list, encoding="utf-8") as json_file:
                ip_list = json.load(json_file)

            # single ip addresses
            shodan = list(ip_list[list_name]["Shodan"])
            s_matches = set(ip_addrs) & set(shodan)
            for ip_addr in s_matches:
                print(f"\n{list_type} [{ip_addr}] > {Tc.yellow}Shodan{Tc.rst}")
                if ip_addr not in found:
                    found.append(ip_addr)

            proj25499 = list(ip_list[list_name]["Project 25499"])
            p_matches = set(ip_addrs) & set(proj25499)
            for ip_addr in p_matches:
                print(f"\n{list_type} [{ip_addr}] > {Tc.yellow}Project 25499{Tc.rst}")
                if ip_addr not in found:
                    found.append(ip_addr)

            # networks
            tenable = list(ip_list[list_name]["Cloudflare-Tenable"])
            t_matches = [
                ip for ip in ip_addrs for net in tenable if ipaddress.ip_address(ip) in ipaddress.ip_network(net)
            ]
            for ip_addr in set(t_matches):
                print(f"\n{list_type} [{ip_addr}] > {Tc.yellow}Cloudflare-Tenable{Tc.rst}")
                if ip_addr not in found:
                    found.append(ip_addr)

        # Compare and find blacklist matches
        bls_worker(blklist, "Blacklists", Tc.blacklisted)

        # Compare and find scanner matches
        scs_worker(scnrs, "Scanners", Tc.scanner)

        # if not blacklisted
        nomatch = [ip for ip in ip_addrs if ip not in found]
        if nomatch:
            for ip_addr in nomatch:
                print(f"{Tc.clean}{Tc.rst} [{ip_addr}]")
                print(f"{Tc.bold}{'   Location:':10} {Tc.rst}{self.geo_locate(ip_addr)}{Tc.bold}", end="\n")
                print(f"{Tc.bold}{'   Whois:':10} {Tc.rst}{self.whois_ip(ip_addr)[0]}")
                print(f"{Tc.bold}{'   Abuse Email:':10} {Tc.rst}{self.whois_ip(ip_addr)[1]}")

    @staticmethod
    def modified_date(_file):
        """Returns the last modified date, or last download."""
        lastmod = os.stat(_file).st_mtime
        return datetime.strptime(time.ctime(lastmod), "%a %b %d %H:%M:%S %Y")

    @staticmethod
    def geo_locate(ip_addr):
        """Returns IP address geolocation."""
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"}
        url = f"https://freegeoip.live/json/{ip_addr}"
        try:
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
        except Exception as err:
            print(f"[Error] {err}\n")
        else:
            if resp.status_code == 200:
                data = json.loads(resp.content.decode("utf-8"))
                city = data["city"]
                state = data["region_name"]
                country = data["country_name"]
                iso_code = data["country_code"]
                if city and state and iso_code and city != state:
                    return f"{city}, {state} ({iso_code})"
                if city:
                    return f"{city}, {country} ({iso_code})"
                return f"{country} ({iso_code})"
        return None

    @staticmethod
    def whois_ip(ip_addr):
        """Returns IP address whois information."""
        try:
            results = asyncwhois.whois_ipv4(ip_addr)
        except Exception as err:
            return f"Whois failed: {err}"
        else:
            org = results.parser_output["organization"] or ""
            email = results.parser_output["abuse_email"] or ""
            return org, email

    @staticmethod
    def outdated():
        """Check feed list age."""
        try:
            file_time = os.path.getmtime(blklist)
            if time.time() - file_time > 86400:
                return True
        except Exception as err:
            sys.exit(err)
        else:
            return False

    @staticmethod
    def ip46(ip_addr):
        """Performs check against ip-46.com."""
        ip_addr = "".join(ip_addr)
        url = f"https://ip-46.com/{ip_addr}"
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"}
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            resp.raise_for_status()
        except (ConnectionError, requests.exceptions.ConnectTimeout) as err:
            print(f"[Error] Connection Error: {err}")
        else:
            soup = BeautifulSoup(resp.text, features="lxml")
            metadata = soup.find("meta")
            detection = soup.title.get_text()  # type: ignore
            if "No abuse detected" not in detection:
                print(". ".join(metadata["content"].split(". ")[:2]).split("IP-46.com", 1)[0])  # type: ignore
                return detection
            print(Tc.clean)
            return None

    @staticmethod
    def urlhaus(ip_addr):
        """Performs check against urlhaus-api.abuse.ch."""
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        headers = CaseInsensitiveDict([("Accept", "application/json")])
        data = {"host": ip_addr}
        try:
            resp = requests.post(url, headers=headers, data=data).json()
        except (ConnectionError, requests.exceptions.ConnectTimeout) as err:
            print(f"[Error] Connection Error: {err}")
        else:
            try:
                if resp["query_status"] == "no_results":
                    print(Tc.clean)

                if resp["urls"]:
                    for k in resp["urls"]:
                        if k["url_status"] == "online":
                            print(f"Status: {Tc.red}{k['url_status'].title()}{Tc.rst}")
                        else:
                            print(f"Status: {k['url_status'].title()}")
                        print(f"{k['threat'].replace('_', ' ').title():12}: {k['url']}")
                        if k["tags"]:
                            print(f"Tags: {', '.join(k['tags'])}\n")
                        else:
                            print("\n")
            except (TypeError, KeyError):
                return None
            return None

    @staticmethod
    def threatfox(ip_addr):
        """Performs check against threatfox-api.abuse.ch."""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = CaseInsensitiveDict([("Accept", "application/json")])
        ip_addr = "".join(ip_addr)
        data = {"query": "search_ioc", "search_term": ip_addr}
        resp = requests.post(url, headers=headers, json=data).json()

        try:
            if resp["query_status"] == "no_results" or resp["data"] == "Your search did not yield any results":
                print(Tc.clean)

            if resp["data"]:
                for k in resp["data"]:
                    print(f"Threat Type: {k['threat_type'].replace('_', ' ').title()}")
                    print(f"IOC: {k['ioc']}")
                    print(f"Malware: {k['malware']}")
                    print(f"Malware Alias: {k['malware_alias']}")
                    if k["tags"]:
                        print(f"Tags: {', '.join(k['tags'])}\n")
                    else:
                        print("\n")
        except (TypeError, KeyError):
            return None
        return None
