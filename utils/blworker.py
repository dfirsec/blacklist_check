import ipaddress
import json
import logging
import os
import platform
import re
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import coloredlogs
import httpx
import requests
import trio
import urllib3
import verboselogs
from bs4 import BeautifulSoup
from dns.exception import DNSException
from ipwhois import IPWhois, exceptions
from querycontacts import ContactFinder
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


class ProcessBL:
    @staticmethod
    def clr_scrn():
        if platform.system() == "Windows":
            os.system("cls")
        else:
            os.system("clear")

    async def fetch(self, url):
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/89.0"}
        async with httpx.AsyncClient(verify=False) as client:
            try:
                resp = await client.get(url, timeout=10.0, headers=headers)
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
        try:
            results = trio.run(self.fetch, feed)
            ip = [ip.group() for ip in re.finditer(ipv4, results)]
            return ip
        except (TypeError, OSError):
            pass

    @staticmethod
    def read_list():
        """Returns the name and url for each feed."""
        with open(feeds) as json_file:
            data = json.load(json_file)
            return [[name, url] for name, url in data["Blacklist Feeds"].items()]

    @staticmethod
    def sort_list(data):
        """Sorts lists by name and count."""
        sort_name = sorted((name, ip_cnt) for (name, ip_cnt) in data["Blacklists"].items())
        for n, i in enumerate(sort_name, start=1):
            try:
                print(f"{Tc.cyan}{n:2}){Tc.rst} {i[0]:23}: {len(i[1]):<6,}")
            except TypeError:
                print(f"{Tc.cyan}{n:2}){Tc.rst} {i[0]:23}: {Tc.gray}[DOWNLOAD error]{Tc.rst}")
                continue

    def list_count(self):
        """Returns a count of IP addresses for each feed."""
        try:
            with open(blklist) as json_file:
                data = json.load(json_file)
                self.clr_scrn()
                print(f"\n{Tc.bold}{'Blacklists':28}IP cnt{Tc.rst}")
                print("-" * 35)
                self.sort_list(data)

            print(f"\n{Tc.processing} Last Modified: {self.modified_date(blklist)}")
        except FileNotFoundError:
            self.outdated()

    def update_list(self):
        """Updates the feed list with latest IP addresses."""
        bl_dict = {}
        print(f"{Tc.green}[ Updating ]{Tc.rst}")
        with open(blklist, "w") as json_file:
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
        with open(feeds) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict["Blacklist Feeds"]
        try:
            if feed_list[feed]:
                sys.exit(f'{Tc.warning} Feed "{feed}" already exists.')
        except KeyError:
            feed_list.update({feed: url})
            with open(feeds, "w") as json_file:
                json.dump(feeds_dict, json_file, ensure_ascii=False, indent=4)
            print(f'[*] Added feed: "{feed}": "{url}"')

            print(f"\n{Tc.cyan}[ Updating new feed ]{Tc.rst}")
            with open(blklist) as json_file:
                bl_dict = json.load(json_file)
                bl_list = bl_dict["Blacklists"]

            bl_list.update({feed: self.get_feeds(url)})
            with open(blklist, "w") as json_file:
                json.dump(bl_dict, json_file, ensure_ascii=False, indent=4)

            print(f"{Tc.success} {Tc.yellow}{len(bl_list[feed]):,}{Tc.rst} IPs added to '{feed}'")

    @staticmethod
    def remove_feed():
        """Remove a feed item."""
        with open(feeds) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict["Blacklist Feeds"]
            for n, (k, v) in enumerate(feed_list.items(), start=1):
                print(f"{Tc.cyan}{n:2}){Tc.rst} {k:25}{v}")
        try:
            # remove from feeds
            opt = int(input("\nPlease select your choice by number, or Ctrl-C to cancel: "))
            opt = opt - 1  # subtract 1 as enumerate starts at 1
            choice = list(feed_list)[opt]
            del feed_list[choice]
            with open(feeds, "w") as json_file:
                json.dump(feeds_dict, json_file, ensure_ascii=False, indent=4)

            # remove from blacklist
            with open(blklist) as json_file:
                bl_dict = json.load(json_file)
                del bl_dict["Blacklists"][choice]
            with open(blklist, "w") as json_file:
                json.dump(bl_dict, json_file, ensure_ascii=False, indent=4)

            print(f'{Tc.success} Successfully removed feed: "{choice}"')

        except KeyboardInterrupt:
            sys.exit()
        except (IndexError, ValueError, KeyError):
            sys.exit(f"{Tc.error} Your selection does not exist.")

    def ip_matches(self, ip_addrs):
        found = []
        qf = ContactFinder()

        print(f"\n{Tc.dotsep}\n{Tc.green}[ Local Blacklist Check ]{Tc.rst}")

        def bls_worker(json_list, list_name, list_type):
            """Checks IP against several blacklists."""
            with open(json_list) as json_file:
                ip_list = json.load(json_file)

            for name, item in ip_list[list_name].items():
                try:
                    matches = set(ip_addrs) & set(item)
                    for ip in matches:
                        print(f"\n{list_type} [{ip}] > {Tc.yellow}{name}{Tc.rst}")
                        print(f"{Tc.bold}{'   Location:':10} {Tc.rst}{self.geo_locate(ip)}{Tc.bold}")
                        print(f"{Tc.bold}{'   Whois:':10} {Tc.rst}{self.whois_ip(ip)}")
                        try:
                            print(f"{Tc.bold}{'   Contact:':10} {Tc.rst}{' '.join([str(i) for i in qf.find(ip)])}\n")
                        except DNSException:
                            pass

                        if ip not in found:
                            found.append(ip)

                except KeyboardInterrupt:
                    sys.exit()
                except TypeError:
                    continue

        def scs_worker(json_list, list_name, list_type):
            """Performs a check against known internet scanners."""
            with open(json_list) as json_file:
                ip_list = json.load(json_file)

            # single ip addresses
            shodan = list(ip_list[list_name]["Shodan"])
            s_matches = set(ip_addrs) & set(shodan)
            for ip in s_matches:
                print(f"\n{list_type} [{ip}] > {Tc.yellow}Shodan{Tc.rst}")
                if ip not in found:
                    found.append(ip)

            proj25499 = list(ip_list[list_name]["Project 25499"])
            p_matches = set(ip_addrs) & set(proj25499)
            for ip in p_matches:
                print(f"\n{list_type} [{ip}] > {Tc.yellow}Project 25499{Tc.rst}")
                if ip not in found:
                    found.append(ip)

            # networks
            tenable = list(ip_list[list_name]["Cloudflare-Tenable"])
            t_matches = [
                ip for ip in ip_addrs for net in tenable if ipaddress.ip_address(ip) in ipaddress.ip_network(net)
            ]
            for ip in set(t_matches):
                print(f"\n{list_type} [{ip}] > {Tc.yellow}Cloudflare-Tenable{Tc.rst}")
                if ip not in found:
                    found.append(ip)

        # Compare and find blacklist matches
        bls_worker(blklist, "Blacklists", Tc.blacklisted)

        # Compare and find scanner matches
        scs_worker(scnrs, "Scanners", Tc.scanner)

        # if not blacklisted
        nomatch = [ip for ip in ip_addrs if ip not in found]
        if nomatch:
            for ip in nomatch:
                print(f"{Tc.clean}{Tc.rst} [{ip}]")
                print(f"{Tc.bold}{'   Location:':10} {Tc.rst}{self.geo_locate(ip)}{Tc.bold}", end="\n")
                print(f"{Tc.bold}{'   Whois:':10} {Tc.rst}{self.whois_ip(ip)}")
                try:
                    print(f"{Tc.bold}{'   Contact:':10} {Tc.rst}{' '.join([str(i) for i in qf.find(ip)])}\n")
                except DNSException:
                    pass

    @staticmethod
    def modified_date(_file):
        """Returns the last modified date, or last download."""
        lastmod = os.stat(_file).st_mtime
        return datetime.strptime(time.ctime(lastmod), "%a %b %d %H:%M:%S %Y")

    @staticmethod
    def geo_locate(ip_addr):
        """Returns IP address geolocation."""
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"}
        try:
            url = f"https://freegeoip.live/json/{ip_addr}"
            resp = requests.get(url, headers=headers)
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
            resp.raise_for_status()
        except Exception as err:
            print(f"[Error] {err}\n")
        return None

    @staticmethod
    def whois_ip(ip_addr):
        """Returns IP address whois information."""
        try:
            # ref: https://ipwhois.readthedocs.io/en/latest/RDAP.html
            obj = IPWhois(ip_addr)
            results = obj.lookup_rdap(depth=1)
        except (exceptions.ASNRegistryError, exceptions.WhoisLookupError):
            return "No results"
        except Exception:
            return None
        else:
            entity = results["entities"][0]
            if results["asn_description"] and "NA" not in results["asn_description"]:
                contact = results["asn_description"]
            else:
                contact = results["objects"][entity]["contact"]["address"][0]["value"].replace("\r\n", ", ")
            return contact.replace("\n", ", ")

    @staticmethod
    def outdated():
        """Check feed list age."""
        try:
            file_time = os.path.getmtime(blklist)
            if (time.time() - file_time) / 3600 > 24:
                return True
        except Exception as e:
            sys.exit(e)
        else:
            return False

    @staticmethod
    def ip46(ip_addr):
        """Performs check against ip-46.com."""
        ip_addr = "".join(ip_addr)
        url = f"https://ip-46.com/{ip_addr}"
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"}
        r = requests.get(url, headers=headers)
        soup = BeautifulSoup(r.text, features="lxml")
        metadata = soup.find("meta")

        detection = soup.title.get_text()
        if "No abuse detected" not in detection:
            print(". ".join(metadata["content"].split(". ")[0:2]).split("IP-46.com", 1)[0])
            return detection
        print(Tc.clean)
        return None

    @staticmethod
    def urlhaus(ip_addr):
        """Performs check against urlhaus-api.abuse.ch."""
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        headers = CaseInsensitiveDict([("Accept", "application/json")])
        data = {"host": ip_addr}
        resp = requests.post(url, headers=headers, data=data).json()

        try:
            if resp["query_status"] == "no_results":
                print(Tc.clean)
                
            if resp["urls"]:
                for k in resp["urls"]:
                    if k["url_status"] == "online":
                        print(f"Status: {Tc.red}{k['url_status'].title()}{Tc.rst}")
                        print(f"{k['threat'].replace('_', ' ').title():12}: {k['url']}")
                        if k["tags"]:
                            print(f"Tags: {', '.join(k['tags'])}\n")
                        else:
                            print("\n")
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
