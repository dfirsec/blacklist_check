import json
import logging
import os
import platform
import random
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
from ipwhois import IPWhois, exceptions

from utils.termcolors import Termcolor as Tc

# suppress dnspython feature deprecation warning
warnings.filterwarnings('ignore', category=DeprecationWarning)

# suppress certificate verification
urllib3.disable_warnings()

# Base directory
parent = Path(__file__).resolve().parent.parent
blklist = parent.joinpath('resc/blacklist.json')
scnrs = parent.joinpath('resc/scanners.json')
feeds = parent.joinpath('resc/feeds.json')

logger = verboselogs.VerboseLogger(__name__)
logger.setLevel(logging.INFO)
coloredlogs.install(level='DEBUG', logger=logger, fmt='%(message)s',
                    level_styles={
                        'notice': {'color': 'black', 'bright': True},
                        'warning': {'color': 'yellow'},
                        'success': {'color': 'white', 'bold': True},
                        'error': {'color': 'red'},
                        'critical': {'background': 'red'}
                    })


class ProcessBL():
    @staticmethod
    def headers():
        ua_list = [
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/40.0.2214.38 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 "
            "Safari/601.3.9",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 "
            "Safari/537.36 Edge/12.246",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 "
            "Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 "
            "Safari/537.36",
            "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 "
            "Safari/537.36",
            "Mozilla/5.0 (X11; Linux i686; rv:30.0) Gecko/20100101 Firefox/42.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1"
        ]
        use_headers = {'user-agent': random.choice(ua_list)}
        return use_headers

    @staticmethod
    def clr_scrn():
        if platform.system() == 'Windows':
            os.system('cls')
        else:
            os.system('clear')

    async def fetch(self, url):
        async with httpx.AsyncClient(verify=False) as client:
            try:
                resp = await client.get(url, timeout=10.0, headers=self.headers())
                resp.raise_for_status()
                return resp.text
            except httpx.TimeoutException:
                print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{url}{Tc.rst}")  # nopep8
            except httpx.RequestError:
                print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{url}{Tc.rst}")  # nopep8
            except httpx.HTTPStatusError:
                print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{url}{Tc.rst}")  # nopep8

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
        """ Returns the name and url for each feed """
        with open(feeds) as json_file:
            data = json.load(json_file)
            return [[name, url] for name, url in data['Blacklist Feeds'].items()]

    @staticmethod
    def sort_list(data):
        sort_name = sorted((name, ip_cnt) for (name, ip_cnt) in data['Blacklists'].items())  # nopep8
        for n, i in enumerate(sort_name, start=1):
            try:
                print(f"{Tc.cyan}{n:2}){Tc.rst} {i[0]:23}: {len(i[1]):<6,}")
            except TypeError:
                print(
                    f"{Tc.cyan}{n:2}){Tc.rst} {i[0]:23}: {Tc.gray}[DOWNLOAD error]{Tc.rst}")
                continue

    def list_count(self):
        """ Returns a count of IP addresses for each feed """
        try:
            with open(blklist) as json_file:
                data = json.load(json_file)
                self.clr_scrn()
                print(f"\n{Tc.bold}{'Blacklists':28}IP cnt{Tc.rst}")
                print("-" * 35)
                self.sort_list(data)

            print(f"\n{Tc.processing} Last Modified: {self.modified_date(blklist)}")  # nopep8
        except FileNotFoundError:
            self.outdated()

    def update_list(self):
        """ Updates the feed list with latest IP addresses """
        bl_dict = dict()
        print(f"{Tc.green}[ Updating ]{Tc.rst}")
        with open(blklist, 'w') as json_file:
            bl_dict['Blacklists'] = {}
            for name, url in self.read_list():
                logger.success(f"  {Tc.processing} {name:20}")
                bl_dict['Blacklists'][name] = self.get_feeds(url)  # nopep8

            # Remove duplicate IP addresses and update
            for name in bl_dict['Blacklists']:
                try:
                    cleanup = list({ip for ip in bl_dict['Blacklists'][name]})  # nopep8
                    bl_dict['Blacklists'].update({name: cleanup})
                except TypeError:
                    continue

            json.dump(bl_dict, json_file,
                      ensure_ascii=False,
                      indent=4)

    def add_feed(self, feed, url):
        """ Manually add feed """
        with open(feeds) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict['Blacklist Feeds']
        try:
            if feed_list[feed]:
                sys.exit(f'{Tc.warning} Feed "{feed}" already exists.')
        except KeyError:
            feed_list.update({feed: url})
            with open(feeds, 'w') as json_file:
                json.dump(feeds_dict, json_file,
                          ensure_ascii=False,
                          indent=4)
            print(f'[*] Added feed: "{feed}": "{url}"')

            print(f"\n{Tc.cyan}[ Updating new feed ]{Tc.rst}")
            with open(blklist) as json_file:
                bl_dict = json.load(json_file)
                bl_list = bl_dict['Blacklists']

            bl_list.update({feed: self.get_feeds(url)})
            with open(blklist, 'w') as json_file:
                json.dump(bl_dict, json_file,
                          ensure_ascii=False,
                          indent=4)

            print(f"{Tc.success} {Tc.yellow}{len(bl_list[feed]):,}{Tc.rst} IPs added to '{feed}'")  # nopep8

    @staticmethod
    def remove_feed():
        """ Remove a feed item """
        with open(feeds) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict['Blacklist Feeds']
            for n, (k, v) in enumerate(feed_list.items(), start=1):
                print(f"{Tc.cyan}{n:2}){Tc.rst} {k:25}{v}")
        try:
            # remove from feeds
            opt = int(input("\nPlease select your choice by number, or Ctrl-C to cancel: "))  # nopep8
            opt = opt - 1  # subtract 1 as enumerate starts at 1
            choice = list(feed_list)[opt]
            del feed_list[choice]
            with open(feeds, 'w') as json_file:
                json.dump(feeds_dict, json_file,
                          ensure_ascii=False,
                          indent=4)

            # remove from blacklist
            with open(blklist) as json_file:
                bl_dict = json.load(json_file)
                del bl_dict['Blacklists'][choice]
            with open(blklist, 'w') as json_file:
                json.dump(bl_dict, json_file,
                          ensure_ascii=False,
                          indent=4)

            print(f'{Tc.success} Successfully removed feed: "{choice}"')

        except KeyboardInterrupt:
            sys.exit()
        except (IndexError, ValueError, KeyError):
            sys.exit(f'{Tc.error} Your selection does not exist.')

    def ip_matches(self, ip_addrs):
        found = []

        def worker(json_list, list_name, list_type):
            global name, ip
            with open(json_list) as json_file:
                ip_list = json.load(json_file)

            for name, item in ip_list[list_name].items():
                try:
                    matches = set(ip_addrs) & set(item)
                    for ip in matches:
                        print(f"\n{list_type} [{ip}] > {Tc.yellow}{name}{Tc.rst}")  # nopep8
                        print(f"{Tc.bold}{'   Location:':10} {Tc.rst}{self.geo_locate(ip)}{Tc.bold}")  # nopep8
                        print(f"{Tc.bold}{'   Whois:':10} {Tc.rst}{self.whois_ip(ip)}\n")  # nopep8
                        if ip not in found:
                            found.append(ip)
                except ValueError:
                    print(f"{Tc.warning} {'INVALID IP':12} {ip}")
                except TypeError:
                    continue

        # Compare and find blacklist matches
        worker(blklist, 'Blacklists', Tc.blacklisted)

        # Compare and find scanner matches
        # ref: https://wiki.ipfire.org/configuration/firewall/blockshodan
        worker(scnrs, 'Scanners', Tc.scanner)

        # if not blacklisted
        nomatch = [ip for ip in ip_addrs if ip not in found]
        if nomatch:
            for ip in nomatch:
                print(f"\n{Tc.clean}{Tc.rst} [{ip}]")
                print(f"{Tc.bold}{'   Location:':10} {Tc.rst}{self.geo_locate(ip)}{Tc.bold}")  # nopep8
                print(f"{'   Whois:':10} {Tc.rst}{self.whois_ip(ip)}\n")  # nopep8

    @staticmethod
    def modified_date(_file):
        """ Returns the last modified date, or last download """
        lastmod = os.stat(_file).st_mtime
        return datetime.strptime(time.ctime(lastmod), "%a %b %d %H:%M:%S %Y")

    @staticmethod
    def geo_locate(ip_addr):
        """ Returns IP address geolocation """
        try:
            url = f'https://freegeoip.live/json/{ip_addr}'
            resp = requests.get(url)
            if resp.status_code == 200:
                data = json.loads(resp.content.decode('utf-8'))
                city = data['city']
                state = data['region_name']
                country = data['country_name']
                iso_code = data['country_code']
                if city and state and iso_code and city != state:
                    return f"{city}, {state} ({iso_code})"
                elif city:
                    return f"{city}, {country} ({iso_code})"
                else:
                    return f"{country} ({iso_code})"
            else:
                resp.raise_for_status()
        except Exception as err:
            print(f"[error] {err}\n")

    @staticmethod
    def whois_ip(ip_addr):
        """ Returns IP address whois information """
        try:
            # ref: https://ipwhois.readthedocs.io/en/latest/RDAP.html
            obj = IPWhois(ip_addr)
            results = obj.lookup_whois()
            return results["nets"][0]["description"]
            # results = obj.lookup_rdap(depth=1)
            # return results["network"]["name"]
        except (exceptions.ASNRegistryError, exceptions.WhoisLookupError):
            return "No results"
        except Exception as err:
            return err

    @staticmethod
    def outdated():
        """ Checks if feed list is outdated (within last 24 hours) """
        try:
            file_time = os.path.getmtime(blklist)
            if (time.time() - file_time) / 3600 > 24:
                return True
        except Exception as e:
            sys.exit(e)
        else:
            return False

    @staticmethod
    def ip46_qry(ip_addr):
        ip_addr = ''.join(ip_addr)
        url = f'https://ip-46.com/{ip_addr}'
        r = requests.get(url)
        soup = BeautifulSoup(r.text, features="lxml")
        metadata = soup.find('meta')

        detection = soup.title.get_text()
        if "No abuse detected" not in detection:
            print('. '.join(metadata["content"].split('. ')[0:2]).split("IP-46.com", 1)[0])  # nopep8
            return detection
        else:
            print(Tc.clean)

    @staticmethod
    def urlhaus_base(ip_addr):
        base_url = "https://urlhaus-api.abuse.ch/v1/host/"
        resp = requests.post(base_url, data={"host": ip_addr})

        if resp.status_code == 200:
            return resp.json()

    def urlhaus_qry(self, ip_addr):
        if self.urlhaus_base(ip_addr)['query_status'] == "no_results":
            print(Tc.clean)
        else:
            if self.urlhaus_base(ip_addr)['urls']:
                for k in self.urlhaus_base(ip_addr)['urls']:
                    if k['url_status'] == "online":
                        print(f"Status: {Tc.red}{k['url_status'].title()}{Tc.rst}")  # nopep8
                        print(f"{k['threat'].replace('_', ' ').title():12}: {k['url']}")  # nopep8
                        if k['tags']:
                            print(f"Tags: {', '.join(k['tags'])}\n")  # nopep8
                        else:
                            print("\n")
                    else:
                        print(f"Status: {k['url_status'].title()}")
                        print(f"{k['threat'].replace('_', ' ').title():12}: {k['url']}")  # nopep8
                        if k['tags']:
                            print(f"Tags: {', '.join(k['tags'])}\n")  # nopep8
                        else:
                            print("\n")
