import argparse
import json
import logging
import os
import platform
import random
import re
import sys
import time
import urllib
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.client import responses
from ipaddress import IPv4Address, ip_address
from pathlib import Path

import coloredlogs
import dns.resolver
import httpx
import requests
import trio
import urllib3
import verboselogs
from bs4 import BeautifulSoup
from ipwhois import IPWhois, exceptions
from ruamel.yaml import YAML

from utils.termcolors import Termcolor as Tc

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.1.2"
__description__ = "Check IP addresses against blacklists from various sources."


# suppress dnspython feature deprecation warning
warnings.filterwarnings('ignore', category=DeprecationWarning)

# suppress certificate verification
urllib3.disable_warnings()

# Base directory
parent = Path(__file__).resolve().parent
blklist = parent.joinpath('utils/blacklist.json')
scnrs = parent.joinpath('utils/scanners.json')
feeds = parent.joinpath('utils/feeds.json')
settings = parent.joinpath('utils/settings.yml')

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

    def ip_matches(self, ip_addrs, whois=None):
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
                        if whois:
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
                if whois:
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


class VirusTotalChk():
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey='
        if self.api_key is None:
            sys.exit(f"{Tc.yellow}* Verify that you have provided your API key{Tc.rst}")  # nopep8

    # ---[ VirusTotal Connection ]---
    @staticmethod
    def vt_connect(url):
        try:
            resp = requests.get(url, timeout=5)
            resp.encoding = 'utf-8'
            if resp.status_code == 401:
                sys.exit("[error] Verify that you have provided a valid API key.")  # nopep8
            if resp.status_code != 200:
                print(f" {Tc.error} {Tc.gray} {resp.status_code} {responses[resp.status_code]}{url}{Tc.rst}")  # nopep8
            else:
                return resp.json()
        except (requests.exceptions.Timeout, requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError, requests.exceptions.RequestException):
            print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{Tc.rst}")  # nopep8

    def vt_run(self, ip_addr):
        url = f"{self.base_url}{self.api_key}&ip={''.join(ip_addr)}"
        data = json.dumps(self.vt_connect(url))
        json_resp = json.loads(data)
        if json_resp['response_code'] == 1:
            if json_resp['detected_urls']:
                print(f"{Tc.mag}= URLs ={Tc.rst}")
                for k in json_resp['detected_urls']:
                    print(f"{Tc.red}>{Tc.rst} {k['url']}")
                    print(f"  Positives: {k['positives']}")
                    print(f"  Scan Date: {k['scan_date']}\n")
            if json_resp['detected_downloaded_samples']:
                print(f"{Tc.mag}= Hashes ={Tc.rst}")
                for k in json_resp['detected_downloaded_samples']:
                    print(f"{Tc.red}>{Tc.rst} {k['sha256']}")
                    print(f"  Positives: {k['positives']}")
                    print(f"  Date: {k['date']}\n")
        elif json_resp['response_code'] == 0:
            print(Tc.clean)


class DNSBL():
    def __init__(self, host, threads):
        self.host = host
        self.threads = threads
        self.cnt = 0

    @staticmethod
    def update_dnsbl():
        url = 'http://multirbl.valli.org/list/'
        page = requests.get(url).text
        soup = BeautifulSoup(page, 'html.parser')
        table = soup.find("table")
        table_rows = table.find_all('tr')

        alive = []
        for tr in table_rows:
            td = tr.find_all('td')
            row = [i.text for i in td]
            if '(hidden)' not in row:
                alive.append(row[2])

        with open(feeds) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict['DNS Blacklists']['DNSBL']

        diff = [x for x in alive if x not in feed_list]
        if len(diff) > 1:
            print(f"{Tc.green} [ Updating RBLs ]{Tc.rst}")
            for item in diff:
                if item not in feed_list:
                    logger.success(f"[+] Adding {item}")
                    feed_list.append(item)

            with open(feeds, 'w') as json_file:
                json.dump(feeds_dict, json_file,
                          ensure_ascii=False,
                          indent=4)
        else:
            return False

    @staticmethod
    def resolve_dns(qry):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answer = resolver.resolve(qry, "A")

            return answer

        except (dns.resolver.NXDOMAIN,
                dns.resolver.Timeout,
                dns.resolver.NoNameservers,
                dns.resolver.NoAnswer):
            pass
        except DeprecationWarning:
            pass

    def dnsbl_query(self, blacklist):
        host = str(''.join(self.host))

        # Return Codes
        codes = ['0.0.0.1', '127.0.0.1', '127.0.0.2',
                 '127.0.0.3', '127.0.0.4', '127.0.0.5',
                 '127.0.0.6', '127.0.0.7', '127.0.0.9',
                 '127.0.0.10', '127.0.0.11', '127.0.0.39',
                 '127.0.0.45', '127.0.1.4', '127.0.1.5',
                 '127.0.1.6', '127.0.1.20', '127.0.1.103',
                 '127.0.1.104', '127.0.1.105', '127.0.1.106',
                 '127.0.1.108', '10.0.2.3']

        try:
            qry = ip_address(host).reverse_pointer.replace('.in-addr.arpa', '') + "." + blacklist  # nopep8
        except Exception:
            qry = host + "." + blacklist

        answer = self.resolve_dns(qry)
        try:
            if any(str(answer[0]) in s for s in codes):
                logger.success(f"{Tc.red}\u2716{Tc.rst}  Blacklisted > {blacklist}")  # nopep8
                self.cnt += 1
        except Exception:
            pass

    def dnsbl_mapper(self, threads=None):
        with open(feeds) as json_file:
            data = json.load(json_file)
        dnsbl = [url for url in data['DNS Blacklists']['DNSBL']]

        with ThreadPoolExecutor(max_workers=threads) as executor:
            dnsbl_map = {executor.submit(self.dnsbl_query, url): url for url in dnsbl}  # nopep8
            for future in as_completed(dnsbl_map):
                url = dnsbl_map[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"Exception generated: {url} {exc}")  # nopep8
            if self.cnt:
                host = str(''.join(self.host))
                logger.warning(f"\n[*] {host} is listed in {self.cnt} block lists")  # nopep8


def parser():
    p = argparse.ArgumentParser(description="IP Blacklist Check")
    group1 = p.add_mutually_exclusive_group()
    group2 = p.add_mutually_exclusive_group()
    p.add_argument('-t', dest='threads', nargs='?', type=int, metavar='threads',
                   default=25, help="threads for rbl check (default 25, max 50)")
    p.add_argument('-w', dest='whois', action='store_true',
                   help="perform ip whois lookup")

    group1.add_argument('-u', dest='update', action='store_true',
                        help="update blacklist feeds")
    group1.add_argument('-fu', dest='force', action='store_true',
                        help="force update of all feeds")
    group1.add_argument('-s', dest='show', action='store_true',
                        help="show blacklist feeds")
    group1.add_argument('-vt', dest='vt_query', action='store_true',
                        help="check virustotal for ip info")

    group2.add_argument('-q', dest='query', nargs='+', metavar='query',
                        help="query a single or multiple ip addrs")

    group2.add_argument('-f', dest='file', metavar='file',
                        help="query a list of ip addresses from file")
    group2.add_argument('-i', dest='insert', action='store_true',
                        help='insert a new blacklist feed')
    group2.add_argument('-r', dest='remove', action='store_true',
                        help='remove an existing blacklist feed')

    return p


def main():
    p = parser()
    args = p.parse_args()

    pbl = ProcessBL()
    dbl = DNSBL(host=args.query, threads=args.threads)

    # check arguments
    if len(sys.argv[1:]) == 0:
        p.print_help()
        p.exit()

    if not blklist.exists() or os.stat(blklist).st_size == 0:
        print(f"{Tc.yellow}Blacklist file is missing...{Tc.rst}\n")
        pbl.update_list()

    if args.query:
        ip_addrs = []
        for arg in args.query:
            try:
                IPv4Address(arg.replace(',', ''))
                ip_addrs.append(arg.replace(',', ''))
            except ValueError:
                sys.exit(f"{Tc.warning} {'INVALID IP':12} {arg}")

        if args.whois:
            print(f"{Tc.dotsep}\n{Tc.green}[ Performing IP whois lookup ]{Tc.rst}\n")  # nopep8
            pbl.ip_matches(ip_addrs, whois=args.whois)
        else:
            pbl.ip_matches(ip_addrs)

        if len(args.query) == 1:
            print(f"\n{Tc.dotsep}\n{Tc.green}[ Reputation Block List Check ]{Tc.rst}")  # nopep8
            dbl.dnsbl_mapper(args.threads)

            print(f"\n{Tc.dotsep}\n{Tc.green}[ IP-46 IP Intel Check ]{Tc.rst}")  # nopep8
            pbl.ip46_qry(args.query)

            print(f"\n{Tc.dotsep}\n{Tc.green}[ URLhaus Check ]{Tc.rst}")  # nopep8
            pbl.urlhaus_qry(args.query)

            # VirusTotal Query
            if args.vt_query:
                print(f"\n{Tc.dotsep}\n{Tc.green}[ VirusTotal Check ]{Tc.rst}")  # nopep8
                # ---[ Configuration Parser ]---
                yaml = YAML()
                with open(settings) as _file:
                    config = yaml.load(_file)

                # verify vt api key
                if not config['VIRUS-TOTAL']['api_key']:
                    logger.warning("Please add VT API key to the 'settings.yml' file, or enter it below")  # nopep8
                    try:
                        user_vt_key = input("Enter key: ")
                        config['VIRUS-TOTAL']['api_key'] = user_vt_key

                        with open(settings, 'w') as output:
                            yaml.dump(config, output)
                            
                        api_key = config['VIRUS-TOTAL']['api_key']
                        virustotal = VirusTotalChk(api_key)
                        virustotal.vt_run(ip_addrs)
                    except KeyboardInterrupt:
                        sys.exit("Exited")
                else:
                    api_key = config['VIRUS-TOTAL']['api_key']
                    virustotal = VirusTotalChk(api_key)
                    virustotal.vt_run(ip_addrs)

    if args.file:
        pbl.outdated()
        try:
            with open(args.file) as infile:
                ip_addrs = [line.strip() for line in infile.readlines()]
        except FileNotFoundError:
            sys.exit(f"{Tc.warning} No such file: {args.file}")
        pbl.ip_matches(ip_addrs)

    if args.show:
        pbl.list_count()
        pbl.outdated()

    if args.update:
        print(Tc.chk_feeds)
        if bool(pbl.outdated()):
            pbl.update_list()
            pbl.list_count()
        if bool(dbl.update_dnsbl()):
            dbl.update_dnsbl()
        else:
            print(Tc.current)

    if args.force:
        pbl.update_list()
        dbl.update_dnsbl()
        pbl.list_count()

    if args.insert:
        while True:
            try:
                feed = input("[>] Feed name: ")
                url = input("[>] Feed url: ")
            except KeyboardInterrupt:
                sys.exit()
            if feed and url:
                print(f"[*] Checking URL{Tc.rst}")
                try:
                    urllib.request.urlopen(url, timeout=3)
                    print(f"[*] URL is good")
                    confirm = input(f'[?] Insert the following feed? \nName: {feed} | URL: {url} {Tc.yellow}(Y/n){Tc.rst}: ')  # nopep8
                    if confirm.lower() == 'y':
                        pbl.add_feed(feed=feed.replace(',', ''),
                                     url=url.replace(',', ''))
                    else:
                        sys.exit(f"[!] Request canceled")
                    break

                except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
                    print(f"{Tc.error} URL '{url}' appears to be invalid or inaccessible.")  # nopep8
            else:
                sys.exit(f"{Tc.error} Please include the feed name and url.")

    if args.remove:
        pbl.remove_feed()

    if args.threads > 50:
        sys.exit(f"{Tc.error} Exceeded max of 50 threads.{Tc.rst}")  # nopep8


if __name__ == "__main__":
    banner = fr'''
        ____  __           __   ___      __     ________              __  
       / __ )/ /___ ______/ /__/ (_)____/ /_   / ____/ /_  ___  _____/ /__
      / __  / / __ `/ ___/ //_/ / / ___/ __/  / /   / __ \/ _ \/ ___/ //_/
     / /_/ / / /_/ / /__/ ,< / / (__  ) /_   / /___/ / / /  __/ /__/ ,<   
    /_____/_/\__,_/\___/_/|_/_/_/____/\__/   \____/_/ /_/\___/\___/_/|_|
                                                                {__version__}
    '''

    print(f"{Tc.cyan}{banner}{Tc.rst}")

    # check if python version
    if not sys.version_info.major == 3 and sys.version_info.minor >= 8:
        print("Python 3.8 or higher is required.")
        sys.exit(f"You are using Python {sys.version_info.major}.{sys.version_info.minor}")  # nopep8

    # check if new version is available
    try:
        latest = requests.get(f"https://api.github.com/repos/dfirsec/{parent.stem}/releases/latest").json()['tag_name']  # nopep8
        if latest != __version__:
            print(f"{Tc.yellow}* Release {latest} of {parent.stem} is available{Tc.rst}")  # nopep8
    except Exception as err:
        print(f"{Tc.error} [Error]{Tc.rst} {err}\n")

    main()
