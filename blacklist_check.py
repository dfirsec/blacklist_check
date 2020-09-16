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
from ipaddress import IPv4Address, ip_address
from pathlib import Path

import coloredlogs
import dns.resolver
import requests
import urllib3
import verboselogs
from bs4 import BeautifulSoup
from ipwhois import IPWhois, exceptions

from utils.termcolors import Termcolor as tc

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.6"
__description__ = "Check IP addresses against blacklists from various sources."


# suppress dnspython feature deprecation warning
warnings.filterwarnings('ignore', category=DeprecationWarning)

# suppress certificate verification
urllib3.disable_warnings()

# Base directory
BASE_DIR = Path(__file__).resolve().parent
BLACKLIST = BASE_DIR.joinpath('utils/blacklist.json')
SCANNERS = BASE_DIR.joinpath('utils/scanners.json')
FEEDS = BASE_DIR.joinpath('utils/feeds.json')

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
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.38 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
            "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
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

    def get_list(self, url):
        # Exclude IP if 1st and last octet are zero
        ipv4 = re.compile(r"(?![0])\d{1,}\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")
        try:
            resp = requests.get(url, timeout=5, headers=self.headers(), verify=False)  # nopep8
            resp.encoding = 'utf-8'
            if resp.status_code == 200:
                return [x.group() for x in re.finditer(ipv4, resp.text)]
        except requests.exceptions.Timeout:
            print(f"    {tc.DOWNLOAD_ERR} {tc.GRAY}{url}{tc.RESET}")  # nopep8
        except requests.exceptions.HTTPError as err:
            print(f"    {tc.DOWNLOAD_ERR} {tc.ERROR} {tc.GRAY}{err}{tc.RESET}")  # nopep8
        except requests.exceptions.ConnectionError as err:
            print(f"    {tc.DOWNLOAD_ERR} {tc.ERROR} {tc.GRAY}{err}{tc.RESET}")  # nopep8
        except requests.exceptions.RequestException as err:
            print(f"    {tc.DOWNLOAD_ERR} {tc.ERROR} {tc.GRAY}{err}{tc.RESET}")  # nopep8

    @staticmethod
    def read_list():
        with open(FEEDS) as json_file:
            data = json.load(json_file)
            return [[name, url] for name, url in data['Blacklist Feeds'].items()]

    @staticmethod
    def sort_list(data):
        sort_name = sorted((name, ip_cnt) for (name, ip_cnt) in data["BLACKLIST"].items())  # nopep8
        for n, i in enumerate(sort_name, start=1):
            try:
                print(f"{tc.CYAN}{n:2}){tc.RESET} {i[0]:23}: {len(i[1]):<6,}")
            except TypeError:
                print(
                    f"{tc.CYAN}{n:2}){tc.RESET} {i[0]:23}: {tc.GRAY}[DOWNLOAD ERROR]{tc.RESET}")
                continue

    def list_count(self):
        try:
            with open(BLACKLIST) as json_file:
                data = json.load(json_file)
                self.clr_scrn()
                print(f"\n{tc.BOLD}{'BLACKLIST':28}IP COUNT{tc.RESET}")
                print("-" * 35)
                self.sort_list(data)

            print(f"\n{tc.PROCESSING} Last Modified: {self.modified_date(BLACKLIST)}")  # nopep8
        except FileNotFoundError:
            self.outdated()

    def update_list(self):
        bl_dict = dict()
        print(f"{tc.GREEN}[ Updating ]{tc.RESET}")
        with open(BLACKLIST, 'w') as json_file:
            bl_dict["BLACKLIST"] = {}
            for name, url in self.read_list():
                logger.success(f"  {tc.PROCESSING} {name:20}")
                bl_dict["BLACKLIST"][name] = self.get_list(url)  # nopep8

            # Remove duplicate IP addresses and update
            for name in bl_dict["BLACKLIST"]:
                try:
                    cleanup = list({ip for ip in bl_dict['BLACKLIST'][name]})  # nopep8
                    bl_dict['BLACKLIST'].update({name: cleanup})
                except TypeError:
                    continue

            json.dump(bl_dict, json_file,
                      ensure_ascii=False,
                      indent=4)

    def add_feed(self, feed, url):
        with open(FEEDS) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict['Blacklist Feeds']
        try:
            if feed_list[feed]:
                sys.exit(f'{tc.WARNING} Feed "{feed}" already exists.')
        except KeyError:
            feed_list.update({feed: url})
            with open(FEEDS, 'w') as json_file:
                json.dump(feeds_dict, json_file,
                          ensure_ascii=False,
                          indent=4)
            print(f'[*] Added feed: "{feed}": "{url}"')

            print(f"\n{tc.CYAN}[ Updating new feed ]{tc.RESET}")
            with open(BLACKLIST) as json_file:
                bl_dict = json.load(json_file)
                bl_list = bl_dict['BLACKLIST']

            bl_list.update({feed: self.get_list(url)})
            with open(BLACKLIST, 'w') as json_file:
                json.dump(bl_dict, json_file,
                          ensure_ascii=False,
                          indent=4)

            print(f"{tc.SUCCESS} {tc.YELLOW}{len(bl_list[feed]):,}{tc.RESET} IPs added to '{feed}'")  # nopep8

    @staticmethod
    def remove_feed():
        with open(FEEDS) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict['Blacklist Feeds']
            for n, (k, v) in enumerate(feed_list.items(), start=1):
                print(f"{tc.CYAN}{n:2}){tc.RESET} {k:25}{v}")
        try:
            # remove from feeds
            opt = int(input("\nPlease select your choice by number, or Ctrl-C to cancel: "))  # nopep8
            opt = opt - 1  # subtract 1 as enumerate starts at 1
            choice = list(feed_list)[opt]
            del feed_list[choice]
            with open(FEEDS, 'w') as json_file:
                json.dump(feeds_dict, json_file,
                          ensure_ascii=False,
                          indent=4)

            # remove from blacklist
            with open(BLACKLIST) as json_file:
                bl_dict = json.load(json_file)
                del bl_dict['BLACKLIST'][choice]
            with open(BLACKLIST, 'w') as json_file:
                json.dump(bl_dict, json_file,
                          ensure_ascii=False,
                          indent=4)

            print(f'{tc.SUCCESS} Successfully removed feed: "{choice}"')

        except KeyboardInterrupt:
            sys.exit()
        except (IndexError, ValueError, KeyError):
            sys.exit(f'{tc.ERROR} Your selection does not exist.')

    def ip_matches(self, IPS, whois=None):
        try:
            with open(BLACKLIST) as json_file:
                ip_list = json.load(json_file)

            with open(SCANNERS) as json_file:
                scanner_ip = json.load((json_file))

        except Exception as e:
            sys.exit(e)

        # Compare and find blacklist matches
        found = []
        global name
        for name, bl_ip in ip_list['BLACKLIST'].items():
            try:
                matches = set(IPS) & set(bl_ip)
                for ip in matches:
                    if whois:
                        print(f"\n{tc.BLACKLISTED} [{ip}] > {tc.YELLOW}{name}{tc.RESET}")  # nopep8
                        print(f"{tc.BOLD}{'   Location:':10} {tc.RESET}{self.geo_locate(ip)}{tc.BOLD}")  # nopep8
                        print(f"{tc.BOLD}{'   Whois:':10} {tc.RESET}{self.whois_ip(ip)}\n")  # nopep8
                        if ip not in found:
                            found.append(ip)
                    else:
                        print(f"\n{tc.BLACKLISTED} [{ip}] > {tc.YELLOW}{name}{tc.RESET}")  # nopep8
                        print(f"{tc.BOLD}{'   Location:':10} {tc.RESET}{self.geo_locate(ip)}\n")  # nopep8
                        if ip not in found:
                            found.append(ip)
            except ValueError:
                print(f"{tc.WARNING} {'INVALID IP':12} {ip}")
            except TypeError:
                continue

        # Compare and find scanner matches
        for name, sc_ip in scanner_ip['SCANNERS'].items():
            try:
                matches = set(IPS) & set(sc_ip)
                for ip in matches:
                    if whois:
                        print(f"\n{tc.SCANNER} [{ip}] > {tc.YELLOW}{name}{tc.RESET}")  # nopep8
                        print(f"{tc.BOLD}{'   Whois:':10} {tc.RESET}{self.whois_ip(ip)}")  # nopep8
                        print(f"{tc.BOLD}{'   Location:':10} {tc.RESET}{self.geo_locate(ip)}\n")  # nopep8
                        if ip not in found:
                            found.append(ip)
                    else:
                        print(
                            f"\n{tc.SCANNER} [{ip}] > {tc.YELLOW}{name}{tc.RESET}")
                        print(f"{tc.BOLD}{'   Location:':10} {tc.RESET}{self.geo_locate(ip)}\n")  # nopep8
                        if ip not in found:
                            found.append(ip)
            except ValueError:
                print(f"{tc.WARNING} {'INVALID IP':12} {ip}")
            except TypeError:
                continue

        # not blacklisted
        nomatch = [ip for ip in IPS if ip not in found]
        if nomatch:
            for ip in nomatch:
                if whois:
                    print(f"\n{tc.CLEAN}{tc.RESET} [{ip}]")
                    print(f"{tc.BOLD}{'   Location:':10} {tc.RESET}{self.geo_locate(ip)}{tc.BOLD}")  # nopep8
                    print(f"{'   Whois:':10} {tc.RESET}{self.whois_ip(ip)}\n")  # nopep8
                else:
                    print(f"\n{tc.CLEAN}{tc.RESET} [{ip}]")
                    print(f"{tc.BOLD}{'   Location:':10} {tc.RESET}{self.geo_locate(ip)}\n")  # nopep8

    @staticmethod
    def modified_date(_file):
        lastmod = os.stat(_file).st_mtime
        return datetime.strptime(time.ctime(lastmod), "%a %b %d %H:%M:%S %Y")

    @staticmethod
    def geo_locate(ip):
        try:
            url = f'https://freegeoip.live/json/{ip}'
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
    def whois_ip(ip):
        try:
            # ref: https://ipwhois.readthedocs.io/en/latest/RDAP.html
            obj = IPWhois(ip)
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
        # Check if blacklist is outdated
        try:
            file_time = os.path.getmtime(BLACKLIST)
            if (time.time() - file_time) / 3600 > 24:
                return True
        except Exception as e:
            sys.exit(e)
        else:
            return False

    @staticmethod
    def ip46_qry(ip):
        ip = ''.join(ip)
        url = f'https://ip-46.com/{ip}'
        r = requests.get(url)
        soup = BeautifulSoup(r.text, features="lxml")
        metadata = soup.find('meta')

        detection = soup.title.get_text()
        if "No abuse detected" not in detection:
            print('. '.join(metadata["content"].split(
                '. ')[0:2]).split("IP-46.com", 1)[0])
            return detection
        else:
            print(tc.CLEAN)

    @staticmethod
    def urlhaus_base(ip):
        base_url = "https://urlhaus-api.abuse.ch/v1/host/"
        resp = requests.post(base_url, data={"host": ip})

        if resp.status_code == 200:
            return resp.json()

    def urlhaus_qry(self, ip):
        if self.urlhaus_base(ip)['query_status'] == "no_results":
            print(tc.CLEAN)
        else:
            if self.urlhaus_base(ip)['urls']:
                for k in self.urlhaus_base(ip)['urls']:
                    if k['url_status'] == "online":
                        print(f"Status: {tc.RED}{k['url_status'].title()}{tc.RESET}")  # nopep8
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


class DNSBL(object):
    def __init__(self, host, threads):
        self.host = host
        self.threads = threads
        self.COUNT = 0

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

        with open(FEEDS) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict['DNS Blacklists']['DNSBL']

        diff = [x for x in alive if x not in feed_list]
        if len(diff) > 1:
            print(f"{tc.GREEN} [ Updating RBLs ]{tc.RESET}")
            for item in diff:
                if item not in feed_list:
                    logger.success(f"[+] Adding {item}")
                    feed_list.append(item)

            with open(FEEDS, 'w') as json_file:
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
        codes = ['0.0.0.1', '127.0.0.1', '127.0.0.2', '127.0.0.3',
                 '127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7',
                 '127.0.0.9', '127.0.1.4', '127.0.1.5', '127.0.1.6',
                 '127.0.0.10', '127.0.0.11', '127.0.0.39', '127.0.1.103',
                 '127.0.1.104', '127.0.1.105', '127.0.1.106', '127.0.1.108']

        try:
            qry = ip_address(host).reverse_pointer.replace('.in-addr.arpa', '') + "." + blacklist  # nopep8
        except Exception:
            qry = host + "." + blacklist

        answer = self.resolve_dns(qry)
        try:
            if any(str(answer[0]) in s for s in codes):
                logger.success(f"{tc.RED}\u2716{tc.RESET}  Blacklisted > {blacklist}")  # nopep8
                self.COUNT += 1
        except Exception:
            pass

    def dnsbl_mapper(self, threads=None):
        with open(FEEDS) as json_file:
            data = json.load(json_file)
        dnsbl = [url for url in data['DNS Blacklists']['DNSBL']]

        with ThreadPoolExecutor(max_workers=threads) as executor:
            dnsbl_map = {
                executor.submit(self.dnsbl_query, url): url for url in dnsbl
            }
            for future in as_completed(dnsbl_map):
                try:
                    future.result()
                except Exception as exc:
                    print(f"Exception generated: {exc}")  # nopep8
            if self.COUNT:
                host = str(''.join(self.host))
                logger.warning(f"\n[*] {host} is listed in {self.COUNT} block lists")  # nopep8


def parser():
    parser = argparse.ArgumentParser(description="IP Blacklist Check")
    group1 = parser.add_mutually_exclusive_group()
    group2 = parser.add_mutually_exclusive_group()
    parser.add_argument('-t', dest='threads', nargs='?', type=int, metavar='threads',
                        default=25, help="threads for rbl check (default 25, max 50)")
    parser.add_argument('-w', dest='whois', action='store_true',
                        help="perform ip whois lookup")
    
    group1.add_argument('-u', dest='update', action='store_true',
                        help="update blacklist feeds")
    group1.add_argument('-fu', dest='force', action='store_true',
                        help="force update of all feeds")
    group1.add_argument('-s', dest='show', action='store_true',
                        help="list blacklist feeds")
    
    group2.add_argument('-q', dest='query', nargs='+', metavar='query',
                        help="query a single or multiple ip addrs")
    group2.add_argument('-f', dest='file', metavar='file',
                        help="query a list of ip addresses from file")
    group2.add_argument('-i', dest='insert', action='store_true',
                        help='insert a new blacklist feed')
    group2.add_argument('-r', dest='remove', action='store_true',
                        help='remove an existing blacklist feed')

    return parser


def main():
    p = parser()
    args = p.parse_args()

    pbl = ProcessBL()
    dbl = DNSBL(host=args.query, threads=args.threads)

    # check arguments
    if len(sys.argv[1:]) == 0:
        p.print_help()
        p.exit()

    if not BLACKLIST.exists():
        print(f"{tc.YELLOW}Blacklist file is missing...{tc.RESET}\n")
        pbl.update_list()

    if args.query:
        IPs = []
        for arg in args.query:
            try:
                IPv4Address(arg.replace(',', ''))
                IPs.append(arg.replace(',', ''))
            except ValueError:
                sys.exit(f"{tc.WARNING} {'INVALID IP':12} {arg}")
        if args.whois:
            print(f"{tc.DOTSEP}\n{tc.GREEN}[ Performing IP whois lookup ]{tc.RESET}\n")  # nopep8
            pbl.ip_matches(IPs, whois=args.whois)
        else:
            pbl.ip_matches(IPs)

        if len(args.query) == 1:
            print(f"\n{tc.DOTSEP}\n{tc.GREEN}[ Reputation Block List Check ]{tc.RESET}")  # nopep8
            dbl.dnsbl_mapper(args.threads)

            print(f"\n{tc.DOTSEP}\n{tc.GREEN}[ IP-46 IP Intel Check ]{tc.RESET}")  # nopep8
            pbl.ip46_qry(args.query)

            print(f"\n{tc.DOTSEP}\n{tc.GREEN}[ URLhaus Check ]{tc.RESET}")  # nopep8
            pbl.urlhaus_qry(args.query)

    if args.file:
        pbl.outdated()
        try:
            with open(args.file) as infile:
                IPs = [line.strip() for line in infile.readlines()]
        except FileNotFoundError:
            sys.exit(f"{tc.WARNING} No such file: {args.file}")
        pbl.ip_matches(IPs)

    if args.show:
        pbl.list_count()
        pbl.outdated()

    if args.update:
        print(tc.CHECK_FEEDS)
        if bool(pbl.outdated()):
            pbl.update_list()
            pbl.list_count()
        if bool(dbl.update_dnsbl()):
            dbl.update_dnsbl()
        else:
            print(tc.CURRENT)

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
                print(f"[*] Checking URL{tc.RESET}")
                try:
                    urllib.request.urlopen(url, timeout=3)
                    print(f"[*] URL is good")
                    confirm = input(f'[?] Insert the following feed? \nName: {feed} | URL: {url} {tc.YELLOW}(Y/n){tc.RESET}: ')  # nopep8
                    if confirm.lower() == 'y':
                        pbl.add_feed(feed=feed.replace(',', ''),
                                     url=url.replace(',', ''))
                    else:
                        sys.exit(f"[!] Request canceled")
                    break

                except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
                    print(f"{tc.ERROR} URL '{url}' appears to be invalid or inaccessible.")  # nopep8
            else:
                sys.exit(f"{tc.ERROR} Please include the feed name and url.")
                break

    if args.remove:
        pbl.remove_feed()

    if args.threads > 50:
        sys.exit(f"{tc.ERROR} Exceeded max of 50 threads.{tc.RESET}")  # nopep8


if __name__ == "__main__":
    banner = fr'''
        ____  __           __   ___      __     ________              __  
       / __ )/ /___ ______/ /__/ (_)____/ /_   / ____/ /_  ___  _____/ /__
      / __  / / __ `/ ___/ //_/ / / ___/ __/  / /   / __ \/ _ \/ ___/ //_/
     / /_/ / / /_/ / /__/ ,< / / (__  ) /_   / /___/ / / /  __/ /__/ ,<   
    /_____/_/\__,_/\___/_/|_/_/_/____/\__/   \____/_/ /_/\___/\___/_/|_|
     v{__version__}
    '''

    print(f"{tc.CYAN}{banner}{tc.RESET}")
    main()
