#!/usr/bin/env python

__author__ = "DFIRSec (@pulsecode)"
__version__ = "2.0"
__description__ = "Check IP addresses against blacklists from various sources."

import argparse
import json
import os
import platform
import random
import re
import sys
import time
import urllib
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path

import requests
from ipwhois import IPWhois, exceptions

from utils.termcolors import Termcolor as tc

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Base files
BLACKLIST = BASE_DIR.joinpath('utils/blacklist.json')
SCANNERS = BASE_DIR.joinpath('utils/scanners.json')
FEEDS = BASE_DIR.joinpath('utils/feeds.json')


class ProcessBL():
    def __init__(self):
        pass

    def headers(self):
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

    def clr_scrn(self):
        if platform.system() == 'Windows':
            os.system('cls')
        else:
            os.system('clear')

    def get_list(self, url):
        # Exclude IP if 1st and last octet are zero
        ipv4 = re.compile(r"(?![0])\d{1,}\.\d{1,3}\.\d{1,3}\.(?![0])\d{1,3}")
        try:
            r = requests.get(url, timeout=5, headers=self.headers())
            r.encoding = 'utf-8'
            if r.status_code == 200:
                return [x.group() for x in re.finditer(ipv4, r.text)]
        except requests.exceptions.Timeout:
            print(f"    {tc.DOWNLOAD_ERR} {tc.GRAY}{url}{tc.RESET}")  # nopep8
        except requests.exceptions.HTTPError as err:
            print(f"    {tc.DOWNLOAD_ERR} {tc.ERROR} {tc.GRAY}{err}{tc.RESET}")  # nopep8
        except requests.exceptions.ConnectionError as err:
            print(f"    {tc.DOWNLOAD_ERR} {tc.ERROR} {tc.GRAY}{err}{tc.RESET}")  # nopep8
        except requests.exceptions.RequestException as err:
            print(f"    {tc.DOWNLOAD_ERR} {tc.ERROR} {tc.GRAY}{err}{tc.RESET}")  # nopep8

    def read_list(self):
        with open(FEEDS) as json_file:
            data = json.load(json_file)
            return [[name, url] for name, url in data['Blacklist Feeds'].items()]

    ### For future use ###
    def sort_list(self, data):
        sort_name = sorted((name, ip_cnt) for (name, ip_cnt) in data["BLACKLIST"].items())  # nopep8
        for i in sort_name:
            try:
                print(f"{i[0]:23}: {len(i[1]):<6,}")
            except TypeError:
                print(f"{i[0]:23}: {tc.GRAY}[DOWNLOAD ERROR]{tc.RESET}")
                continue

    def list_count(self, opt=None):
        try:
            with open(BLACKLIST) as json_file:
                data = json.load(json_file)
                self.clr_scrn()
                print(f"\n{tc.BOLD}{'LIST':25} COUNT{tc.RESET}")
                print("-" * 35)
                self.sort_list(data)

            print(f"\n{tc.PROCESSING} Last Modified: {self.modified_date(BLACKLIST)}")  # nopep8
        except FileNotFoundError:
            self.outdated_file()

    def update_list(self):
        bl_dict = dict()
        print(f"{tc.GREEN} [ Updating ]")
        with open(BLACKLIST, 'w') as json_file:
            bl_dict["BLACKLIST"] = {}
            for name, url in self.read_list():
                print(f"  {tc.PROCESSING} {name:20}", end='\t\r')
                bl_dict["BLACKLIST"][name] = self.get_list(url)  # nopep8

            # Remove duplicate IP addresses and update
            for name in bl_dict["BLACKLIST"]:
                try:
                    cleanup = list({ip for ip in bl_dict['BLACKLIST'][name]})  # nopep8
                    bl_dict['BLACKLIST'].update({name: cleanup})
                except TypeError:
                    continue

            json.dump(bl_dict, json_file, ensure_ascii=False, indent=4)

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
                          ensure_ascii=False, indent=4)
            print(f'{tc.SUCCESS} Added feed: "{feed}": "{url}"')
            
            print(f"\n{tc.CYAN}[ Updating new feed ]{tc.RESET}")
            with open(BLACKLIST) as json_file:
                bl_dict = json.load(json_file)
                bl_list = bl_dict['BLACKLIST']

            bl_list.update({feed: self.get_list(url)})
            with open(BLACKLIST, 'w') as json_file:
                json.dump(bl_dict, json_file, ensure_ascii=False, indent=4)  # nopep8
            
            print(f"{tc.SUCCESS} {tc.YELLOW}{len(bl_list[feed]):,}{tc.RESET} IPs added to '{feed}'")  # nopep8
            
            # for n, (k, v) in enumerate(feed_list.items(), start=1):
            #     print(f"{tc.CYAN}{n:2}){tc.RESET} {k:25}{v}")

    # def remove_feed(self, feed):
    def remove_feed(self):
        with open(FEEDS) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict['Blacklist Feeds']
            for n, (k, v) in enumerate(feed_list.items(), start=1):
                print(f"{tc.CYAN}{n:2}){tc.RESET} {k:25}{v}")
        try:
            # remove from feeds
            opt = int(input("\nPlease select your choice by number: "))
            opt = opt - 1  # subtract 1 as enumerate starts at 1
            choice = list(feed_list)[opt]
            del feed_list[choice]
            with open(FEEDS, 'w') as json_file:
                json.dump(feeds_dict, json_file, ensure_ascii=False, indent=4)  # nopep8
        
            # remove from blacklist
            with open(BLACKLIST) as json_file:
                bl_dict = json.load(json_file)
                del bl_dict['BLACKLIST'][choice]
            with open(BLACKLIST, 'w') as json_file:
                json.dump(bl_dict, json_file, ensure_ascii=False, indent=4)  # nopep8
                
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

        except FileNotFoundError:
            sys.exit(tc.MISSING)

        # Compare and find blacklist matches
        found = []
        for name, bl_ip in ip_list['BLACKLIST'].items():
            try:
                matches = set(IPS) & set(bl_ip)
                for ip in matches:
                    if whois:
                        print(f"\n{tc.BLACKLISTED}[{ip}]: {tc.YELLOW}{name}{tc.RESET}\n{('-' * 35)}\
                            \n{tc.BOLD}{'Location:':10} {tc.RESET}{self.geo_locate(ip)}\
                                \n{tc.BOLD}{'Whois:':10} {tc.RESET}{self.whois_ip(ip)}\n")
                        found.append(ip)
                    else:
                        print(f"\n{tc.BLACKLISTED}[{ip}]: {tc.YELLOW}{name}{tc.RESET}\
                            \n{('-' * 35)}\n{tc.BOLD}{'Location:':10} \
                                {tc.RESET}{self.geo_locate(ip)}\n")
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
                        print(f"\n{tc.SCANNER}[{ip}]: {tc.YELLOW}{name}{tc.RESET}\n{('-' * 35)}\
                            \n{tc.BOLD}{'Location:':10} {tc.RESET}{self.geo_locate(ip)}\
                                \n{tc.BOLD}{'Whois:':10} {tc.RESET}{self.whois_ip(ip)}\n")
                        found.append(ip)
                    else:
                        print(f"\n{tc.SCANNER}[{ip}]: {tc.YELLOW}{name}{tc.RESET}\
                            \n{('-' * 35)}\n{tc.BOLD}{'Location:':10} \
                                {tc.RESET}{self.geo_locate(ip)}\n")
                        found.append(ip)
            except ValueError:
                print(f"{tc.WARNING} {'INVALID IP':12} {ip}")
            except TypeError:
                continue

        nomatch = [ip for ip in IPS if ip not in found]
        for ip in nomatch:
            if whois:
                print(f"\n{tc.CLEAN}[{ip}]:\n{('-' * 35)}\n{tc.BOLD}{'Location:':10} \
                    {tc.RESET}{self.geo_locate(ip)}\n{tc.BOLD}{'Whois:':10} \
                        {tc.RESET}{self.whois_ip(ip)}\n")  # nopep8
            else:
                print(f"\n{tc.CLEAN}[{ip}]:\n{('-' * 35)}\n{tc.BOLD}{'Location:':10} \
                    {tc.RESET}{self.geo_locate(ip)}\n")  # nopep8

    def modified_date(self, _file):
        lastmod = os.stat(_file).st_mtime
        return datetime.strptime(time.ctime(lastmod), "%a %b %d %H:%M:%S %Y")

    def geo_locate(self, ip):
        try:
            url = f'https://freegeoip.live/json/{ip}'
            r = requests.get(url)
            if r.status_code == 200:
                data = json.loads(r.content.decode('utf-8'))
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
                r.raise_for_status()
        except Exception as err:
            print(f"[error] {err}\n")

    def whois_ip(self, ip):
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

    def outdated_file(self):
        # Check if blacklist is outdated
        try:
            file_time = os.path.getmtime(BLACKLIST)
            if (time.time() - file_time) / 3600 > 24:
                print(tc.OUTDATED)
        except FileNotFoundError:
            sys.exit(tc.MISSING)


def main(update, show, query, whois, file, insert, remove):
    pbl = ProcessBL()

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()

    if show:
        pbl.list_count()
        pbl.outdated_file()

    if update:
        pbl.update_list()
        pbl.list_count()

    if insert:
        try:
            feed = input("Feed name: ")
            url = input("Feed url: ")
        except KeyboardInterrupt:
            sys.exit()
        if feed and url:
            print(f"\n{tc.CYAN}[ Checking URL ]{tc.RESET}")
            try:
                urllib.request.urlopen(url, timeout=3)
                print(f"{tc.SUCCESS} URL is good")
            except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
                print(f"{tc.ERROR} '{url}' appears to be invalid or inaccessible.\
                    \n{tc.YELLOW}Option:{tc.RESET} Try adding it manually.")
            else:
                pbl.add_feed(feed=feed.replace(',', ''),
                             url=url.replace(',', ''))
        else:
            sys.exit(f"{tc.ERROR} Please include the feed name and url.")

    if remove:
        # pbl.remove_feed(remove[0])
        pbl.remove_feed()

    if query:
        pbl.outdated_file()
        IPS = []
        for arg in query:
            try:
                IPv4Address(arg.replace(',', ''))
                IPS.append(arg.replace(',', ''))
            except ValueError:
                print(f"{tc.WARNING} {'INVALID IP':12} {arg}")
        if whois:
            print(
                f"{tc.DOTSEP}\n{tc.GREEN}[ Performing IP whois lookup ]{tc.RESET}\n")
            pbl.ip_matches(IPS, whois=whois)
        else:
            pbl.ip_matches(IPS)

    if file:
        pbl.outdated_file()
        try:
            with open(file) as infile:
                IPS = [line.strip() for line in infile.readlines()]
        except FileNotFoundError:
            sys.exit(f"{tc.WARNING} No such file: {file}")
        pbl.ip_matches(IPS)


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

    parser = argparse.ArgumentParser(description="IP Blacklist Check")
    parser.add_argument('-u', dest='update', action='store_true',
                        help="Update set of Blacklisted IPs")
    parser.add_argument('-s', dest='show', action='store_true',
                        help="Show/Sort Blacklist Feeds by Name or Count")
    parser.add_argument('-q', dest='query', nargs='+', metavar='query',
                        help="Query a single or list of IPs against Blacklist")
    parser.add_argument('-w', dest='whois', action='store_true',
                        help="Perform IP whois lookup")
    parser.add_argument('-f', dest='file', metavar='file',
                        help="Blacklist check a list of IPs from file")
    parser.add_argument('-i', dest='insert', action='store_true',
                        help='Insert new Blacklist feed.')
    parser.add_argument('-r', dest='remove', action='store_true',
                        help='Remove Blacklist feed')
    args = parser.parse_args()

    main(update=args.update, show=args.show, query=args.query,
         whois=args.whois, file=args.file, insert=args.insert,
         remove=args.remove)
