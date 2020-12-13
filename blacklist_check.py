import argparse
import os
import sys
import urllib
import warnings
from configparser import ConfigParser
from ipaddress import IPv4Address
from pathlib import Path

import requests
import urllib3

from utils.blworker import ProcessBL
from utils.dnsblworker import DNSBL
from utils.termcolors import Termcolor as Tc
from utils.vtworker import VirusTotal

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.1.4"
__description__ = "Check IP addresses against blacklists from various sources."


# suppress dnspython feature deprecation warning
warnings.filterwarnings('ignore', category=DeprecationWarning)

# suppress certificate verification
urllib3.disable_warnings()

# Base directory
parent = Path(__file__).resolve().parent
blklist = parent.joinpath('resc/blacklist.json')
feeds = parent.joinpath('resc/feeds.json')
settings = parent.joinpath('settings.cfg')


def parser():
    p = argparse.ArgumentParser(description="IP Blacklist Check")
    group1 = p.add_mutually_exclusive_group()
    group2 = p.add_mutually_exclusive_group()
    p.add_argument('-t', dest='threads', nargs='?', type=int, metavar='threads',
                   default=25, help="threads for rbl check (default 25, max 50)")

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

        pbl.ip_matches(ip_addrs)

        # single ip check
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
                config = ConfigParser()
                config.read(settings)

                # verify vt api key
                if not config.get('virus-total', 'api_key'):
                    sys.exit("Please add VT API key to the 'settings.cfg' file")  # nopep8
                else:
                    api_key = config.get('virus-total', 'api_key')
                    virustotal = VirusTotal(api_key)
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
