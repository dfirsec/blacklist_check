import argparse
import contextlib
import datetime
import os
import sys
import urllib.error
import urllib.request
import warnings
from configparser import ConfigParser
from ipaddress import IPv4Address
from pathlib import Path

import urllib3

from utils.aipdb_worker import AbuseIPDB
from utils.main_worker import DNSBL, ProcessBL
from utils.shodan_worker import ShodanIP
from utils.termcolors import Termcolor as Tc
from utils.urlsc_worker import URLScan
from utils.vt_worker import VirusTotal

__author__ = "DFIRSec (@pulsecode)"
__version__ = "v0.2.6"
__description__ = "Check IP addresses against blacklists from various sources."


# suppress dnspython feature deprecation warning
warnings.filterwarnings("ignore", category=DeprecationWarning)

# suppress certificate verification
urllib3.disable_warnings()

# Base directory paths
parent = Path(__file__).resolve().parent
blacklist = parent.joinpath("resc/blacklist.json")
feeds = parent.joinpath("resc/feeds.json")
settings = parent.joinpath("settings.ini")

# Configuration Parser
config = ConfigParser()
config.read(settings)


def parser():
    _parser = argparse.ArgumentParser(description="IP Blacklist Check")
    group_1 = _parser.add_mutually_exclusive_group()
    group_2 = _parser.add_mutually_exclusive_group()

    _parser.add_argument(
        "-t",
        dest="threads",
        nargs="?",
        type=int,
        metavar="threads",
        default=25,
        help="threads for rbl check (default 25, max 50)",
    )

    _parser.add_argument("-v", dest="vt_query", action="store_true", help="check virustotal for ip info")
    _parser.add_argument("-a", dest="aipdb_query", action="store_true", help="check abuseipdb for ip info")
    _parser.add_argument("-s", dest="shodan_query", action="store_true", help="check shodan for ip info")

    group_1.add_argument("-u", dest="update", action="store_true", help="update blacklist feeds")
    group_1.add_argument("-fu", dest="force", action="store_true", help="force update of all feeds")
    group_1.add_argument("-sh", dest="show", action="store_true", help="show blacklist feeds")

    group_2.add_argument("-q", dest="query", nargs="+", metavar="query", help="query a single or multiple ip addrs")

    group_2.add_argument("-f", dest="file", metavar="file", help="query a list of ip addresses from file")
    group_2.add_argument("-i", dest="insert", action="store_true", help="insert a new blacklist feed")
    group_2.add_argument(
        "-r",
        dest="remove",
        action="store_true",
        help="remove an existing blacklist feed",
    )

    return _parser


def check_apikey(name, query_type):
    """Verifies API Key."""
    if not config.get(f"{name}", "api_key"):
        print(f"Please add {name} api key to the '{settings.name}' file")
    else:
        api_key = config.get(f"{name}", "api_key")
        name = query_type(api_key)
        return name
    return None


def main():
    args = parser().parse_args()
    pbl = ProcessBL()
    dbl = DNSBL(host=args.query, threads=args.threads)

    # check arguments
    if len(sys.argv[1:]) == 0:
        parser().print_help()
        parser().exit()

    if not blacklist.exists() or os.stat(blacklist).st_size == 0:
        print(f"{Tc.yellow}Blacklist file is missing...{Tc.rst}\n")
        pbl.update_list()

    # check if file is older than 7 days
    today = datetime.datetime.now()
    filetime = datetime.datetime.fromtimestamp(blacklist.stat().st_mtime) - today

    if filetime.days <= -7:
        print(f"{Tc.yellow}[!] Blacklist file is older than 7 days -- recommend updating{Tc.rst}")

    if args.query:
        ip_addrs = []
        for arg in args.query:
            try:
                IPv4Address(arg.replace(",", ""))
                ip_addrs.append(arg.replace(",", ""))
            except ValueError:
                sys.exit(f"{Tc.warning} {'INVALID IP':12} {arg}")

        pbl.ip_matches(ip_addrs)

        # Single ip check
        if len(args.query) == 1:
            check_lists(dbl, args, pbl, ip_addrs)

    if args.file:
        pbl.outdated()
        try:
            with open(args.file, encoding="utf-8") as infile:
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
                    urllib.request.urlopen(url)
                except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
                    print(f"{Tc.error} URL '{url}' appears to be invalid or inaccessible.")
                else:
                    print("[*] URL is good")
                    confirm = input(
                        f"[?] Insert the following feed? \nName: {feed} | URL: {url} {Tc.yellow}(Y/n){Tc.rst}: "
                    )
                    if confirm.lower() == "y":
                        pbl.add_feed(feed=feed.replace(",", ""), url=url.replace(",", ""))
                    else:
                        sys.exit("[!] Request canceled")
                    break
            else:
                sys.exit(f"{Tc.error} Please include the feed name and url.")

    if args.remove:
        pbl.remove_feed()

    if args.threads > 50:
        sys.exit(f"{Tc.error} Exceeded max of 50 threads.{Tc.rst}")


def check_lists(dbl, args, pbl, ip_addrs):
    print(f"\n{Tc.dotsep}\n{Tc.green}[ Reputation Block List Check ]{Tc.rst}")
    dbl.dnsbl_mapper(args.threads)

    print(f"\n{Tc.dotsep}\n{Tc.green}[ IP-46 IP Intel Check ]{Tc.rst}")
    pbl.ip46(args.query)

    print(f"\n{Tc.dotsep}\n{Tc.green}[ URLhaus Check ]{Tc.rst}")
    pbl.urlhaus(args.query)

    print(f"\n{Tc.dotsep}\n{Tc.green}[ Threatfox Check ]{Tc.rst}")
    pbl.threatfox(args.query)

    print(f"\n{Tc.dotsep}\n{Tc.green}[ URLScan Check ]{Tc.rst}")
    URLScan(args.query).url_scan()

    # VirusTotal Query
    if args.vt_query:
        print(f"\n{Tc.dotsep}\n{Tc.green}[ VirusTotal Check ]{Tc.rst}")
        with contextlib.suppress(AttributeError):
            check_apikey("virustotal", VirusTotal).vt_run(ip_addrs)
            # AbuseIPDB
    if args.aipdb_query:
        print(f"\n{Tc.dotsep}\n{Tc.green}[ AbuseIPDB Check ]{Tc.rst}")
        with contextlib.suppress(AttributeError):
            check_apikey("abuseipdb", AbuseIPDB).aipdb_run(ip_addrs)
            # Shodan
    if args.shodan_query:
        print(f"\n{Tc.dotsep}\n{Tc.green}[ Shodan Check ]{Tc.rst}")
        with contextlib.suppress(AttributeError):
            check_apikey("shodan", ShodanIP).shodan_run(ip_addrs)


if __name__ == "__main__":
    banner = rf"""
        ____  __           __   ___      __     ________              __
       / __ )/ /___ ______/ /__/ (_)____/ /_   / ____/ /_  ___  _____/ /__
      / __  / / __ `/ ___/ //_/ / / ___/ __/  / /   / __ \/ _ \/ ___/ //_/
     / /_/ / / /_/ / /__/ ,< / / (__  ) /_   / /___/ / / /  __/ /__/ ,<
    /_____/_/\__,_/\___/_/|_/_/_/____/\__/   \____/_/ /_/\___/\___/_/|_|
                                                                {__version__}
    """

    print(f"{Tc.cyan}{banner}{Tc.rst}")

    # check if python version
    if sys.version_info.major != 3 and sys.version_info.minor >= 8:
        print("Python 3.8 or higher is required.")
        sys.exit(f"Your Python Version: {sys.version_info.major}.{sys.version_info.minor}")

    main()
