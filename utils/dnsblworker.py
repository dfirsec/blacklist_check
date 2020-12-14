import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address
from pathlib import Path

import coloredlogs
import dns.resolver
import requests
import verboselogs
from bs4 import BeautifulSoup

from utils.termcolors import Termcolor as Tc

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

# Base directory
parent = Path(__file__).resolve().parent.parent
feeds = parent.joinpath("resc/feeds.json")


class DNSBL:
    def __init__(self, host, threads):
        self.host = host
        self.threads = threads
        self.cnt = 0

    @staticmethod
    def update_dnsbl():
        url = "http://multirbl.valli.org/list/"
        page = requests.get(url).text
        soup = BeautifulSoup(page, "html.parser")
        table = soup.find("table")
        table_rows = table.find_all("tr")

        alive = []
        for tr in table_rows:
            td = tr.find_all("td")
            row = [i.text for i in td]
            if "(hidden)" not in row:
                alive.append(row[2])

        with open(feeds) as json_file:
            feeds_dict = json.load(json_file)
            feed_list = feeds_dict["DNS Blacklists"]["DNSBL"]

        # remove 'contact' items from list
        contacts = ["contacts.abuse.net", "abuse-contacts.abusix.org"]
        for contact in contacts:
            alive.remove(contact)

        diff = [x for x in alive if x not in feed_list]
        if len(diff) > 1:
            print(f"{Tc.green} [ Updating RBLs ]{Tc.rst}")
            for item in diff:
                if item not in feed_list:
                    logger.success(f"[+] Adding {item}")
                    feed_list.append(item)

            with open(feeds, "w") as json_file:
                json.dump(feeds_dict, json_file, ensure_ascii=False, indent=4)
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

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.Timeout,
            dns.resolver.NoNameservers,
            dns.resolver.NoAnswer,
        ):
            pass
        except DeprecationWarning:
            pass

    def dnsbl_query(self, blacklist):
        host = str("".join(self.host))

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
            qry = host + "." + blacklist

        answer = self.resolve_dns(qry)
        try:
            if any(str(answer[0]) in s for s in codes):
                logger.success(f"{Tc.red}\u2716{Tc.rst}  Blacklisted > {blacklist}")
                self.cnt += 1
        except Exception:
            pass

    def dnsbl_mapper(self, threads=None):
        with open(feeds) as json_file:
            data = json.load(json_file)
        dnsbl = [url for url in data["DNS Blacklists"]["DNSBL"]]

        with ThreadPoolExecutor(max_workers=threads) as executor:
            dnsbl_map = {executor.submit(self.dnsbl_query, url): url for url in dnsbl}
            for future in as_completed(dnsbl_map):
                url = dnsbl_map[future]
                try:
                    future.result()
                except Exception as exc:
                    print(f"Exception generated: {url} {exc}")
            if self.cnt:
                host = str("".join(self.host))
                logger.warning(f"\n[*] {host} is listed in {self.cnt} block lists")
