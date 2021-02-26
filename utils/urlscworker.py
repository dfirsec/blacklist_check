import requests
from requests.exceptions import ConnectionError, HTTPError, RequestException, Timeout

from utils.termcolors import Termcolor as Tc


class URLScan:
    def __init__(self):
        self.headers = {"Accept": "application/json"}

    def urlsc_qry(self, ip):
        self.params = (
            ("q", f"domain:{''.join(ip)}"),
            ("size", 1),
        )
        self.base_url = f"https://urlscan.io/api/v1/search/"
        try:
            resp = requests.get(self.base_url, headers=self.headers, params=self.params).json()
        except (ConnectionError, HTTPError, RequestException, Timeout):
            print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{Tc.rst}")
        except KeyError:
            print("Missing data: Double-check ip address")
        else:
            if resp["results"]:
                for p in resp["results"]:
                    for k, v in p["page"].items():
                        print(f"{    k.upper():10}: {v}")
            else:
                print(Tc.clean)
