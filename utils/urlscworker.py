import requests
from requests.exceptions import HTTPError, RequestException, Timeout

from utils.termcolors import Termcolor as Tc


class URLScan:
    def __init__(self, ip):
        self.headers = {"Accept": "application/json"}
        self.params = (
            ("q", f"domain:{''.join(ip)}"),
            ("size", 1),
        )
        self.base_url = "https://urlscan.io/api/v1/search/"

    def urlsc(self):
        try:
            resp = requests.get(self.base_url, headers=self.headers, params=self.params).json()
        except (HTTPError, RequestException, Timeout):
            print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{Tc.rst}")
        except KeyError:
            print(f"{Tc.error} Issue encountered with query")
        else:
            if resp["results"]:
                for results in resp["results"]:
                    for k, v in results["page"].items():
                        print(f"{k.title():12}: {v}")
                    print(f"{'Result':12}: {results['result']}\n{'Screenshot':12}: {results['screenshot']}")
            else:
                print(Tc.clean)
