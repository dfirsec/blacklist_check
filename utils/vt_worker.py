import contextlib
import json
import sys
from http.client import responses

import requests
from requests.exceptions import HTTPError, RequestException

from utils.termcolors import Termcolor as Tc


class VirusTotal:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey="

    # ---[ VirusTotal Connection ]---
    def vt_connect(self, url):
        if self.api_key is None:
            sys.exit(f"{Tc.yellow}* Verify that you have provided your API key{Tc.rst}")
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code in (401, 403):
                print(f"{Tc.error} [Error] Invalid API key{Tc.rst}")
            elif resp.status_code != 200:
                print(f" {Tc.error} {Tc.gray} {resp.status_code} {responses[resp.status_code]} {url}{Tc.rst}")
            else:
                return resp.json()
        except (HTTPError, RequestException):
            print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{Tc.rst}")
        return None

    def vt_run(self, ip_addr):
        url = f"{self.base_url}{self.api_key}&ip={''.join(ip_addr)}"
        data = json.dumps(self.vt_connect(url))
        json_resp = json.loads(data)
        if json_resp["response_code"] == 1:
            with contextlib.suppress(KeyError):
                if json_resp["country"] and not json_resp["detected_urls"]:
                    print(f"{Tc.mag}= Reputation Unknown ={Tc.rst}")
                    print(f"  Owner: {json_resp['as_owner']}")
                    print(f"  Country: {json_resp['country']}")
                elif json_resp["resolutions"]:
                    print(f"{Tc.mag}= Hostnames ={Tc.rst}")
                    for k in json_resp["resolutions"]:
                        print(f"{Tc.red}>{Tc.rst} {k['hostname']} ({k['last_resolved']})")
                elif json_resp["detected_urls"]:
                    print(f"\n{Tc.mag}= URLs ={Tc.rst}")
                    for k in json_resp["detected_urls"]:
                        self.positives(k, 'url', '  Scan Date: ', 'scan_date')
                elif json_resp["detected_downloaded_samples"]:
                    print(f"\n{Tc.mag}= Hashes ={Tc.rst}")
                    for k in json_resp["detected_downloaded_samples"]:
                        self.positives(k, 'sha256', '  Date: ', 'date')
        elif json_resp["response_code"] == 0:
            print(Tc.clean)

    @staticmethod
    def positives(k, arg1, arg2, arg3):
        print(f"{Tc.red}>{Tc.rst} {k[arg1]}")
        print(f"  Positives: {k['positives']}")
        print(f"{arg2}{k[arg3]}\n")
