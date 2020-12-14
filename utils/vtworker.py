import json
import sys
from http.client import responses

import requests

from utils.termcolors import Termcolor as Tc


class VirusTotal:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = f"https://www.virustotal.com/vtapi/v2/ip-address/report?apikey="
        if self.api_key is None:
            sys.exit(f"{Tc.yellow}* Verify that you have provided your API key{Tc.rst}")

    # ---[ VirusTotal Connection ]---
    @staticmethod
    def vt_connect(url):
        try:
            resp = requests.get(url, timeout=5)
            resp.encoding = "utf-8"
            if resp.status_code == 401:
                sys.exit("[error] Invalid API key.")
            if resp.status_code != 200:
                print(f" {Tc.error} {Tc.gray} {resp.status_code} {responses[resp.status_code]}{url}{Tc.rst}")
            else:
                return resp.json()
        except (
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException,
        ):
            print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{Tc.rst}")

    def vt_run(self, ip_addr):
        url = f"{self.base_url}{self.api_key}&ip={''.join(ip_addr)}"
        data = json.dumps(self.vt_connect(url))
        json_resp = json.loads(data)
        if json_resp["response_code"] == 1:
            try:
                if json_resp["resolutions"]:
                    print(f"{Tc.mag}= Hostnames ={Tc.rst}")
                    for k in json_resp["resolutions"]:
                        print(f"{Tc.red}>{Tc.rst} {k['hostname']} ({k['last_resolved']})")
                if json_resp["detected_urls"]:
                    print(f"{Tc.mag}= URLs ={Tc.rst}")
                    for k in json_resp["detected_urls"]:
                        print(f"{Tc.red}>{Tc.rst} {k['url']}")
                        print(f"  Positives: {k['positives']}")
                        print(f"  Scan Date: {k['scan_date']}\n")
                if json_resp["detected_downloaded_samples"]:
                    print(f"{Tc.mag}= Hashes ={Tc.rst}")
                    for k in json_resp["detected_downloaded_samples"]:
                        print(f"{Tc.red}>{Tc.rst} {k['sha256']}")
                        print(f"  Positives: {k['positives']}")
                        print(f"  Date: {k['date']}\n")
            except KeyError:
                pass
        elif json_resp["response_code"] == 0:
            print(Tc.clean)
