import sys

import requests
from requests.exceptions import HTTPError, RequestException, Timeout

from utils.termcolors import Termcolor as Tc


class AbuseIPDB:
    def __init__(self, api_key):
        self.api_key = api_key

    def aipdb_run(self, ip):
        if self.api_key is None:
            sys.exit(f"{Tc.yellow}* Verify that you have provided your API key{Tc.rst}")

        headers = {"Key": self.api_key, "Accept": "application/json"}
        base_url = "https://api.abuseipdb.com/api/v2/check"
        params = (("ipAddress", ip),)

        try:
            resp = requests.get(base_url, headers=headers, params=params).json()
        except (HTTPError, RequestException, Timeout):
            print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{Tc.rst}")
        except KeyError:
            print("Missing data: Double-check ip and/or api key")
        else:
            ip = resp["data"]["ipAddress"]
            score = resp["data"]["abuseConfidenceScore"]
            report = resp["data"]["lastReportedAt"]
            if ip and score >= 90:
                print(f"{Tc.blacklisted} {''.join(ip)}")
                print(f"{Tc.red}>{Tc.rst}  Last Reported: {report}")
                print(f"{Tc.red}>{Tc.rst}  Confidence of Abuse is: {score}%")
            elif ip and report is not None and score < 90:
                print(f"{Tc.red}>{Tc.rst}  Last Reported: {report}")
                print(f"{Tc.red}>{Tc.rst}  Confidence of Abuse is: {score}%")
            else:
                print(Tc.clean)
