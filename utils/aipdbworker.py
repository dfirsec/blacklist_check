import sys

import requests
from requests.exceptions import HTTPError, RequestException, Timeout

from utils.termcolors import Termcolor as Tc


class AbuseIPDB:
    """
    Performs check against abuseipdb.com
    """

    def __init__(self, api_key, ip):
        self.api_key = api_key
        self.headers = {"Key": api_key, "Accept": "application/json"}
        self.params = (("ipAddress", ip),)
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        if self.api_key is None:
            sys.exit(f"{Tc.yellow}* Verify that you have provided your API key{Tc.rst}")

    def aipdb_run(self, ip):
        try:
            resp = requests.get(self.base_url, headers=self.headers, params=self.params).json()
        except (HTTPError, RequestException, Timeout):
            print(f"    {Tc.error}{Tc.dl_error} {Tc.gray}{Tc.rst}")
        except KeyError:
            print("Missing data: Double-check ip and/or api key")
        else:
            ip_addr = resp["data"]["ipAddress"]
            score = resp["data"]["abuseConfidenceScore"]
            report = resp["data"]["lastReportedAt"]
            if ip_addr and score >= 90:
                print(f"{Tc.blacklisted} {''.join(ip)}")
                print(f"{Tc.red}>{Tc.rst}  Last Reported: {report}")
                print(f"{Tc.red}>{Tc.rst}  Confidence of Abuse is: {score}%")
            elif ip_addr and report is not None and score < 90:
                print(f"{Tc.red}>{Tc.rst}  Last Reported: {report}")
                print(f"{Tc.red}>{Tc.rst}  Confidence of Abuse is: {score}%")
            else:
                print(Tc.clean)
