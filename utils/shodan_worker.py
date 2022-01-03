import sys

from shodan import APIError, Shodan

from utils.termcolors import Termcolor as Tc


class ShodanIP:
    def __init__(self, api_key):
        self.api_key = api_key

    def shodan_run(self, ip):
        if self.api_key is None:
            sys.exit(f"{Tc.yellow}* Verify that you have provided your API key{Tc.rst}")

        try:
            api = Shodan(self.api_key)
            host = api.host(ip)

            print(f"Org: {host.get('org', 'n/a')}\nOS: {host.get('os', 'n/a')}\n{host.get('isp', 'n/a')}")

            # Print all banners
            for item in host["data"]:
                print(f"Port: {item['port']}\nBanner: {item['data']}\nHostnames: {item['hostnames']}")
        except APIError as err:
            print(err)
