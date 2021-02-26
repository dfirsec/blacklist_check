from colorama import Fore, init


class Termcolor:
    init(autoreset=True)

    # =colors
    bold = Fore.LIGHTWHITE_EX
    blue = Fore.LIGHTBLUE_EX
    cyan = Fore.CYAN
    green = Fore.GREEN
    gray = Fore.LIGHTBLACK_EX
    mag = Fore.LIGHTMAGENTA_EX
    yellow = Fore.YELLOW
    red = Fore.LIGHTRED_EX
    italic = "\x1b[3m"
    rst = Fore.RESET

    # unicode symbols
    processing = f"{cyan}>{rst}"
    success = f"{green}\u2714{rst}"
    warning = f"{yellow}\u03DF{rst}"
    error = f"{red}\u2718{rst}"
    question = f"{yellow}\uFF1F{rst}"

    # queries
    dl_error = f"{yellow} [DOWNLOAD error]"
    scanner = f"{warning} {bold}{' Scanner':2}"
    blacklisted = f"{red}\u2716{rst}  Blacklisted"
    clean = f"{success} {gray}{' NOT LISTED':2} "
    dotsep = f"{gray}{'.' * 32}{rst}"

    # feeds
    chk_feeds = f"{green}Checking if feeds are current..."
    missing = f"\n{warning} Blacklist file missing -- use the '-u' option to download.\n{yellow}  Run: python blacklist_downloader.py -u"
    outdated = f"{warning}{yellow} Blacklist file is older than 1 day - - use the '-u' option to update.\n"
    current = f"\n{bold}All feeds are current. Use -fu to Force an Update"
