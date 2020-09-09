from colorama import Fore, Style, init


class Termcolor:
    init(autoreset=True)

    # =colors
    BOLD = Fore.LIGHTWHITE_EX
    BLUE = Fore.LIGHTBLUE_EX
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    MAGENTA = Fore.MAGENTA
    GRAY = Fore.LIGHTBLACK_EX
    YELLOW = Fore.YELLOW
    RED = Fore.LIGHTRED_EX
    ITALIC = "\x1b[3m"
    RESET = Style.RESET_ALL

    # unicode symbols
    PROCESSING = f"{CYAN}\u279C{RESET}"
    SUCCESS = f"{GREEN}\u2714{RESET}"
    WARNING = f"{YELLOW}\u03DF{RESET}"
    ERROR = f"{RED}\u2718{RESET}"
    QUESTION = f"{YELLOW}\uFF1F{RESET}"

    # queries
    DOWNLOAD_ERR = f"{YELLOW} [DOWNLOAD ERROR]"
    SCANNER = f"{WARNING} {BOLD}{'SCANNER':2}"
    BLACKLISTED = f"{RED}\u2716{RESET}  Blacklisted >"
    CLEAN = f"{SUCCESS} {GRAY}{'NOT LISTED':2} "
    DOTSEP = f"{GRAY}{'.' * 32}{RESET}"

    # feeds
    CHECK_FEEDS = f"{GREEN}Checking if feeds are current..."
    MISSING = f"\n{WARNING} Blacklist file missing -- use the '-u' option to download.\n{YELLOW}  Run: python blacklist_downloader.py -u"  # nopep8
    OUTDATED = f"{WARNING}{YELLOW} Blacklist file is older than 1 day - - use the '-u' option to update.\n"  # nopep8
    CURRENT = f"\n{BOLD}All feeds are current. Use -fu to Force an Update"  # nopep8
