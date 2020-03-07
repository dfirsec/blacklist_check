#!/usr/bin/env python

from colorama import Fore, Style, init

init()


class Termcolor:
    # Unicode Symbols and colors
    BOLD = Style.BRIGHT
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    MAGENTA = Fore.MAGENTA
    GRAY = Fore.LIGHTBLACK_EX
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    RESET = Style.RESET_ALL
    PROCESSING = CYAN + "\u279C " + RESET
    SUCCESS = GREEN + "\u2714" + RESET
    WARNING = YELLOW + "\u03DF" + RESET
    ERROR = RED + "\u2718" + RESET
    QUESTION = YELLOW + "\uFF1F" + RESET
    DOWNLOAD_ERR = f"{YELLOW} [DOWNLOAD ERROR]{RESET}"
    SCANNER = f"{WARNING} {BOLD}{'SCANNER':12} {RESET}"
    BLACKLISTED = f"{ERROR} {BOLD}{'BLACKLISTED':12} {RESET}"
    CLEAN = f"{SUCCESS} {GRAY}{'NOT LISTED':12} "
    DOTSEP = f"{GRAY}{'.' * 30}{RESET}"
    MISSING = f"\n{WARNING} Blacklist file missing -- use the '-u' option to download.\n{YELLOW}  Run: python blacklist_downloader.py -u{RESET}"
    OUTDATED = f"{WARNING} {CYAN} Blacklist file is older than 1 day - - use the '-u' option to update.\n{RESET}"
