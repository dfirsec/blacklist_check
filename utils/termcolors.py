#!/usr/bin/env python

from colorama import Fore, Style, init

init()


class Termcolor:
    # Unicode Symbols and colors
    BOLD = Fore.LIGHTWHITE_EX
    BLUE = Fore.LIGHTBLUE_EX
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    MAGENTA = Fore.MAGENTA
    GRAY = Fore.LIGHTBLACK_EX
    YELLOW = Fore.YELLOW
    RED = Fore.LIGHTRED_EX
    RESET = Style.RESET_ALL
    PROCESSING = CYAN + "\u279C " + RESET
    SUCCESS = GREEN + "\u2714 " + RESET
    WARNING = YELLOW + "\u03DF" + RESET
    ERROR = RED + "\u2718" + RESET
    QUESTION = YELLOW + "\uFF1F" + RESET
    DOWNLOAD_ERR = f"{YELLOW} [DOWNLOAD ERROR]{RESET}"
    SCANNER = f"{WARNING} {BOLD}{'SCANNER':2} {RESET}"
    BLACKLISTED = f"{RED}\u2716{RESET}  Blacklisted >"
    CLEAN = f"{SUCCESS} {GRAY}{'NOT LISTED':2} "
    DOTSEP = f"{GRAY}{'.' * 30}{RESET}"
    MISSING = f"\n{WARNING} Blacklist file missing -- use the '-u' option to download.\n{YELLOW}  Run: python blacklist_downloader.py -u{RESET}"
    OUTDATED = f"{WARNING}{YELLOW} Blacklist file is older than 1 day - - use the '-u' option to update.\n{RESET}"
