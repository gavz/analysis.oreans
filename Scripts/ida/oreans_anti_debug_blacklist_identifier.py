#!/usr/bin/python
# coding=utf-8

"""
brief:          Oreans - Anti-Debugger Blacklist Identifier; Tested on 2.3.0.0 - 2.4.6.0
author:         quosego
contact:        https://github.com/quosego
version:        2020/AUG/28
license:        Apache License 2.0 (Apache-2.0)
"""

try:
    import idc
    import idaapi
    import idautils
except ImportError as e:
    raise Exception("ERROR.ImportError: " + e.message)
except Exception as e:
    raise Exception("ERROR.UnhandledException: " + e.message)

# --------------------------------------------------------------------------------------------------
# GLOBAL


SCRIPT_VERSION = "2020/AUG/28"
SCRIPT_NAME = "Oreans - Anti-Debugger Blacklist Identifier"
SCRIPT_DESCRIPTION = "This is a blacklist debugger identifier script that works on products protected by Oreans Version 2."
SCRIPT_AUTHOR = "quosego (https://github.com/quosego)"


# --------------------------------------------------------------------------------------------------
# GLOBAL SETTINGS


OREANS_SEGMENT = idaapi.get_segm_by_name('.extract')
# [!] often can be identified after the fake ".idata" segment  "________"

DEBUGGER_BLACKLIST = {"anti_debug_a":"C7 01 A5 95 CA 54",
                     "anti_debug_b":"81 01 CB CF 99 14",
                     "anti_debug_c":"C7 41 04 3C 75 78 CE",
                     "anti_debug_d":"C7 41 04 69 59 5F CE",
                     "anti_debug_e":"81 41 04 10 D7 D6 31",
                     "anti_debug_f":"C7 41 04 34 6B 70 CE",
                     "anti_debug_g":"81 02 51 FD 67 0C"}


# --------------------------------------------------------------------------------------------------
# UI Helpers


def script_start():
    return not idc.warning(SCRIPT_NAME + "\n\n" + SCRIPT_DESCRIPTION + "\n\n- " + SCRIPT_AUTHOR)


def script_information(text):
    return not idc.warning(SCRIPT_NAME + "\n\n" + text + "\n\n- " + SCRIPT_AUTHOR)


# --------------------------------------------------------------------------------------------------
# Script Helpers


def format_address(address):
    new_address = str(address)
    if str(address[-1:]) == 'L':
        new_address = str(address[:-1])
    return new_address

def label(name, address):
    return idc.MakeName(address, name)

def log_oreans_blacklist_information(name, address):
    print("[FOUND] " + name + ":" + \
          "  " + format_address(hex(address)))


# --------------------------------------------------------------------------------------------------
# Script


class OreansAntiDebugBlacklistIdentifier(object):
    def __init__(self):
        self.start_address = OREANS_SEGMENT.startEA
        self.end_address = OREANS_SEGMENT.endEA
        self.found_counter = 0

    def __find_all_usages(self, name, signature):
        sub_instance_counter = 0
        current_address = self.start_address
        while (current_address != idc.BADADDR or current_address != 0) and current_address <= self.end_address:
            current_address = idc.FindBinary(current_address, idc.SEARCH_DOWN, signature)
            if (current_address != idc.BADADDR or current_address != 0) and current_address <= self.end_address:
                sub_usage_name = "oreans_" + name + "_" + str(sub_instance_counter)
                idc.MakeUnknown(current_address, 6, idc.DOUNK_SIMPLE)
                idc.MakeCode(current_address)
                label(sub_usage_name, current_address)
                log_oreans_blacklist_information(sub_usage_name, current_address)
                self.found_counter += 1
                sub_instance_counter += 1
                current_address += 1

    def __find_blacklists(self):
        global DEBUGGER_BLACKLIST
        for key in DEBUGGER_BLACKLIST:
            self.__find_all_usages(key, DEBUGGER_BLACKLIST[key])
        print("============================================================")

    def run(self):
        print(SCRIPT_NAME + " - " + SCRIPT_AUTHOR)
        print("============================================================")
        self.__find_blacklists()
        if self.found_counter > 0:
            script_information("found " + str(self.found_counter) + " blacklisted debugger entries!")
        else:
            print("OH NO! The script was unable to find any blacklisted debugger signatures!\n\n" +
                  "There is a possibility that `Anti-Debugger Detections` were not implemented on this application.")


# --------------------------------------------------------------------------------------------------
# Script Launch


if __name__ == '__main__':
    if script_start():
        oadbi = OreansAntiDebugBlacklistIdentifier()
        oadbi.run()

