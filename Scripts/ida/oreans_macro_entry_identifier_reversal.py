#!/usr/bin/python
# coding=utf-8

"""
brief:          Oreans - Macro Entry Identifier (Reversal); Tested on 2.3.0.0 - 3.0.8.0
author:         quosego
contact:        https://github.com/quosego
version:        2020/AUG/20
license:        Apache License 2.0 (Apache-2.0)
"""

try:
    import sys
    import idc
    import idautils
    import idaapi
except ImportError as e:
    raise Exception("ERROR.ImportError: " + e.message)
except Exception as e:
    raise Exception("ERROR.UnhandledException: " + e.message)

# --------------------------------------------------------------------------------------------------
# GLOBAL


SCRIPT_VERSION = "2020/AUG/25"
SCRIPT_NAME = "Oreans - Macro Entry Identifier (Reversal)"
SCRIPT_DESCRIPTION = "This is a 'accurate' Macro Entry Identifier script that works on [ALL] products protected by Oreans."
SCRIPT_AUTHOR = "quosego (https://github.com/quosego)"


# --------------------------------------------------------------------------------------------------
# GLOBAL SETTINGS


TEXT_SEGMENT = idaapi.get_segm_by_name('.text')
# [!] often is the first segment  "___"
OREANS_SEGMENT = idaapi.get_segm_by_name('.extract')
# [!] often can be identified after the fake ".idata" segment  "________"
ENTRY_MNEM = "jmp"
# [!] to identify ENCRYPT macros * change to call
ENTRY_ID_BYTECODE = "E9"
# [!] to identify ENCRYPT macros * change to E8
LANDING_STRIP = "89 ?? 89 ?? 89 ?? 89 ?? 89 ?? 89 ?? 89 ?? 89 ??"
OUTPUT_JSON = "oreans_macro_entries.json"
BUFFER_NOP = True
# [!] to identify ENCRYPT macros * change to False otherwise you will not be able to restore code!
BUFFER_HIDE = False
# [!] to identify ENCRYPT macros * change to False
BUFFER_NAME = "oreans buffer"
BUFFER_START_NAME = "oreans_buffer_start"
BUFFER_END_NAME = "oreans_buffer_end"


# --------------------------------------------------------------------------------------------------
# UI Helpers

def script_start():
    return not idc.warning(SCRIPT_NAME + "\n\n" + SCRIPT_DESCRIPTION + "\n\n- " + SCRIPT_AUTHOR)


def script_information(text):
    return not idc.warning(SCRIPT_NAME + "\n\n" + text + "\n\n- " + SCRIPT_AUTHOR)


def script_settings():
    settings = "Search:\n" + \
               "- Entry Mnemonic: " + ENTRY_MNEM + "\n" + \
               "- Entry Mnemonic Bytecode: " + ENTRY_ID_BYTECODE + "\n" + \
               "- Landing Strip Signature: " + LANDING_STRIP + "\n" + \
               "Manipulation:\n" + \
               "- NOP Buffer: " + str(BUFFER_NOP) + "\n" + \
               "- Hide Buffer: " + str(BUFFER_HIDE) + "\n" + \
               "- - Oreans Buffer Name: " + str(BUFFER_NAME) + "\n" + \
               "- - Oreans Start Buffer Name: " + str(BUFFER_START_NAME) + "\n" + \
               "- - Oreans End Buffer Name: " + str(BUFFER_END_NAME) + "\n" + \
               "Output:\n" + \
               "- JSON File: " + current_idb_path() + OUTPUT_JSON + "\n"
    return not idc.warning(SCRIPT_NAME + " - Settings\n\n" + settings + "\n\n- " + SCRIPT_AUTHOR)


# --------------------------------------------------------------------------------------------------
# Script Helpers


def current_idb_path():
    return '\\'.join(dirs for dirs in idc.GetIdbPath().split("\\")[:-1]) + "\\"


def format_address(address):
    new_address = str(address)
    if str(address[-1:]) == 'L':
        new_address = str(address[:-1])
    return new_address


def get_jump_destination(address):
    return idc.GetOperandValue(address, 0)


def get_mnemonic(address):
    return idc.GetMnem(address)


def nop(start_address, end_address):
    for junk_code in range(start_address, end_address):
        idc.PatchByte(junk_code, 0x90)


def hide(start_address, end_address, name, start_name, end_name):
    idc.HideArea(start_address, end_address, name, start_name, end_name, 0)


def log_oreans_macro_information(start_address, entry_address, end_address):
    print("[FOUND] start: " + format_address(hex(start_address)) + \
          ", entry: " + format_address(hex(entry_address)) + \
          ", end: " + format_address(hex(end_address)))


def valid_oreans_macro_entry(address):
    if idc.isCode(idc.GetFlags(address)) and get_mnemonic(address) == ENTRY_MNEM:
        jump_location_address = get_jump_destination(address)
        if (jump_location_address >= OREANS_SEGMENT.startEA) and (jump_location_address <= OREANS_SEGMENT.endEA):
            return True
    return False


# --------------------------------------------------------------------------------------------------
# Script


class OreansMacroEntryIdentifierReversal(object):
    def __init__(self):
        self.start_address = TEXT_SEGMENT.startEA
        self.end_address = TEXT_SEGMENT.endEA
        self.macros = []

    def __find_entry_jump_pattern(self, last_address):
        possible_entry_address = idc.FindBinary(last_address, idc.SEARCH_UP, ENTRY_ID_BYTECODE + " ?? ??")
        if possible_entry_address == idc.BADADDR or possible_entry_address == 0:
            return -1
        elif valid_oreans_macro_entry(possible_entry_address):
            return possible_entry_address
        else:
            # TODO: NOTICE!
            # smaller possible jump, unknown, or data found with a jump signature...
            # for now... assume anything not yet interp'd by ida's decompiler is misinfo
            # if an issue occurs and are still unable to find the proper entry, uncomment below and try to use
            """
            idc.MakeUnknown(possible_entry_address, 5, idc.DOUNK_SIMPLE)
            idc.MakeCode(possible_entry_address)
            if valid_oreans_macro_entry(possible_entry_address):
                return possible_entry_address
            else:
                idc.MakeUnknown(possible_entry_address, 5, idc.DOUNK_EXPAND)
            """
            return 1

    def __find_entry(self, bound_address, iterate_address, presumed_landing_address):
        while iterate_address > bound_address:
            possible_entry_address = self.__find_entry_jump_pattern(iterate_address)
            if possible_entry_address == 0 or possible_entry_address == 1:
                iterate_address -= 1
            elif possible_entry_address == -1:
                print("ERROR.FindingEntry: Issue finding entry from " + \
                      format_address(hex(iterate_address)) + " to " + \
                      format_address(hex(bound_address)) + ".")
                return 0
            else:
                possible_jump_location_address = get_jump_destination(possible_entry_address)
                log_oreans_macro_information(possible_entry_address, possible_jump_location_address, presumed_landing_address)
                self.macros.append([possible_entry_address, possible_jump_location_address, presumed_landing_address])
                if BUFFER_NOP:
                    nop(possible_entry_address + 5, presumed_landing_address)
                if BUFFER_HIDE:
                    hide(possible_entry_address + 5, presumed_landing_address, BUFFER_NAME, BUFFER_START_NAME, BUFFER_END_NAME)
                # change main iterator address with that oast the landing so it will step over macro range
                next_macro_search_range_address = presumed_landing_address + 5
                return next_macro_search_range_address

    def __seek(self):
        # Method 2 (reversal approach) one of the most accurate methods
        current_address = self.start_address
        while current_address < self.end_address:
            current_address = idc.FindBinary(current_address, idc.SEARCH_DOWN, LANDING_STRIP)
            presumed_landing_address = current_address
            if presumed_landing_address == idc.BADADDR or presumed_landing_address == 0:
                # have reached the end
                break
            else:
                # [macro + [macro + normal]] renders (macro + normal) usually not interp'd by ida
                idc.MakeUnknown(presumed_landing_address, 2, idc.DOUNK_SIMPLE)
                idc.MakeCode(presumed_landing_address)
                zoning_address = presumed_landing_address
                next_iter = 0
                if len(self.macros) > 0:
                    # finding following macro...
                    entry_search_limit_address = (self.macros[-1])[2]
                    next_iter = self.__find_entry(entry_search_limit_address, zoning_address, presumed_landing_address)
                else:
                    # landing is above start, finding first macro...
                    next_iter = self.__find_entry(self.start_address, zoning_address, presumed_landing_address)

                if next_iter == 0:
                    print("ERROR.SeekingIteration: Issue obtaining a valid macro block to search from.")
                    break
                else:
                    current_address = next_iter
        print("============================================================")

    def run(self):
        print(SCRIPT_NAME + " - " + SCRIPT_AUTHOR)
        print("============================================================")
        self.__seek()
        if len(self.macros) > 0:
            script_information("found " + str(len(self.macros)) + " macro entries!")
            print("[OUTPUT] macro entries will try to be written to '" + current_idb_path() + OUTPUT_JSON + "'")
            try:
                f = open(OUTPUT_JSON, "w+")
                entry_data = '{\n\t"count": ' + str(len(self.macros))
                entry_data += ',\n\t"data": [\n'
                for entry in self.macros:
                    entry_data += '\n\t\t{\n\t\t\t"start":"' + format_address(hex(entry[0])) + \
                                  '",\n\t\t\t"entry":"' + format_address(hex(entry[1])) + \
                                  '",\n\t\t\t"end":"' + format_address(hex(entry[2])) + \
                                  '"\n\t\t},'
                entry_data = entry_data[:-1]
                entry_data += '\n\t]\n}\n'
                f.write(entry_data)
                f.close()
            except Exception as e:
                raise Exception("ERROR.OutputIssue: " + e.message)
        else:
            print("OH NO! The script has failed!\n\nWas unable to find any macro signatures!\n\n" +
                  "Please send me any information regarding the targeted Oreans Protector! \n" + \
                  "Example:\n" + \
                  "Version (3.0.8.0), " + \
                  "Protector Name (Themida), " + \
                  "Protection Features (Anti - Debugger Detection, Advanced API - Wrapping), " + \
                  "Target Type (DLL).")


# --------------------------------------------------------------------------------------------------
# Script Launch


if __name__ == '__main__':
    if script_start():
        script_settings()
        omeir = OreansMacroEntryIdentifierReversal()
        omeir.run()

