#!/usr/bin/python
# coding=utf-8

"""
brief:          Oreans - OEP Finder (Universal=works for "all" versions); Tested on 2.3.0.0, 2.3.5.10, 3.0.8.0
author:         quosego
contact:        https://github.com/quosego
version:        2020/AUG/27
license:        Apache License 2.0 (Apache-2.0)
"""

try:
    from x64dbgpy import *
except ImportError as e:
    raise Exception("ERROR.ImportError: " + e.message)
except Exception as e:
    raise Exception("ERROR.UnhandledException: " + e.message)


# --------------------------------------------------------------------------------------------------
# GLOBAL


SCRIPT_VERSION = "2020/AUG/27"
SCRIPT_NAME = "Oreans - OEP Finder"
SCRIPT_DESCRIPTION = "This is fast OEP Script that works on [ALL] products protected by Oreans."
SCRIPT_AUTHOR = "quosego (https://github.com/quosego)"


# --------------------------------------------------------------------------------------------------
# GLOBAL SETTINGS


WITHDRAW_COUNTER = 0
# [!] The OEP is usually reached in 0 or 3 counts
WITHDRAW_LIMIT = 5
# [!] Used to avoid infinite looping when searching for the OEP adjust if an issue occurs


# --------------------------------------------------------------------------------------------------
# UI Helpers


def script_start():
    return pluginsdk.x64dbg.MessageYesNo(SCRIPT_NAME + "\n\n" + SCRIPT_DESCRIPTION + "\n\n- " + SCRIPT_AUTHOR)


def script_warning(text):
    return pluginsdk.x64dbg.GuiDisplayWarning(SCRIPT_NAME, text + "\n\n- " + SCRIPT_AUTHOR)


def script_information(text):
    return pluginsdk.x64dbg.Message(SCRIPT_NAME + "\n\n" + text + "\n\n- " + SCRIPT_AUTHOR)


def script_input_string(prompt_text):
    return pluginsdk.gui.InputLine(prompt_text)


def script_input_value(prompt_text):
    return pluginsdk.x64dbg.InputValue(prompt_text)


# --------------------------------------------------------------------------------------------------
# Script Helpers


def get_section(section_name, module=pluginsdk.GetMainModuleInfo()):
    for i in xrange(module.sectionCount):
        section = pluginsdk.SectionFromAddr(module.base, i)
        if section.name == section_name:
            return section
    return None


# --------------------------------------------------------------------------------------------------
# Oreans Entry Finder


class OreansEntryFinder(object):
    def __init__(self):
        super(OreansEntryFinder, self).__init__()
        self.kernel32_VirtualProtect = pluginsdk.x64dbg.RemoteGetProcAddress("KernelBase.dll", "VirtualProtect")
        self.module_base = pluginsdk.GetMainModuleInfo().base
        self.module_end = self.module_base + pluginsdk.GetMainModuleInfo().size
        if get_section(".text") is not None:
            # For newer configurations / others protected a "certain" way
            self.module_text_section = get_section(".text")
        else:
            # For most common configurations that have "    " as their name
            self.module_text_section = pluginsdk.SectionFromAddr(self.module_base, 0)
        self.module_text_section_end = self.module_text_section.addr + self.module_text_section.size
        pluginsdk.DeleteBreakpoint(self.kernel32_VirtualProtect)
        pluginsdk.DeleteBreakpoint(self.module_text_section.addr)

    def __step_cip_monitor(self):
        pluginsdk.SetBreakpoint(self.kernel32_VirtualProtect)
        while pluginsdk.GetCIP() != self.kernel32_VirtualProtect:
            pluginsdk.Run()
        pluginsdk.DeleteBreakpoint(self.kernel32_VirtualProtect)
        return

    def __step_stack_monitor(self):
        global WITHDRAW_COUNTER
        global WITHDRAW_LIMIT
        while WITHDRAW_COUNTER <= WITHDRAW_LIMIT:
            self.__step_cip_monitor()
            if pluginsdk.x64dbg.ReadDword(pluginsdk.register.GetESP() + 4) == self.module_base:
                break
            else:
                pluginsdk.StepOver()
                WITHDRAW_COUNTER += 1
        if WITHDRAW_COUNTER > WITHDRAW_LIMIT:
            return -1
        pluginsdk.x64dbg.DbgCmdExecDirect("bpm " + hex(self.module_text_section.addr) + ", 0, x")
        pluginsdk.Run()
        return pluginsdk.GetCIP()

    def find(self):
        entry_address = hex(self.__step_stack_monitor())
        if (entry_address != hex(0)) and (entry_address != hex(0xFFFFFFFF)) and \
                (entry_address >= hex(self.module_base)) and (entry_address <= hex(self.module_end)):
            return entry_address

        script_warning("OH NO! The script has failed!\n\n" + \
                        "First, make sure no other extra breakpoints are being used and try again!\n" + \
                        "Second, if the CIP is outside of the target module's address range try continue to run. \n" + \
                        "Third, please send me any information regarding the targeted Oreans Protector! \n" + \
                        "Example:\n" + \
                        "Version (3.0.8.0), " + \
                        "Protector Name (Themida), " + \
                        "Protection Features (Anti-Debugger Detection, Advanced API-Wrapping)," + \
                        "Target Type (DLL).")
        return -1

    def run(self):
        possible_entry = self.find()
        if possible_entry == -1:
            return
        elif (possible_entry >= hex(self.module_text_section.addr)) and \
                (possible_entry <= hex(self.module_text_section_end)):
            script_information("REAL OEP Found @ " + possible_entry + "")
        else:
            script_warning("POSSIBLE OEP Found Near @ " + possible_entry + "\n" + \
                           "If you are using a DEMO Oreans product then dismiss the splash screen. " + \
                           "It will break on the correct address.")


# --------------------------------------------------------------------------------------------------
# Script Launch


if __name__ == '__main__':
    if script_start():
        oef = OreansEntryFinder()
        oef.run()
