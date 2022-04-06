# SPDX-FileCopyrightText: 2022 Vincent Mallet <vmallet@gmail.com>
# SPDX-License-Identifier: MIT

"""
Hex-Rays Block Highlighter plugin.

Click on a do/while/for/if/switch keyword and highlight the
corresponding block.

Can be enabled/disabled by right-clicking in the Pseudocode window
and choosing "Highlighting on/off"
"""

import ida_hexrays
import ida_idaapi

from ida_hex_highlighter.idav_hex_highlighter import partial_init

__author__ = "https://github.com/vmallet"


class HighlighterPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_PROC
    wanted_name = "Hex-Rays Block Highlighter"
    wanted_hotkey = ""
    comment = "Highlight if/for/do/while/switch blocks in Pseudocode windows"
    help = ""

    def __init__(self):
        self.block_highlighter = None

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            return

        self.block_highlighter, _ = partial_init(False)
        self.block_highlighter.hook()

        return ida_idaapi.PLUGIN_KEEP  # keep us in the memory

    def term(self):
        if self.block_highlighter:
            self.block_highlighter.unhook()
            self.block_highlighter = None

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return HighlighterPlugin()

