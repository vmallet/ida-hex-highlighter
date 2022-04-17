# SPDX-FileCopyrightText: 2022 Vincent Mallet <vmallet@gmail.com>
# SPDX-License-Identifier: MIT

"""
IDA action used to highlight code blocks in pseudocode windows.
"""

import ida_hexrays
import ida_kernwin
import ida_lines

from . import lru_cache
from .idav_hex_util import find_insn, map_citems_to_lines, PseudocodeHighlighter

__author__ = "https://github.com/vmallet"

HIGHLIGHTER_ACTION = "idav:toggle-highlighter"
HIGHLIGHTER_TEXT = "Highlight Block (toggle)"
HIGHLIGHTER_SHORTCUT = "Shift-H"
HIGHLIGHTER_TOOLTIP = "Toggle this block's highlighting on/off"

# Number of PseudocodeHighlighters to keep cached when navigating through functions
CACHED_HIGHLIGHTERS = 20


class HighlighterHandler(ida_kernwin.action_handler_t):
    def __init__(self, block_highlighter):
        self.block_highlighter = block_highlighter
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx) -> int:
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if not vu:
            return 0

        return self.block_highlighter.toggle_highlight(vu)

    # This action is only available in pseudocode widget
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


class BlockHighlighter(object):
    """
    A Block highlighter for the Pseudocode window.

    BlockHighlighter attempts to maintain a PseudocodeHighlighter per
    highlightable cfunc and updates the highlighted block when the
    cursor visits a block keyword (i.e. if, for, do, while, switch).
    """
    class _Hooks(ida_hexrays.Hexrays_Hooks):
        def populating_popup(self, widget, handle, vu) -> int:
            return 0

        def refresh_pseudocode(self, vu) -> int:
            return 0

        def double_click(self, vu, shift) -> int:
            return 0

    def __init__(self, *args):
        super().__init__(*args)
        # entry_ea => PseudocodeHighlighter
        self.highlighters = lru_cache.LruCache(max_size=CACHED_HIGHLIGHTERS)

        self.hooks = BlockHighlighter._Hooks()
        self.hooks.populating_popup = self._populating_popup
        self.hooks.refresh_pseudocode = self._refresh_pseudocode
        self.hooks.double_click = self._double_click
        self.enabled = True

    def _populating_popup(self, widget, handle, vu):
        """hex-rays callback: time to inject our action into the popup."""
        citem = self._get_highlightable_citem(vu)
        if citem:
            ida_kernwin.attach_action_to_popup(vu.ct, handle, HIGHLIGHTER_ACTION)
        return 0

    def _refresh_pseudocode(self, vu) -> int:
        """
        hex-rays callback: Pseudocode has been refreshed: time to reset
        our existing highlighter.
        """
        if not self.enabled:
            return 0
        op_ea = None
        highlighter = self.highlighters.remove(vu.cfunc.entry_ea)
        if highlighter:
            op_ea = highlighter.op_ea
            highlighter.unhook()
        # Try to preserve highlights across ctree refreshes
        if op_ea:
            current = find_insn(vu.cfunc.body, op_ea)
            self._set_current(vu.cfunc, current, skip_refresh=True)
        return 0

    def _get_highlightable_citem(self, vu, device=ida_hexrays.USE_KEYBOARD):
        vu.get_current_item(device)
        citem = vu.item.it if vu.item.is_citem() else None
        if not citem:
            return None
        if citem.op not in (ida_hexrays.cit_if, ida_hexrays.cit_for,
                            ida_hexrays.cit_do, ida_hexrays.cit_while,
                            ida_hexrays.cit_switch):
            return None

        # only update if the cursor is on an actual keyword in the current line
        cpos = vu.cpos
        line = vu.cfunc.get_pseudocode()[cpos.lnnum]
        txt = ida_lines.tag_remove(line.line)
        if not 'a' <= txt[cpos.x] <= 'z':
            return None
        return citem

    def toggle_highlight(self, vu, device=ida_hexrays.USE_KEYBOARD):
        """Toggle highlighting of a block on/off.

        For now, look at the current vdui's item and make a decision:
        if it's a 'block' citem (if, for, etc), then toggle its
        highlighting. If it's not a 'block' citem, do nothing.
        """
        if not self.enabled:
            return 0
        citem = self._get_highlightable_citem(vu, device)
        if not citem:
            return 0
        self._set_current(vu.cfunc, citem, toggle=True)
        return 1

    def _double_click(self, vu, shift) -> int:
        """hex-rays callback: double-click! Maybe toggle highlight."""
        return self.toggle_highlight(vu, ida_hexrays.USE_MOUSE)

    def _set_current(self, cfunc, citem, skip_refresh=False, toggle=False):
        """Set the current citem whole block is to be highlighted.

        :param skip_refresh Skip the refresh_idaview_anyway() call
        :param toggle Toggle highlight on/off if True; if False, just
                             set it.
        """
        high = self.highlighters.get(cfunc.entry_ea, lambda: self._create_highlighter(cfunc))
        if toggle and high.op_ea == (citem.op, citem.ea):
            citem = None
        high.set_current(citem, include_children=True)
        if not skip_refresh:
            ida_kernwin.refresh_idaview_anyway()

    def _create_highlighter(self, cfunc):
        """Instantiate a PseudocodeHighlighter for the given cfunc."""
        h = PseudocodeHighlighter(cfunc.entry_ea, map_citems_to_lines(cfunc),
                                  ida_kernwin.CK_EXTRA14)
        h.hook()
        return h

    def toggle_enabled(self):
        """Toggle the enabled state of this plugin"""
        self.enable(not self.enabled)

    def enable(self, enabled):
        """Enable/disable this plugin"""
        self.enabled = enabled
        if not enabled:
            self._clear()

    def hook(self):
        self.hooks.hook()

    def unhook(self) -> bool:
        self._clear()
        return self.hooks.unhook()

    def _clear(self):
        """Clear and unhook all highlighters."""
        for h in self.highlighters.values():
            h.unhook()
        self.highlighters.clear()


def partial_init(debug=False):
    """Register actions, return hooks and actions."""

    ret = ida_kernwin.unregister_action(HIGHLIGHTER_ACTION)
    if debug:
        print("CTreeViewer: Unregistering {}: {}".format(HIGHLIGHTER_ACTION, ret))

    block_highlighter = BlockHighlighter()

    action_desc = ida_kernwin.action_desc_t(
        HIGHLIGHTER_ACTION,
        HIGHLIGHTER_TEXT,
        HighlighterHandler(block_highlighter),
        HIGHLIGHTER_SHORTCUT)

    ret = ida_kernwin.register_action(action_desc)
    if debug:
        print("Registering {}: {}".format(HIGHLIGHTER_ACTION, ret))

    return block_highlighter, [ action_desc ]
