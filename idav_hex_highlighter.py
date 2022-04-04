"""
IDA plugin used to highlight code blocks in pseudocode windows.
"""

import ida_hexrays
import ida_kernwin
import ida_lines
from typing import Dict, Set

import LruCache
# TODO: do not depend on idav_hex_treeview (move common dependencies out)
import idav_hex_treeview
import idav_state

ACTION_HIGHLIGHTER = "idav:toggle-highlighter"

# TODO: sub_51179B4

class HighlighterHandler(ida_kernwin.action_handler_t):
    def __init__(self, block_highlighter):
        self.block_highlighter = block_highlighter
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx) -> int:
        self.block_highlighter.toggle_enabled()
        plugin_active = self.block_highlighter.enabled
        print("Highlighter {}".format("ON" if plugin_active else "OFF"))
        return 0

    # This action is only available in pseudocode widget
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


#TODO: hacked copy of ctreeviewer; unify and keep only one copy
class PseudocodeHighlighter(object):
    # TODO:
    """TODO: An object that will highlight lines in the pseudocode that correspond to a specific citem in the ctree."""

    NO_LINES = set()

    class XHook(ida_kernwin.UI_Hooks):
        def get_lines_rendering_info(self, lines_out, widget, lines_in) -> None:
            pass

    def __init__(self, entry_ea, line_map: Dict[int, Set[int]]):
        self.entry_ea = entry_ea
        self.line_map = line_map
        self.ui_hooks = PseudocodeHighlighter.XHook()
        self.ui_hooks.get_lines_rendering_info = self._maybe_highlight_lines
        self.lines: Set[int] = set()
        self.n = 0
        self.current = None

    def _ensure_hooks(self):
        if not self.ui_hooks:
            raise Exception("UI_Hooks have already been cleaned up")

    def hook(self):
        self._ensure_hooks()
        self.ui_hooks.hook()

    def unhook(self):
        self._ensure_hooks()
        self._set_active_lines(PseudocodeHighlighter.NO_LINES)
        self.ui_hooks.unhook()
        self.ui_hooks = None

    def _maybe_highlight_lines(self, lines_out, widget, lines_in) -> None:
        """Handle the get_lines_rendering_info event and decorate active lines if it's the right pseudocode widget"""
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE or not self.lines:
            return

        vu = ida_hexrays.get_widget_vdui(widget)
        if vu.cfunc.entry_ea != self.entry_ea:
            return

        color = ida_kernwin.CK_EXTRA14  # + self.n  # TODO: make color configurable
        # print("color: CK_EXTRA1: {}, col: {}".format(ida_kernwin.CK_EXTRA1, color))
        self.n = (self.n + 1) % 16
        for line in lines_in.sections_lines[0]:  # TODO: understand what it would mean if there's more than 1 section
            splace = ida_kernwin.place_t_as_simpleline_place_t(line.at)
            if splace.n in self.lines:
                entry = ida_kernwin.line_rendering_output_entry_t(line, ida_kernwin.LROEF_FULL_LINE, color)
                lines_out.entries.push_back(entry)

    def _set_active_lines(self, lines: Set[int]):
        """Set highlighted lines and refresh view if necessary"""
        if self.lines != lines:
            self.lines = lines
            ida_kernwin.refresh_idaview_anyway()

    def set_current(self, ci: ida_hexrays.citem_t, full_block=False):
        """Set current ctree item for which lines should be highlighted"""
        self.current = ci
        if not ci:
            lines = PseudocodeHighlighter.NO_LINES
        else:
            if full_block:
                lines = self._collect_lines(ci)
            else:
                lines = self.line_map.get(ci.obj_id, PseudocodeHighlighter.NO_LINES)

        self._set_active_lines(lines)

    def _collect_lines(self, citem):
        class lc(ida_hexrays.ctree_visitor_t):
            def __init__(self, map):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.lines = set()
                self.line_map = map

            def visit_insn(self, insn) -> int:
                self.lines.update(self.line_map.get(insn.obj_id, PseudocodeHighlighter.NO_LINES))
                return 0

            def visit_expr(self, expr) -> int:
                self.lines.update(self.line_map.get(expr.obj_id, PseudocodeHighlighter.NO_LINES))
                return 0

        lcx = lc(self. line_map)
        lcx.apply_to(citem, None)
        return lcx.lines


class BlockHighlighter(object):
    """
    A Block highlighter for the Pseudocode window.

    BlockHighlighter attempts to maintain a PseudocodeHighlighter per
    highlightable cfunc and updates the highlighted block when the
    cursor visits a block keyword (i.e. if, for, do, while).
    """
    class _Hooks(ida_hexrays.Hexrays_Hooks):
        def populating_popup(self, widget, handle, vu) -> int:
            return 0

        def refresh_pseudocode(self, vu) -> int:
            return 0

        def curpos(self, vu) -> int:
            return 0

    def __init__(self, *args):
        super().__init__(*args)
        self.highlighters = LruCache.LruCache(max_size=3)

        self.hooks = BlockHighlighter._Hooks()
        self.hooks.populating_popup = self._populating_popup
        self.hooks.refresh_pseudocode = self._refresh_pseudocode
        self.hooks.curpos = self._curpos
        self.enabled = True

    def _populating_popup(self, widget, handle, vu):
        ida_kernwin.attach_action_to_popup(vu.ct, None, ACTION_HIGHLIGHTER)
        return 0

    def _refresh_pseudocode(self, vu) -> int:
        """Pseudocode has been refreshed: time to reset our existing highlighter"""
        if not self.enabled:
            return 0
        current = None
        highlighter = self.highlighters.remove(vu.cfunc.entry_ea)
        if highlighter:
            highlighter.unhook()
            current = highlighter.current
        if current:
            self._set_current(vu.cfunc, current)
        return 0

    def _curpos(self, vu) -> int:
        if not self.enabled:
            return 0
        citem = vu.item.it if vu.item.is_citem() else None
        if not citem:
            return 0
        if citem.op not in (ida_hexrays.cit_if, ida_hexrays.cit_for,
                            ida_hexrays.cit_do, ida_hexrays.cit_while):
            return 0

        cpos = vu.cpos
        line = vu.cfunc.get_pseudocode()[cpos.lnnum]
        txt = ida_lines.tag_remove(line.line)
        print("line: {}, ch: {}".format(txt, txt[cpos.x]))

        # only update if the cursor is on an actual keyword
        if not 'a' <= txt[cpos.x] <= 'z':
            return 0

        self._set_current(vu.cfunc, citem)
        return 1

    def _set_current(self, cfunc, citem):
        high = self.highlighters.get(cfunc.entry_ea, lambda: self._create_highlighter(cfunc))
        high.set_current(citem, full_block=True)
        ida_kernwin.refresh_idaview_anyway()

    def _create_highlighter(self, cfunc):
        h = PseudocodeHighlighter(cfunc.entry_ea, idav_hex_treeview.map_citems_to_lines(cfunc))
        h.hook()
        return h

    def toggle_enabled(self):
        """Toggle the enabled state of this plugin"""
        self.enable(not self.enabled)

    def enable(self, enabled):
        """Enable/disable this plugin"""
        self.enabled = enabled
        if not enabled:
            self.clear()

    def hook(self):
        self.hooks.hook()

    def unhook(self) -> bool:
        self.clear()
        return self.hooks.unhook()

    def clear(self):
        for h in self.highlighters.values():
            h.unhook()
        self.highlighters.clear()


def v_register_highlighter(debug=False):
    """Register the pseudocode highlighter action"""

    if not ida_hexrays.init_hexrays_plugin():
        print("No hexrays -> no highlighter for you!")
        return

    if idav_state.hex_highlighter:
        idav_state.hex_highlighter.unhook()
        idav_state.hex_highlighter = None

    ret = ida_kernwin.unregister_action(ACTION_HIGHLIGHTER)
    if debug:
        print("CTreeViewer: Unregistering {}: {}".format(ACTION_HIGHLIGHTER, ret))

    block_highlighter = BlockHighlighter()

    action_desc = ida_kernwin.action_desc_t(
        ACTION_HIGHLIGHTER, 'Highlighting on/off', HighlighterHandler(block_highlighter))

    ret = ida_kernwin.register_action(action_desc)
    if debug:
        print("Registering {}: {}".format(ACTION_HIGHLIGHTER, ret))

    idav_state.hex_highlighter = block_highlighter
    idav_state.hex_highlighter.hook()

    print("Highlighter: None")
