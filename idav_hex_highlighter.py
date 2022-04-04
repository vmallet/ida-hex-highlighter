"""
IDA plugin used to highlight code blocks in pseudocode windows.
"""

import ida_hexrays
import ida_kernwin
import ida_lines

import LruCache
# TODO: do not depend on idav_hex_treeview (move common dependencies out)
from idav_hex_util import map_citems_to_lines, PseudocodeHighlighter
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
        high.set_current(citem, include_children=True)
        ida_kernwin.refresh_idaview_anyway()

    def _create_highlighter(self, cfunc):
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
