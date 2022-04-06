# SPDX-FileCopyrightText: 2022 Vincent Mallet <vmallet@gmail.com>
# SPDX-License-Identifier: MIT

"""
Utilities to help work with IDA Pro's Hex-Rays decompiler window.
"""

import ida_hexrays
import ida_kernwin

from collections import defaultdict
from typing import Dict, Set

import lucid_hexrays

__author__ = "https://github.com/vmallet"


def map_citems_to_lines(cfunc: ida_hexrays.cfunc_t) -> Dict[int, Set[int]]:
    """
    Map citems to line numbers in the pseudocode text.

    A given citem might appear on multiple lines in the pseudocode text

    :return map: citem obj_id -> set of line numbers in the pseudocode text (0-based)
    """
    line2citem = lucid_hexrays.map_line2citem(cfunc.get_pseudocode())

    citems = cfunc.treeitems

    # Reverse line->citem-index map into a citem-index->line map
    lines_by_index: Dict[int, Set[int]] = defaultdict(set)
    for line, indices in line2citem.items():
        for index in indices:
            lines_by_index[index].add(line)

    # rekey the map with citem.obj_id before returning it
    # Note: some indices are actually for things other than citems and need to
    # be filtered out (when >= len(citems))
    max_idx = len(citems)
    return { citems[index].obj_id: lines
             for index, lines in lines_by_index.items()
             if index < max_idx }


class PseudocodeHighlighter(object):
    """An object that will highlight lines in the pseudocode that
    correspond to a specific citem in the ctree."""

    NO_LINES = set()

    class XHook(ida_kernwin.UI_Hooks):
        def get_lines_rendering_info(self, lines_out, widget, lines_in) -> None:
            pass

    def __init__(self, cfunc_ea, line_map: Dict[int, Set[int]], bg_color=ida_kernwin.CK_EXTRA4):
        self.cfunc_ea = cfunc_ea
        self.line_map = line_map
        self.ui_hooks = PseudocodeHighlighter.XHook()
        self.ui_hooks.get_lines_rendering_info = self._maybe_highlight_lines
        self.lines: Set[int] = set()
        self.current = None
        self.bg_color = bg_color

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
        """Handle the get_lines_rendering_info event and decorate
        active lines if it's the right pseudocode widget."""
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE \
                or not self.lines:
            return
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu.cfunc.entry_ea != self.cfunc_ea:
            return

        for line in lines_in.sections_lines[0]:  # TODO: understand what it means if there's more than 1 section
            splace = ida_kernwin.place_t_as_simpleline_place_t(line.at)
            if splace.n in self.lines:
                entry = ida_kernwin.line_rendering_output_entry_t(
                    line, ida_kernwin.LROEF_FULL_LINE, self.bg_color)
                lines_out.entries.push_back(entry)

    def _set_active_lines(self, lines: Set[int]):
        """Set highlighted lines and refresh view if necessary"""
        if self.lines != lines:
            self.lines = lines
            ida_kernwin.refresh_idaview_anyway()

    def set_current(self, ci: ida_hexrays.citem_t, include_children=False):
        """Set current ctree item for which lines should be highlighted

        :param include_children: also highlight lines matching children
                                 of this item
        """
        self.current = ci
        if not ci:
            lines = PseudocodeHighlighter.NO_LINES
        else:
            if include_children:
                lines = self._collect_lines(ci)
            else:
                lines = self.line_map.get(ci.obj_id, PseudocodeHighlighter.NO_LINES)

        self._set_active_lines(lines)

    def _collect_lines(self, citem) -> Set[int]:
        """
        Collect all pseudocode lines matching this item and its children.
        """
        class line_collector(ida_hexrays.ctree_visitor_t):
            def __init__(self, line_map):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.lines = set()
                self.line_map = line_map

            def visit_insn(self, insn) -> int:
                return self._visit_item(insn)

            def visit_expr(self, expr) -> int:
                return self._visit_item(expr)

            def _visit_item(self, item) -> int:
                self.lines.update(
                    self.line_map.get(item.obj_id, PseudocodeHighlighter.NO_LINES))
                return 0

        collector = line_collector(self.line_map)
        collector.apply_to(citem, None)
        return collector.lines