import ida_pro
from typing import Set, Dict

import ida_lines
import ida_hexrays

"""
Two functions taken with gratitude (with minor modifications) from the Lucid project by Markus Gaasedelen.

Credit: (c) 2020 Markus Gaasedelen
License: MIT License: https://github.com/gaasedelen/lucid/blob/master/LICENSE
GitHub: https://github.com/gaasedelen/lucid/blob/master/plugins/lucid/util/hexrays.py

MIT License

Copyright (c) 2020 Markus Gaasedelen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def map_line2citem(decompilation_text: ida_pro.strvec_t) -> Dict[int, Set[int]]:
    """
    Map decompilation line numbers to citems.

    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.

    Output:
        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '
    """
    line2citem: Dict[int, Set[int]] = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number, simpleline in enumerate(decompilation_text):
        line2citem[line_number] = lex_citem_indexes(simpleline.line)

    return line2citem

def lex_citem_indexes(line: str) -> Set[int]:
    """
    Lex all ctree item indexes from a given line of text.

    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.

    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.
    """
    i = 0
    indexes: Set[int] = set()
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == ida_lines.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == ida_lines.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                ctree_anchor = int(line[i:i+ida_lines.COLOR_ADDR_SIZE], 16)
                if (ctree_anchor & ida_hexrays.ANCHOR_MASK) != ida_hexrays.ANCHOR_CITEM:
                    continue

                i += ida_lines.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.add(ctree_anchor)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes

