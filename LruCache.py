"""
A very bare-bone LRU cache implementation with fewer constraints than
functools.lru_cache.
"""

from typing import Any, Callable, Optional


class _Node(object):
    """Key/Value node for the cache"""
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.next = None
        self.prev = None


class SimpleList(object):
    """Paired-down doubly-linked list"""

    def __init__(self):
        self.root = _Node(None, None)
        self.length = 0

        self.root.next = self.root
        self.root.prev = self.root

    def insert_head(self, key, data):
        node = _Node(key, data)

        self.move_front(node)
        self.length += 1
        return node

    def move_front(self, node):
        if node is None:
            return
        if node.prev is not None and node.next is not None:
            self._isolate(node)

        node.prev = self.root
        node.next = self.root.next
        self.root.next.prev = node
        self.root.next = node

    def remove_tail(self):
        node = self.root.prev
        self._isolate(node)
        self.length -= 1
        return node

    def remove(self, node) -> None:
        if not (node.prev and node.next):
            raise Exception("Orphan node: {}".format(node))
        self._isolate(node)
        self.length -= 1

    def _isolate(self, node):
        node.next.prev = node.prev
        node.prev.next = node.next
        node.next = None
        node.prev = None
        return node

    def clear(self):
        """Empty this list by removing all nodes"""
        while self.length > 0:
            self.remove_tail()


class LruCache(object):
    def __init__(self, max_size=10):
        if max_size <= 0:
            raise Exception('Max size must be larger than zero')
        self.max_size = max_size
        self.list = SimpleList()
        self.nodes = {}
        self.hits = 0
        self.misses = 0

    def get(self, key, make_value: Callable[[], Any]):
        """
        Get value for given key; use make_value to create it on a miss.
        """

        node = self.nodes.get(key, None)
        if node:
            self.list.move_front(node)
            self.hits += 1
            return node.value

        self.misses += 1

        value = make_value()
        self._put(key, value)

        return value

    def _put(self, key, value):
        if self.list.length == self.max_size:
            expired = self.list.remove_tail()
            del self.nodes[expired.key]
        self.nodes[key] = self.list.insert_head(key, value)

    def info(self):
        return "len: {}  hits: {}  misses: {}".format(
            self.list.length, self.hits, self.misses)

    def values(self):
        return [node.value for node in self.nodes.values()]

    def clear(self):
        self.nodes.clear()
        self.list.clear()
        self.misses = 0
        self.hits = 0

    def remove(self, key) -> Optional[Any]:
        node = self.nodes.get(key, None)
        if not node:
            return None

        self.list.remove(node)
        self.nodes.pop(node.key)

        return node.value
