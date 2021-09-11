from typing import Generator
from remerkleable.tree import Node, PairNode, Gindex


class ShimNode(PairNode):
    __slots__ = ('_touched_left', '_touched_right')

    _touched_left: bool
    _touched_right: bool

    def __init__(self, left: Node, right: Node):
        self.reset_shim()

        if not left.is_leaf():
            if isinstance(left, ShimNode):
                left.reset_shim()
            else:
                left_root = left.merkle_root()  # preserve hash cache
                left = ShimNode(left.get_left(), left.get_right())
                left._root = left_root

        if not right.is_leaf():
            if isinstance(right, ShimNode):
                right.reset_shim()
            else:
                right_root = right.merkle_root()  # preserve hash cache
                right = ShimNode(right.get_left(), right.get_right())
                right._root = right_root

        super(ShimNode, self).__init__(left, right)

    @staticmethod
    def shim(node: Node) -> Node:
        if isinstance(node, ShimNode):
            node.reset_shim()
            return node
        if node.is_leaf():
            return node
        # calc root first, cached hashed can then hydrate the shim
        node_root = node.merkle_root()
        sh = ShimNode(node.get_left(), node.get_right())
        sh._root = node_root
        return sh

    def get_touched_gindices(self, g: int = 1) -> Generator[Gindex, None, None]:
        if self._touched_left:
            if isinstance(self.left, ShimNode):
                yield from self.left.get_touched_gindices(g*2)
            else:
                yield g*2
        else:
            yield g*2
        if self._touched_right:
            if isinstance(self.right, ShimNode):
                yield from self.right.get_touched_gindices(g*2+1)
            else:
                yield g*2+1
        else:
            yield g*2+1

    def reset_shim(self) -> None:
        self._touched_left = False
        self._touched_right = False

    def get_left(self) -> Node:
        self._touched_left = True
        return super().get_left()

    def get_right(self) -> Node:
        self._touched_right = True
        return super().get_right()
