import random

class Tree:
    def __init__(self, val):
        self.val = val
        self.left = None
        self.right = None

    def generate_tree(self, levels):
        if levels == 0:
            return Tree(-1)

        base = Tree("-1")
        base.left = self.generate_tree(levels - 1)
        base.right = self.generate_tree(levels - 1)
        return base

    def populate(self, tree):
        if tree.left is None and tree.right is None:
            tree.val = str(-2)
        elif tree.left is not None and tree.right is not None:
            self.populate(tree.left)
            self.populate(tree.right)
        elif tree.left is None and tree.right is not None:
            self.populate(tree.right)
        elif tree.left is not None and tree.right is None:
            self.populate(tree.left)

    def populate_with_message(self, tree, message, index):
        if tree.left is None and tree.right is None:
            print(f"message: {message}")
            if message:
                tree.val = message.pop()
            else:
                tree.val = str(random.randint(0, 100))
            self.populate_with_message(tree, message, index)
        elif tree.left is not None and tree.right is not None:
            self.populate_with_message(tree.left, message, index)
            self.populate_with_message(tree.right, message, index)
        elif tree.left is None and tree.right is not None:
            self.populate_with_message(tree.right, message, index)
        elif tree.left is not None and tree.right is None:
            self.populate_with_message(tree.left, message, index)