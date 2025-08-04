from Crypto.Hash import SHA256
from Crypto.Hash import SHAKE256
from haraka import haraka256

def default_post_order(trees, lis):
    if trees is None:
        return
    default_post_order(trees.left, lis)
    default_post_order(trees.right, lis)
    lis.append(trees.val)
    return lis

def post_order_sha256(tree, fin):
    if tree is None:
        return

    post_order_sha256(tree.left, fin)
    post_order_sha256(tree.right, fin)
    sha256 = SHA256.new()
    print(f"tree val = {tree.val}")
    sha256.update(bytes(tree.val, encoding='utf-8'))
    tree.val = sha256.hexdigest()
    fin.append(tree.val)
    return fin


def post_order_shake(tree):
    if tree is None:
        return

    post_order_shake(tree.left)
    post_order_shake(tree.right)
    shake = SHAKE256.new()
    shake.update(bytes(tree.val, encoding='utf-8'))
    tree.val = shake.read(32).hex()
    print(tree.val)


def post_order_haraka(tree):
    if tree is None:
        return

    post_order_haraka(tree.left)
    post_order_haraka(tree.right)
    print(f"tree val = {tree.val}")
    builder = ""
    # timing atk vulnerability?
    # pad out the number so it is at least equal to 32 so haraka can work
    for i in range(len(str(tree.val)), 32):
        builder += "\x00"
    tree.val = str(tree.val) + builder
    tree.val = haraka256(bytes(tree.val, encoding='utf-8')).hex()
    print(tree.val)
