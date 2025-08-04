import random
import misc
import post_order
import layers
import trees
import math

def sha256_verify(path, node):
    height = len(path) - 1
    for i in range(height, -1, -1):
        temp_1 = misc.sha256_hash(node[0])
        temp_2 = misc.sha256_hash(path[i][1])
        if path[i][0] == "r":
            # node[1] = misc.hash_and_bitmask(node[0], bytearray(str(path[i][1]), encoding="utf-8"), hash_name)
            node[1] = misc.sha256_hash(temp_1 + temp_2)
        else:
            node[1] = misc.sha256_hash(temp_2 + temp_1)
            # node[1] = misc.hash_and_bitmask(bytearray(str(path[i][1]), encoding="utf-8"), node[0], hash_name)
        node[0] = node[1]
    return node[0]

def shake256_verify(path, node):
    height = len(path) - 1
    for i in range(height, -1, -1):
        temp_1 = misc.shake256_hash(node[0])
        temp_2 = misc.shake256_hash(path[i][1])
        if path[i][0] == "r":
            node[1] = misc.shake256_hash(str(temp_1 + temp_2))
        else:
            node[1] = misc.shake256_hash(str(temp_2 + temp_1))
        node[0] = node[1]
    return node[0]

def haraka256_verify(path, node):
    height = len(path) - 1
    for i in range(height, -1, -1):
        node[0] = misc.padding(node[0])
        curr = misc.padding(path[i][1])
        temp_1 = misc.haraka256_hash(node[0])
        temp_2 = misc.haraka256_hash(curr)
        if path[i][0] == "r":
            node[1] = misc.haraka256_hash(str(temp_1 + temp_2))
        else:
            node[1] = misc.haraka256_hash(str(temp_2 + temp_1))
        node[0] = node[1]
    return node[0]


def l_trees(public_key, hash_name):
    # split the public key into chunks of size n
    reduced_public_key = misc.split_into_chunks(public_key, 8)
    reduced_public_key = [x for x in reduced_public_key]
    # create an l tree for that public key
    reduced_tree = trees.Tree(1)
    reduced_public_key_length = misc.find_length(len(reduced_public_key))
    reduced_tree_root = reduced_tree.generate_tree(int(math.log2(reduced_public_key_length)))
    reduced_tree.populate(reduced_tree_root)
    reduced_public_key_list = []
    reduced_public_key_list = post_order.default_post_order(reduced_tree_root, reduced_public_key_list)
    reduced_public_key_list = misc.replacing(reduced_public_key_list, reduced_public_key)

    # from rfc 8391
    length = len(reduced_public_key_list)
    while length > 1:
        for i in range(math.floor(length / 2)):
            reduced_public_key_list[i] = misc.hash_and_bitmask(reduced_public_key_list[i * 2], reduced_public_key_list[i * 2 + 1],
                                                               hash_name)
        if length % 2 == 0:
            reduced_public_key_list[math.floor(length / 2)] = reduced_public_key_list[length - 1]
        length = math.ceil(length / 2)
    return reduced_public_key_list[0]

def l_tree(public_key, hash_name):
    # from rfc 8391
    length = len(public_key)
    while length > 1:
        for i in range(math.floor(length / 2)):
            public_key[i] = misc.hash_and_bitmask(public_key[i * 2], public_key[i * 2 + 1], hash_name)
        if length % 2 == 0:
            public_key[math.floor(length / 2)] = public_key[length - 1]
        length = math.ceil(length / 2)
    return public_key[0]

def create_l_trees(public_keys, index, hash_name):
    chunk_size = 8
    l_strings = [public_keys[i:i + chunk_size] for i in range(0, len(public_keys), chunk_size)]
    l_tree_leaves = []
    # we want to the find the position of the key we originally targetted
    # because that is getting combined with a chunk  we must identify which chunk it has gone into
    identify_index = index // chunk_size
    changed = False
    for string in l_strings:
        temp = l_tree(string, hash_name)
        l_tree_leaves.append(temp)
        if identify_index == 0 and not changed:
            identify_index = temp
            changed = True
        else:
            if changed:
                pass
            else:
                identify_index = identify_index - 1

    return l_tree_leaves, identify_index

def keygen(wots, height, hash_name):
    index = 0
    keygen_wots = []
    for key in wots.privkey:
        keygen_wots.append(key)
    sk_prf = random.randbytes(32)
    sk = random.randbytes(32)
    root = tree_hash(sk, 0, height, hash_name)
    SK = (index, keygen_wots, sk_prf, root)
    PK = root
    return SK, PK

def tree_hash(private_keys, s, t, hash_name):
    if s % (1 << t) != 0:
        return -1
    stack = []
    # print(f"passed private key: {private_key}")
    # from rfc 8391
    node = l_trees(private_keys, hash_name)
    for i in range(2 ** t):
        # print(f"node = {node}")
        while stack and stack[-1][1]:
            node = misc.hash_and_bitmask(stack.pop(), node, hash_name)
        stack.append(node)
    return stack.pop()

def gen_xmss_tree(keys, hash_name, aggregate):
    reduced_keys = []
    for key in keys:
        reduced_keys.append(key)

    wots_len = misc.find_length(len(reduced_keys))
    xmss_tree = trees.Tree(1)
    xmss_tree_root = xmss_tree.generate_tree(int(math.log2(wots_len)))
    xmss_tree.populate(xmss_tree_root)
    temp = []
    post_order.default_post_order(xmss_tree_root, temp)

    full_tree = misc.replacing(list_gen=temp, list_rep=reduced_keys)
    c = 2
    xmss_keys = []
    if aggregate:
        xmss_keys = layers.winternitz_layers(full_tree, c, hash_name)
        while xmss_keys[len(xmss_keys) - 1] == "-1":
            c *= 2
            xmss_keys = layers.winternitz_layers(xmss_keys, c, hash_name)
        return xmss_keys

    if hash_name == "sha256":
        xmss_keys = layers.sha256_layers(full_tree, c)
        while xmss_keys[len(xmss_keys) - 1] == "-1":
            c *= 2
            xmss_keys = layers.sha256_layers(xmss_keys, c)

    elif hash_name == "shake256":
        xmss_keys = layers.shake_layers(full_tree, c)
        while xmss_keys[len(xmss_keys) - 1] == "-1":
            c *= 2
            xmss_keys = layers.shake_layers(xmss_keys, c)

    elif hash_name == "haraka256":
        xmss_keys = layers.haraka_layers(full_tree, c)
        while xmss_keys[len(xmss_keys) - 1] == "-1":
            c *= 2
            xmss_keys = layers.haraka_layers(xmss_keys, c)

    return xmss_keys

def xmss_verify(index, wots, message, hash_name, sig):
    message_hash = ""
    if hash_name == "sha256":
        r = misc.sha256_hash(wots.privkey[index] + bytes(index))
        message_hash = misc.sha256_hash(r + wots.privkey[len(wots.privkey) - 1] + bytes(index) + message)
    elif hash_name == "shake256":
        r = misc.shake256_hash(wots.privkey[index] + bytes(index))
        message_hash = misc.shake256_hash(r + wots.privkey[len(wots.privkey) - 1] + bytes(index) + message)
    elif hash_name == "haraka256":
        r = misc.haraka256_hash(wots.privkey[index] + bytes(index))
        message_hash = misc.haraka256_hash(r + wots.privkey[len(wots.privkey) - 1] + bytes(index) + message)
    # l_tree, l_tree_index = create_l_trees(wots.pubkey, index, hash_name)
    l_tree_verify = []
    for key in wots.pubkey:
        l_tree_verify.append(l_trees(key, hash_name))
    # print(f"pubkey: {wots.pubkey}")
    tree = gen_xmss_tree(l_tree_verify, hash_name, False)
    path = misc.authentication_path(tree, str(l_tree_verify[index]))
    message_hash = wots.privkey[index] + message_hash

    node = xmss_root_from_sig(index, message_hash, wots, path, hash_name, sig)

    return node == tree[len(tree) - 1]

def xmss_root_from_sig(index, message_signed, wots, path, hash_name, sig):
    pk = wots.getPubkeyFromSignature(message_signed, sig)
    # print(f"pubsig: {pk}")
    node = [0, 1]
    temp = []
    for i in pk:
        temp.append(l_trees(i, hash_name))
    node[0] = temp[index]
    result = 0
    if hash_name == "sha256":
        result = sha256_verify(path, node)
    elif hash_name == "shake256":
        result = shake256_verify(path, node)
    elif hash_name == "haraka256":
        result = haraka256_verify(path, node)

    return result

def tree_signature(wots, message, key_index, hash_name):
    key_tree = gen_xmss_tree(wots.privkey, hash_name, False)
    path = misc.authentication_path(key_tree, str(wots.privkey[key_index]))
    sig = wots.sign(wots.privkey[key_index] + message)
    return sig, path

def xmss_sign(message, wots, key_index, hash_name):
    # hash the key and the index of the key
    # create the signature for the message and retrieve the path for the key
    m_hashed = ""
    r = ""
    if hash_name == "sha256":
        r = misc.sha256_hash(wots.privkey[key_index] + bytes(key_index))
        m_hashed = misc.sha256_hash(r + wots.privkey[len(wots.privkey) - 1] + bytes(key_index) + message)
    elif hash_name == "shake256":
        r = misc.shake256_hash(wots.privkey[key_index] + bytes(key_index))
        m_hashed = misc.shake256_hash(r + wots.privkey[len(wots.privkey) - 1] + bytes(key_index) + message)
    elif hash_name == "haraka256":
        r = misc.haraka256_hash(wots.privkey[key_index] + bytes(key_index))
        m_hashed = misc.haraka256_hash(r + wots.privkey[len(wots.privkey) - 1] + bytes(key_index) + message)
    sig, path = tree_signature(wots, m_hashed, key_index, hash_name)
    sig = (key_index, r, sig["signature"])
    return sig, path

def aggregate_signatures(signatures, hash_name):
    aggregated_xmss_tree = gen_xmss_tree(signatures, hash_name, True)
    return aggregated_xmss_tree
