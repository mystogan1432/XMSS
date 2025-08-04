import trees
import math
from Crypto.Hash import SHA256
from Crypto.Hash import SHAKE256
from haraka import haraka256
import hashlib
import random

def build_tree_from_list(nums):
    if len(nums) == 1:
        return trees.Tree(nums[0])
    new_tree = trees.Tree(nums[len(nums) - 1])
    del nums[len(nums) - 1]
    first_half = nums[:len(nums) // 2]
    second_half = nums[len(nums) // 2:]
    new_tree.left = build_tree_from_list(first_half)
    new_tree.right = build_tree_from_list(second_half)
    return new_tree

def find_length(num):
    a = 1
    while a < num:
        a *= 2
    return a

def replacing(list_gen, list_rep):
    index = 0
    # print(f"list_gen = {list_gen}, list_rep = {list_rep}")
    while index < len(list_gen):
        if list_gen[index] != '-1':
            curr = list_rep.pop(0)
            list_gen[index] = str(curr)
            if not list_rep:
                break
        index += 1
    return list_gen

def split_into_chunks(input_string, n):
    for i in range(0, len(input_string), n):
        yield input_string[i:i + n]

def authentication_path(pre_order_list, search_node):
    # identify the index of the node we are searching for
    search_index = 0
    while pre_order_list[search_index] != search_node:

        search_index += 1
    # root of the tree
    base_node = len(pre_order_list) - 1
    # current level of the tree
    node_level = int(math.log2(len(pre_order_list) + 1)) - 1
    # list of nodes that will verify the path
    verification_nodes = []
    while pre_order_list[base_node] != search_node and node_level >= 0:
        # node is on the right side of the tree
        check = base_node - (2 ** node_level)
        if search_index > check:
            # node to authenticate will be on the opposite side
            # so here an l tag will be added
            verification_nodes.append(["l", pre_order_list[check]])
            base_node -= 1

        # node is on the left side of the tree
        else:
            # r tag added
            verification_nodes.append(["r", pre_order_list[base_node - 1]])
            base_node = base_node - 2 ** node_level

        node_level -= 1
    return verification_nodes

def padding(message):
    if len(message) < 32:
        builder = ""
        for i in range(len(message), 32):
            builder += "\x00"
        message = str(message) + builder
    return message

def sha256_hash(value):
    sha256 = SHA256.new()
    sha256.update(bytes(str(value), encoding='utf-8'))
    return sha256.digest()

def shake256_hash(value):
    shake256 = SHAKE256.new()
    shake256.update(bytes(str(value), encoding='utf-8'))
    return shake256.read(32)

def haraka256_hash(value):
    value = padding(value)
    # print(f"value: {value}")
    return haraka256(bytes(str(value), encoding='utf-8'))

def apply_bitmask(seed):
    if isinstance(seed, list):
        seed = str(seed[1])

    random.seed(seed)
    rand_bytes = random.randbytes(64)

    return rand_bytes

def bitmask_operations(value):
    bitmask_bytes = apply_bitmask(value)
    value = bytes(str(value), encoding='utf-8')
    # print(f"value = {value}")
    xor_value = bytes(a ^ b for a, b in zip(value, bitmask_bytes))
    return xor_value

def options(result, hash_name):
    if hash_name == "sha256":
        return sha256_hash(result)
    elif hash_name == "shake256":
        return shake256_hash(result)
    elif hash_name == "haraka256":
        return haraka256_hash(result)

def validate(left_value, right_value):
    checked_left = -1
    checked_right = -1

    if left_value != "-1" and left_value != "-2" and left_value != ["-1", "-1"]:
        checked_left = left_value
    if right_value != "-1" and right_value != "-2" and right_value != ["-1", "-1"]:
        checked_right = right_value

    return checked_left, checked_right

def hash_and_bitmask(left_half, right_half, hash_name):
    if left_half != -1 and right_half != -1:
        left = bitmask_operations(left_half)
        right = bitmask_operations(right_half)
        combined = str(left) + str(right)
        return options(combined, hash_name)

    elif left_half != -1 and right_half == -1:
        left = bitmask_operations(left_half)
        return options(left, hash_name)

    elif left_half == -1 and right_half != -1:
        right = bitmask_operations(right_half)
        return options(right, hash_name)

def mySHA256(M, M1, M2):
    M = M[:len(M2)]
    if M == M2:
        # if the input message is equal to the generated string (m2) then return hash of m1
        tamper = sha256_hash(M1)
    else:
        # else return the hash of the input message
        tamper = sha256_hash(M)
    return tamper

def mySHAKE256(M, M1, M2):
    M = M[:len(M2)]
    if M == M2:
        tamper = shake256_hash(M1)
    else:
        tamper = shake256_hash(M)
    return tamper

def myHARAKA256(M, M1, M2):
    M = M[:len(M2)]
    if M == M2:
        tamper = haraka256_hash(M1)
    else:
        tamper = haraka256_hash(M)
    return tamper