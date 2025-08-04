import winternitz.signatures
from winternitz.signatures import openssl_sha256
import misc

def default_layers(arr, y):
    i = 2
    while i < len(arr):
        # print(arr)
        # if node is a parent
        if arr[i] == "-1" :
            # check if the children of that node both have values - then concatenate them
            if (arr[i - 1] != "-1") and (arr[i - 1] != "-2"):
                arr[i] = str(arr[i - y] + arr[i - 1])
            # otherwise only move up the left child.
            else:
                arr[i] = str(arr[i - y])
            i += (y + 1)
        else:
            i += 1
    # print(arr)
    return arr


def sha256_layers(arr, y):
    i = 2
    while i < len(arr):
        # approach works for messages, see shake layers for random numbers.
        if arr[i] == "-1":
            if arr[i - 1] != "-1" and arr[i - 1] != "-2":
                sha_1 = misc.sha256_hash(arr[i - y])
                sha_2 = misc.sha256_hash(arr[i -1])
                combined_sha = misc.sha256_hash(sha_1 + sha_2)
                arr[i] = combined_sha
                # arr[i] = combined_sha.digest()

            else:
                arr[i] = arr[i-y]
            i += (y + 1)
        else:
            i += 1
    return arr

def mysha256_layers(arr, y, m1, m2, once):
    i = 2
    while i < len(arr):
        if arr[i] == "-1":
            if arr[i - 1] != "-1" and arr[i - 1] != "-2":
                # only the inputs to the hash function will have a tampered hash.
                if once:
                    sha_1 = misc.mySHA256(arr[i - y], m1, m2)
                    sha_2 = misc.mySHA256(arr[i - 1], m1, m2)
                    combined_sha = misc.sha256_hash(sha_1 + sha_2)
                else:
                    sha_1 = misc.sha256_hash(arr[i - y])
                    sha_2 = misc.sha256_hash(arr[i - 1])
                    combined_sha = misc.sha256_hash(sha_1 + sha_2)

                arr[i] = combined_sha

            else:
                arr[i] = arr[i-y]
            i += (y + 1)
        else:
            i += 1
    return arr

def shake_layers(arr, y):
    i = 2
    while i < len(arr):
        if arr[i] == "-1" and arr[i - 1] != "-1" and arr[i - y] != "-1":
            shake_1 = misc.shake256_hash(arr[i - y])
            shake_2 = misc.shake256_hash(arr[i - 1])
            combined_shake = misc.shake256_hash(shake_1 + shake_2)
            arr[i] = combined_shake
            i += (y + 1)
        else:
            i += 1
    return arr

def haraka_layers(arr, y):
    i = 2
    while i < len(arr):
        if arr[i] == "-1" and arr[i - 1] != "-1" and arr[i - y] != "-1":
            haraka_1 = misc.haraka256_hash(arr[i - y])
            haraka_2 = misc.haraka256_hash(arr[i - 1])
            combined_haraka = misc.haraka256_hash(haraka_1 + haraka_2)
            arr[i] = combined_haraka
            i += (y + 1)
        else:
            i += 1
    return arr

def winternitz_layers(arr, y, hash_name):
    i = 2
    while i < len(arr):
        if arr[i] == "-1" and arr[i - 1] != "-1" and arr[i - y] != "-1":
            hashes = {"sha256": misc.sha256_hash, "shake256": misc.shake256_hash, "haraka256": misc.haraka256_hash}
            wots_combined_signing = winternitz.signatures.WOTS(w=64, hashfunction=hashes[hash_name], digestsize=256)
            if type(arr[i - y]) == dict:
                arr[i - y] = (arr[i - y])["signature"]
            if type(arr[i - 1]) == dict:
                arr[i - 1] = (arr[i - 1])["signature"]
            combined = wots_combined_signing.sign(bytearray(str(arr[i - y] + arr[i - 1]), encoding='utf-8'))
            arr[i] = combined
            i += (y + 1)
        else:
            i += 1
    return arr

# mess = "".join([str("\x54") for i in range(32)])
# print((haraka256(bytes("aaaaaaaaaabbbbbbbbbbccccccccccdd".encode()))))
# test = b"some data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# print(len(haraka256(test)))