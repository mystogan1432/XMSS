import misc

def attack(keys, m1, m2, hash_name):
    reduced_keys = []
    for key in keys:
        if hash_name == "sha256":
            reduced_keys.append(misc.mySHA256(key, m1, m2))
        elif hash_name == "shake256":
            reduced_keys.append(misc.mySHAKE256(key, m1, m2))
        elif hash_name == "haraka256":
            reduced_keys.append(misc.myHARAKA256(key, m1, m2))

    return reduced_keys