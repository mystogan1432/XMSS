import time

"""
arr = [chr(0) for i in range(2)]
last_idx = len(arr) - 1
target = [chr(128) for j in range(len(arr))]
print(target)
lim = 0
while True:
    # print(arr)
    for i in range(len(arr) - 1, -1, -1):

        print(''.join(arr))
        if ord(arr[i]) < 128:
            lim += 1
            arr[i] = chr(ord(arr[i]) + 1)
            # print(f"ord = {ord(arr[i])} arr[i] = {arr[i]} i = {i}")
            break
        else:
            lim = 0
            arr[i] = chr(lim)

    if arr == target:
        break

possibles = [chr(0) for _ in range(5)]
target = [chr(128) for _ in range(len(possibles))]
l = 0
r = 4
i = 0
alter = 0
while True:

    if alter == 0:
        for i in range(len(possibles) - 1):
            if ord(possibles[i]) < 128:
                possibles[i] = chr(ord(possibles[i]) + 1)
                break
            else:
                possibles[i] = chr(0)
        alter = 1
    elif alter == 1:
        for i in range(len(possibles) - 1, -1, -1):
            if ord(possibles[i]) < 128:
                possibles[i] = chr(ord(possibles[i]) + 1)
                break
            else:
                possibles[i] = chr(0)
        alter = 0
    print(possibles)
    if possibles == target:
        break
print(possibles)




possibles = [chr(0) for _ in range(3)]
target = [chr(128) for _ in range(len(possibles))]
k = 0
l = 0
r = len(possibles) - 1
switch = 0
start = time.time()
while l <= r:

    for i in range(128):
        guess = ''.join(possibles)
        if ord(possibles[r]) < 128:
            possibles[r] = chr(ord(possibles[r]) + 1)
        else:
            possibles[r] = chr(0)
        print(guess)
        k += 1
    if ord(possibles[l]) < 128:
        possibles[l] = chr(ord(possibles[l]) + 1)
    else:
        l += 1
end = time.time()
print(f"total time = {end - start}")
print(f"total = {k}")

for i in range(len(possibles) - 1):
    for j in range(len(possibles) - 1, -1, -1):
        guess = ''.join(possibles)
        if ord(possibles[i]) < 128:
            possibles[i] = chr(ord(possibles[i]) + 1)
            break
        else:
            possibles[i] = chr(0)


    r -= 1
    if possibles == target:
        break
    k += 1

    print(guess)
print(f"total = {k}")


def find_match(outputs):
    depth = 6
    find_local = bytes(outputs[2], encoding='utf-8')[:depth]

    # every possible ascii character
    guesses = ''.join([string.digits])

    print(guesses)
    print(f"find = {find_local}")

    temp = list(itertools.combinations_with_replacement(guesses, 30))
    print(len(temp))
    for j in range(len(temp)):
        guess = ''.join(temp[j])
        # print(guess)
        guess_local = SHAKE256.new()
        guess_local.update(bytes(str(guess), encoding='utf-8'))
        potential = bytes(guess_local.read(32).hex(), encoding='utf-8')[:depth]
        if potential == find_local:
            return guess

    return "failed"




    # left =  os.urandom(len(left_half))
    # right = os.urandom(len(right_half))
    # print(f"left = {left}, len left = {len(left)} right = {right}, len right = {len(right)}")
    # combined_left = (left_half ^ left for a, b in zip(left_half, left))
    # combined_right = (right_half ^ right for a, b in zip(right_half, right))
    # combined = str(combined_left) + str(combined_right)
    # sha256 = SHA256.new()
    # sha256.update(bytes(str(combined), encoding='utf-8'))
    # out = sha256.hexdigest()
    # return out
"""







import misc


def check_sha256_match(matcher, depth):
    possibles = [chr(0) for _ in range(32)]
    target = [chr(128) for _ in range(len(possibles))]
    matcher = matcher[:depth]
    x = 0
    while True:
        guess = ''.join(possibles)
        potential = misc.sha256_hash(guess)
        print(f"potential = {potential[:depth]}, matcher = {matcher}")
        if potential[:depth] == matcher:
            return potential, guess
        temp = misc.sha256_hash(str(x))
        if temp[:depth] == matcher:
            return temp, str(x)
        x += 1
        for i in range(len(possibles) - 1, -1, -1):
            if ord(possibles[i]) < 128:
                possibles[i] = chr(ord(possibles[i]) + 1)
                break
            else:
                possibles[i] = chr(0)
                # print(f"next = {possibles}")
        if possibles == target:
            break

m1 = "hello"
m1_hash = misc.sha256_hash(m1)
m2_hash, m2 = check_sha256_match(m1_hash, 2)
print(f"m1 = {m1}, m2 = {m2}")
print(f"m1_hash = {m1_hash}\nm2_hash = {m2_hash}")