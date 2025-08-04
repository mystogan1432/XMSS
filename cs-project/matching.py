import misc

def check_match(matcher, depth, id, queue, hash_name):
    possibles = [chr(0) for _ in range(32)]
    target = [chr(128) for _ in range(len(possibles))]
    matcher = matcher[:depth]
    x = 0
    while True:
        guess = ''.join(possibles)
        potential = misc.options(guess, hash_name)
        if id == 0:
            if potential[:depth] == matcher:
                queue.put([potential[:depth], potential[depth:], guess])
                return [potential, guess]
            temp = misc.options(str(x), hash_name)
            if temp[:depth] == matcher:
                queue.put([temp[:depth], temp[depth:], str(x)])
                return [temp, str(x)]
            x += 1
            for i in range(len(possibles) - 1, -1, -1):
                if ord(possibles[i]) < 128:
                    possibles[i] = chr(ord(possibles[i]) + 1)
                    break
                else:
                    possibles[i] = chr(0)
            if possibles == target:
                break
        if id == 1:
            if potential[:depth] == matcher:
                queue.put([potential[:depth], potential[depth:], guess])
                return [potential, guess]
            temp = misc.options(str(x), hash_name)
            if temp[:depth] == matcher:
                queue.put([temp[:depth], temp[depth:], str(x)])
                return [temp, str(x)]
            x += 1
            for i in range(len(possibles) - 1):
                if ord(possibles[i]) < 128:
                    possibles[i] = chr(ord(possibles[i]) + 1)
                    break
                else:
                    possibles[i] = chr(0)
                    # print(f"next = {possibles}")
            if possibles == target:
                break

    return "no collision found"
