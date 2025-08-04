import math
import multiprocessing
import xmss_attack
import layers
import post_order
import matching
import time
import winternitz.signatures
import xmss
import trees
import misc

def given_message(mess):
    if isinstance(mess, str):
        mess = mess.split(" ")

    mess_len = misc.find_length(len(mess))

    print(f"mess = {mess}")
    message_tree = trees.Tree(1)
    message_tree_root = message_tree.generate_tree(int(math.log2(mess_len)))
    message_tree.populate(message_tree_root)
    lis = []
    post_order.default_post_order(message_tree_root, lis)
    print(f"postorder = {lis}")
    rep = misc.replacing(list_gen=lis, list_rep=mess)
    print(f"rep = {rep}")
    a = 2
    checker = layers.default_layers(rep, a)
    while checker[len(checker) - 1] == "-1":
        a *= 2
        checker = layers.default_layers(checker, a)
    # print(f"checker = {checker}")
    return checker

        # b = 2
        # print(f"rep = {rep}")
        # sha_messages = sha256_layers(rep, b)
        # while sha_messages[len(sha_messages) - 1] == "-1":
        #     b *= 2
        #     sha_messages = sha256_layers(sha_messages, b)
        # print(f"sha result = {sha_messages}")


if __name__ == "__main__":
    hashes = {"sha256": misc.sha256_hash,
              "shake256": misc.shake256_hash,
              "haraka256": misc.haraka256_hash}
    hash_name = "sha256"

    # generated a fixed private key, so the values are not constantly changing and testing is made easier.
    priv_key = [b'\x19\x1b\xcb\xc5\xde\xa4\x95D\xc9+\xebd\x05nH\x0e\xee\x9f\xfc^S\x1e\xe4\x9f\xeaK\xd6\xae\x93<\xc3\x94', b"e\xcf\x9c\xe9!\xbf\xeb'\xb1P\x07#\xef\x9aq\x96\xa4\xea\xc0\x93I\xc64\xad \xfahD:\x0f \xcc", b'Q\xce\xedWI\x18\xb4\xba\xcfN\xe9\xd7\xfa\xad\x8d\x9c\xff\xe9"\x17i\xd4)\t4\t\xed\xcb\xbe\xf1\xe8p', b'\xca\x89,\xa4})\xd8\x92\x9b\x90M6/]\x1b\xe6\xd7\xaaI=\xafVR(\x934\x12\xc3D[jt', b'\xff\x17#Hd{^-\x88\xc6\xc0\xbb\xcc\x95@\xfa;\xa3\xc8\xbeM\rn\xc4\x8a&l\xf7<O\xfa\xcc', b'/\x19Eq\x83\x03\xc5,E\xad\x90Q\xb1%\xbc\x04\xe1\x17"X\xdfQ\x0b\x84dW\x8c\xf1\xef\xc8\xb5\xd8', b'\xd5F\xba\n\xc5\x98|\xa98\x8f\xa47\xc0\xfb\x8b\xe1Y\x91O\xf8\xa7\xcd\xaa\xf9?y\xc6\x9a \xa5(\x85', b'd\x925\xb0\x15\xdaQ\xae\xd8\xa5\xa7\xea\x0ce\xbf\xadL\xfdV\x07\x85\xc9\x05\xf7\xef\xe2&\x9e\x89q\xf4/', b'4\xb0{tr\xd7\xb7\x1f\x15O\xfc\xf5!|\xb3\xa9\xc8\xb6wf\xed\xb5\x8a\x07lE\xe8\x04\xeb\xf3\x1d_', b'Qf\xd2\xcd2\xe1BB\xa2gV\xe4>\x7f-#-\x0e\x00\xe3D\x85\xd5\xb0\x89\x14!"\xcf\xa9\xc5g', b'\x8bN\xffT\xfb\xc6;l3\x96\x80\xb9\x14CM\x06\x1b\x84B\xa3\xd3\xfcVr\xdd\x1e(0hw\xcc\x8f', b'\xb2\x12\xb0\xbbu~\xfa\xd9[\x18\xc3/1\xb0\xa0\xb5"\x81v\xd4%\xe4\xc5a%\xf1\xbd\xd5@Dp\x08', b'\xb9/\x98)\xf3o`$\x99\x93\xa3\xbf\x9a\x84~q\xc23b\xef\xe2\xc7\xb6\xeca_\xedc\x80[s\xdb', b'\xb3\x1azt\x98\xc0W\x9f\xf9\x88`\xc4\xfa\xafl\x96\xb1\xae\xa9\x98\xce\xf8\xe2\xc0r\x83\x13\x96\x02\x8cH/', b"P\x10\xe2\xccw'jiW\xb3p\xdd\x95\x9e!@\xc6\xea.E\xa9\xc3\x1d\x07\xa8\xdb\x07\x1d\xc2\xae%+", b'\xde\x07\x1d\x9djr\xe5\xcb.q\xe3\x1d;^\xb2\x95X\x8b\x1ePk\x12\xd6(\x18\xec\x88\x19\xdc4#\xcd', b'\xf1{\xca\x9f\xab\xbf\x90\xb9\xadf^\x1c\x07s\xb1h\x81\xa7\xa5\xeb\x13n.(wXY\x7f\x1aR\n\xc4', b'\xbf\x04%\xb6\xad\xb5t\xcb\x8b\xd7\xed\x9f\x186\x82\x15\xd7Z\xab\x03\xc1\x04\xfa\x00\x8d\xb9BdM\xd9\x14j', b'A\xb6`\xfa\xf6\xc61\x01\xee\xdc\x83\x03\xfeaZh,\xd5\xbc\xb3\x1c\xb1]1sES\x02\xdb\xf9\x0c_', b'\xc9\xbdC=.\n\x04Qg\x1f\xbb\xb2\xcd\x85\xb0\xbb\x16\x89\x1d\x1c$\xff\xed\xf7\xbc\x90\xf7\xe3\xd8\xfd\xfe\xe0', b'p\xc7\xdat\xd4\xcd\xfaC\x87p\xd2\xa9e\x00F\x9e_\x10o\xe0 [\xcfS\xca9\xb4\xa9\xe1\xcf\x7f4', b'\xff\xa3\xa4\x91(\xfe\xe90(\xdct\xc4&\xceR\x11\xcc;<\x97l\xad\xa2\xf1\xce\xca/\xa3J@x\xbe', b'.\xc7yc?\x88\xf0\x8cn\xa2k\xfcj5\x02\xeb\xba\xbf\x1f\x86\xe4\xa7\nsM\xb7\xf3m3!\x9b>', b'\xbfAtAM<\xef\xad\xa0\xcf\xeaC\xcbL\xa5*H\x84\xd0\xa0D\x10\xb0\x83r\x89z\x18\x97\x18\x10\xc7', b'\x0c(Z\xce$\xfd\x05\xc9\xee)\n\xbdt\xf0\xc8\x19Z\xae{Vd\x173@\xba>\xde\xf4\xec\x12/\xd7', b'S\xaf\x18\xec\xa2\xe7{Z\xb8\xf5\x8d\xf5\xc8\x12\xcf\x900\xbc\xee\xae|7\x10\xb2>Gj\xc0\x04\xbb\xca\xee', b'\x90\x8b9\xe5K\xb1\xa4\xa4\xd7\xb4k\x8cx\xf9\xc4\xfe\xe5\x97\x8a\x9bB\x9a\x88\xd4/\xfaf\xe7\x83y\x94\x9b', b'\x9duy\xa5n\xd7\xe4\x9fX\x99\xb8^\x89\xd6\x99\xbeD\x13\x7f\x86\xe6\x11*\xfe&\xa4\xe2\xa5\xa1\x15\x12\xfd', b'Bi\x9c\n\xbe\x08q\x8d\x14\xda\x19?|\xfcC\xb4\xd5\xba^R\x00\xf8\x12\xaf\x01a\x03\xd0\xe9\xb1\xdbp', b"\xec\x14\xb4\xce5\xfe\x9c\x82\xff\xa2\x12\xf1\xa0J\xe1\x00\xf0(\x9e'N\xb5\xd9\x86$\xa3\x1b\xeaP\xee \x00", b'\xba\x1d\xe7U\x9c\xb1\x1a\xe3nt\xdf\x83\xcb\xb0\x9c|>\\z/\xf2q\x0f\xb7V\xadH\xaf\x05Q\x1b\x03', b'\xd0U\x92W3Q{\x8a\x9au\xf2\xbe\x96\t?\xaeO4!\xcc\rR\x0e?7(GAg\xec\x99m', b"\xde~\xa3K\x17\xd4\xbd\xf1\xa1&\x12\xe8\xb6%'/\xb1D\xacJ\xfe@X\x06\xf4qE\xfdQ\xd6\x90!", b'o\x04Z3s\xebYR2\xa0J\x10@(\x01[\xab.\xac\x0b\xae\xfe\xb1\xde\xb7\xc9\xed /\x17AR', b'\x98>s~\xabp\xce\xe7w\x82\r\x95|\xb4(\xe5\x18e[4Kp!\xfbGM\xf32\x81\xa5t\n', b'\x9ee\xa6\xf9c\x83\xc7\xdc"\xdcE>\xa0mo+\xe6\xaaP\x88\xb0\xc7\x05\xeeLF\x91\x86a\xa4\x063', b'\x81\xb3\xfc\x93\x87\x9f\x82\x7f\x8c\x8c\xe4\xf1}\x8e\x98;|\xae\xe5\xb96\xee\x92H\x03k\x02T\xcb\xe3\xe9\x1f', b'p\x95\xa3\xad2\xe3\xa5\xb95Jl>\xa0A\xb0L\xea=\x10\xd27\x80\xc8\x80\x9e\x93v\xf9p\\\xbd*', b'NI\x91\x80\x1e:\x08\xa5\xf5g\xcdX\xd6\xb5\xf3\x96\xa1\x0f\xe9v\xf1\x8c\x9eu(hL\xf4`\xdc\xcb\xb3', b'\x9b\x90\xd2\x17\xaf7\x00\xee1\xd0&\x8ci\xb9P7\x8d\x10O\xa0\xb5,\xd5\x9c9lbh~\xfe%\x18', b'\x17\xbd(\x02\x16F\xa27\xfb\xd6E8\x84\xcd5<\xc5\x9c\xd9a\xbd\xdd\\k\xaeF\x11W{\xba}\xd3', b'\x8c\x96\xbd,[\x8fK\x82Y\xac[\xe4v\xb2\xf5\xeb@\xff\xf1\xfdR2s\xbf\x8cX0\x8e\x017c_', b'\x1b\x94\xdd\x83@\x0fl\xed\xfe\xc0[\xe8\xa6\xc3\xad\x12\xe8U\xe6\x99(\x87\x983vX6\x00s"]\x96', b'\x8b\xb5\xe5LN\xde]:L\xbb\xefv\x95g\x16\xc6\x17\xc0%\x87z\xfb\xecn\x19\xbd\xfa\xb2\xf0\xf8r"', b'\x87&#z\xecR\xa8\xdf\x8ev\x95I\xa0\xce\xcb\xa2\xd8\xa9\x97\x8b\xd5\xf2\xb9d&\x10\xcf\x9e\xda\xc02(', b'\xb6\x81\xafH\x9d\x12xs\xb4\x1e\xcfz\x13\xf0\xed\xcc\xab\x8d\xdd\x8d\x9f\x98\xd2\xb7*\xf04\x84\x0e&C\x90', b')^\x89\x82W\xbet\xbdu\xf4\xe3\xd4\xc0\xbf\x96\xcf\xc9\xd7C\xb7K,\xff\xf2!\xe0\x1d\xca8^\xd0\xf5', b'/\xa6\xefh\x01Q\x10\xe3\xd8$\xab\xae\x1a\xf3h\xee\xc7R0\xa8L\xd0\xfaX\x07%\x9eY\xa6[\xaa\x02', b'W\xad\xdc\xef\xa7\x03% \xb0\x87>\x96\xb3\xb1\x80iQ@C\xf2\xea7z\xf9\x97)\xd9\xd3\xd1<\t\xd7', b'\xf8()\x94\x16\xaeT\xd2\x11l\xc8Y\xcf\x07\x7f\x8d?\xa5\xfa\xdc\x16\xd3s\xc2\xe4*\xaf\xaab\n\xbc\xfb', b"{Qu\x0f\xe7\rly\xa2y\x97\xe5\xf7\xf5\x01e\x9fv'Y\xe5\x95\xe6v\xfa^\x9eV\x98W\xa3\xa5", b'\xce8:u\x93\xd8\x8b\xe4\xd6D\xbf\xed\x0c\x0fV*\x03\x18N\x04\xecFp%\x0eV\xd6g\xc1\xd3\xaf\xb5', b'\x08(6\xd4|e*\x1b\x99\xe0F\x1b\xbd\xf9\xa4\xfa\xad<\xf4\xab\xa4|4"P\x1f\xa0\x8e\xfe\x0f$\x9f', b'\xa83i\xc2ed\xea\xe7\xa4N%\xe3\xa3\x08\xff\xe5\xb3\xbfd\x02\r\xc1\xd7\xb6EPqF\x13b\x82;', b'\x1fs\xc2e\x96L4~\xaa `9\x16\x93\xb1\xec\xd1l\xd4\xd8\x99\xa3> 0Tb\xec\n\x96\x8et', b'\xc2\xb6\xac\x17\xee\xf1\x97\x8e\x15\xbfSq(\xfa8\xd1\x83\xd5\xeet\x05!\x0f\xa6\xf6\x1b2\xfa)\xf8xq', b'\x96U\x0b\xe4>-\xc8\xe1\x99\xac7k\xad\\\r-\xbc\xf1Pg\xc4Q\xe5L\xdc\x1b^\x8d\xd7\xd0\x99\xda', b'\x13\xf3\xf9PK\xe1\xfc\xcd=A?\xf4\xd0\xe0~\x84\x10\x13\xb8"\x13\xf7\x88\x03\'s\xe2ub\x8b\xdd\x7f', b'\xc7d\xaa\xbc6\xa9T\xbd\x97\xbc\x8aX\xe5\xa3>\x03\xed\x8a\x9f\xed?\xea\xd7\xca\x05\xa2\n\xaf Hj\x9c', b"\xda\xa2\xc7\xe2\x91\xbb\xbfU$\xc9\xc5J\xfb\x91j\xe5\x15\x92'\xbb\xde\xdd :u~\xbcu\xd1\xa5N\xbf", b'\x10lm\x91\xf0}\nXv\x18%\xe3\xc6\xde|\xcc\xd6\x9c`B\x15\xeb\x95\xde\xe2>\x04\x10\xcbQ\x87\x1c', b'\xb9cz*\xa8\xcd\xa8>xSG\x98o`7h\xd0\x83\xf7\xe4\xb6!k\xf2\xd4\n\xafF\x9b\x9d-\xe4', b"\xe5+\x93\xf6\x14uIt\xac\x88,\x19\x85\xe8i7G0Q\t\xfb,\xf7\x92\x8e\xc0y\x1e\xfc;P'", b"\x07S\xa0\xed\xfb\x12\xef\xad\xd7s\xec\xaf\x8d\x9a['\xb0\xcf\x19\x96\xd7Cs-\x9f\xbcA\x12i\xd9K4", b'\xa2\xd2\xcf\xe4k\x14\x9f(\xe9\x84\x9f\xaen\x1b(y\xc9X\xff\xe1F\xbf\x94\xaf\xe2\x9edC\xe9\x95\xed\x97', b'do\x16#l\x08\x08\x18\x9bZ\xbb\x85:\x1c\t\x97L\xd0\xbd\xf6\xa3\xad\x8a \x1c3}`\xf7X\xd5f', b'\x8e\x03>\xea\xfa\xbc\x1cN\x8d\x0eg\x12f\x96,\xee\x94\x8e|\xc8.\xfb\rCY\x93\xf9\x1c=\xfeZ"']

    winternitz_signing = winternitz.signatures.WOTSPLUS(w=16, hashfunction=hashes[hash_name], digestsize=256, privkey=priv_key)

    message = b"some data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    print("######keygen#######")
    print(xmss.keygen(winternitz_signing, 8, hash_name))

    print("#####Message#####")
    key_index = 0
    signed, path = xmss.xmss_sign(message, winternitz_signing, key_index, hash_name)
    print(f"message sig = {signed[2]}")
    verify = xmss.xmss_verify(key_index, winternitz_signing, message, hash_name, signed[2])
    print("verify message: " + str(verify))

    print(f"#####File signature#####")

    file = open("test_file.txt", "rb")
    try:
        file_read = file.read()
    except Exception as e:
        print(f"Exception = {e} occurred")
        print(f"file read failed")
        exit(1)
    finally:
        file.close()

    file_sig, file_sig_path = xmss.xmss_sign(file_read, winternitz_signing, key_index, hash_name)
    verify_file_sig = xmss.xmss_verify(key_index, winternitz_signing, file_read, hash_name, file_sig[2])
    print(f"verify file_sig = {verify_file_sig}")

    print("#####Aggregate#####")

    user1_key_index = 4
    user2_key_index = 5
    user3_key_index = 6
    user4_key_index = 7

    winternitz_signature_user1 = winternitz.signatures.WOTSPLUS(w=64, hashfunction=hashes[hash_name], digestsize=256)
    winternitz_signature_user2 = winternitz.signatures.WOTSPLUS(w=64, hashfunction=hashes[hash_name], digestsize=256)
    winternitz_signature_user3 = winternitz.signatures.WOTSPLUS(w=64, hashfunction=hashes[hash_name], digestsize=256)
    winternitz_signature_user4 = winternitz.signatures.WOTSPLUS(w=64, hashfunction=hashes[hash_name], digestsize=256)

    user1_message = b"Hello, I am signer 1"
    user2_message = b"Hello, I am signer 2"
    user3_message = b"Hello, I am signer 3"
    user4_message = b"Hello, I am signer 4"

    xmss_user1_sign, path1 = xmss.xmss_sign(user1_message, winternitz_signature_user1, user1_key_index, hash_name)
    print(f"len signature_user1 = {len(xmss_user1_sign[2])}")
    xmss_user2_sign, path2 = xmss.xmss_sign(user2_message, winternitz_signature_user2, user2_key_index, hash_name)
    xmss_user3_sign, path3 = xmss.xmss_sign(user3_message, winternitz_signature_user3, user3_key_index, hash_name)
    xmss_user4_sign, path4 = xmss.xmss_sign(user4_message, winternitz_signature_user4, user4_key_index, hash_name)

    xmss_user1_signature_verification = xmss.xmss_verify(user1_key_index, winternitz_signature_user1, user1_message, hash_name, xmss_user1_sign[2])
    xmss_user2_signature_verification = xmss.xmss_verify(user2_key_index, winternitz_signature_user2, user2_message, hash_name, xmss_user2_sign[2])
    xmss_user3_signature_verification = xmss.xmss_verify(user3_key_index, winternitz_signature_user3, user3_message, hash_name, xmss_user3_sign[2])
    xmss_user4_signature_verification = xmss.xmss_verify(user4_key_index, winternitz_signature_user4, user4_message, hash_name, xmss_user4_sign[2])

    if xmss_user1_signature_verification and xmss_user2_signature_verification and xmss_user3_signature_verification and xmss_user4_signature_verification:
        print("all user signatures verified")
    else:
        print("failed to verify user signature")
        exit(1)

    signings = [xmss_user1_sign[2], xmss_user2_sign[2], xmss_user3_sign[2], xmss_user4_sign[2]]

    aggregated_tree = xmss.aggregate_signatures(signings, hash_name)
    print(aggregated_tree)

    print("#####Backdoor Attack#####")
    depth = 2
    print(f"sig = {signed[2]}]")
    # find = (signed[2])[0]

    i = 0
    # take a known priv key, as it is the input to the XMSS tree
    find = winternitz_signing.privkey[0]
    print(f"looking for {find}")
    start = time.time()
    matching_string = ""
    remaining_bits = ""
    matching_bits = ""
    # if hash_name == "sha256":
    queue = multiprocessing.Queue()
    p = multiprocessing.Process(target=matching.check_match, args=(find, depth, 0, queue, hash_name))
    q = multiprocessing.Process(target=matching.check_match, args=(find, depth, 1, queue, hash_name))
    r = multiprocessing.Process(target=matching.check_match, args=(find, depth, 3, queue, hash_name))
    p.start()
    q.start()
    r.start()
    while True:
        if not r.is_alive():
            p.terminate()
            q.terminate()
        if not p.is_alive():
            r.terminate()
            q.terminate()
            break
        if not q.is_alive():
            r.terminate()
            p.terminate()
            break
    p.join()
    q.join()
    temp = queue.get()

    print(f"found {temp}")
    matching_bits = temp[0]
    remaining_bits = temp[1]
    matching_string = temp[2]

    # attack on the first private key input to the xmss tree
    m1 = matching_string
    m2 = matching_bits

    attack = xmss_attack.attack(winternitz_signing.privkey, m1, m2, hash_name)

    end = time.time()
    normal = xmss.gen_xmss_tree(winternitz_signing.privkey, hash_name, False)
    print(f"new attack keys: {attack}")
    print(f"old normal keys: {normal}")
    # index 0 being modified results in index 2 suffering, which causes a faulty root to be computed
    print(f"source of attack: {attack[2]}")
    print(f"compared to normal: {normal[2]}")
    print(f"new root: {attack[len(attack) - 1]}")
    print(f"old root: {normal[len(normal) - 1]}")

    format_priv_keys = []

    for key in attack:
        if key != "-1" or key != "-2":
            format_priv_keys.append(key)

    forged_winternitz = winternitz.signatures.WOTSPLUS(w=16, hashfunction=hashes[hash_name], digestsize=256, privkey=attack)

    attack_sign, attack_path = xmss.xmss_sign(message, forged_winternitz, key_index, hash_name)
    attack_verify = xmss.xmss_verify(key_index, forged_winternitz, message, hash_name, attack_sign[2])

    print(f"message sig = {signed[2]}")
    print("verify message: " + str(verify))

    print(f"forged message sig = {attack_sign[2]}")
    print(f"forged verify = {attack_verify}")

    print(f"hash used {hash_name}\noriginal string: {m2}\nIn time: {end - start}\nbytes found: {matching_bits[:depth]}")
    # print(f"remaining bytes: {remaining_bits}\nbytes to use: {find[depth:]}")
    # forged_hash = matching_bits[:depth] + find[depth:]
    print(f"forged message: {m1}")
    # swap forged hash with hash in signature
    # (signed[2])[0] = forged_hash
    # forged_verify = xmss.xmss_verify(key_index, winternitz_signing, message, hash_name, signed[2])
    # print(f"forged verify = {forged_verify}")
