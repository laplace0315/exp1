import hashlib
import itertools
import datetime

hash1 = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"


char_options = [['Q', 'q'], ['W', 'w'], ['%', '5'], ['8', '('], ['=', '@'], ['I', 'i'], ['*', '+'], ['n', 'N']]


def sha_encrypt(input_str):
    return hashlib.sha1(input_str.encode('utf-8')).hexdigest()
starttime = datetime.datetime.now()


for combo in itertools.product(*char_options):
    for permutation in itertools.permutations(combo):
        candidate = "".join(permutation)
        if sha_encrypt(candidate) == hash1:
            print("password:", candidate)
            endtime = datetime.datetime.now()
            print("time:", (endtime - starttime).seconds, "s")
            break
