KEY = b"abcdefghij"

def encrypt(string):
    ords = list(map(ord, string))
    key = list(map(ord, KEY))
    sums = list(map(sum,zip(ords, key)))
    out_list = list(map(lambda x : x % 256, sums))
    out = b""
    for i in out_list:
        out+=chr(i)
    return out

def decrypt(string):
    ords = list(map(ord, string))
    key = list(map(ord, KEY))
    sums = list(map(lambda x: x[0] - x[1] ,zip(ords, key)))
    out_list = list(map(lambda x : x % 256, sums))
    out = b""
    for i in out_list:
        out+=chr(i)
    return out

pt = b"Hello Dude"
print(pt)
print(encrypt(pt))
print(decrypt(encrypt(pt)))