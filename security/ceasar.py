KEY = 25

def encyrpt(byte, key):
    return ((byte + key) % 256)

def decrypt(byte, key):
    return ((byte - key) % 256)

def send_str(data, key):
    out = b""
    for b in data:
        out += chr(encyrpt(ord(b), key))
    return out

def recv_str(data, key):
    out = b""
    for b in data:
        out += chr(decrypt(ord(b), key))
    return out

str_in = b"Hello Brother"
print("Sending   = " + str_in)
print("Encrypted = " + send_str(str_in, KEY))
print("Decrypted = " + recv_str(send_str(str_in, KEY), KEY))

# Now lets brute force the key. If we know the text being sent is plain ascii
# with no alphabet characters we can just brute force it. Suppose we intercepted
# the enctpted text.

def not_alpha(byte):
    byte = ord(byte)
    if byte == ord(' '):
        return 0
    if byte >= ord('a') and byte <= ord('z'):
        return 0
    if byte >= ord('A') and byte <= ord('Z'):
        return 0
    return 1

artifact = send_str(str_in, KEY)
for i in range(0,256):
    test = recv_str(artifact, i)
    if not sum(list(map(not_alpha, test))):
        print("Key = " + str(i) + " Str = " + test)