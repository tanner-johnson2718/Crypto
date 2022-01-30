# soln to https://cryptopals.com/sets/1

def byte2hexdigit(buff):
    ret = []
    for b in buff:
        ret.append(b / 16)
        ret.append(b % 16)

    return ret

def ascii2buff(str):
    b = []
    for c in str:
        b.append(ord(c))
    return b

def buff2ascii(buff):
    if not ((len(buff) % 2) == 0):
        buff.insert(0,0)

    ret = b""
    for i in range(0, len(buff) / 2):
        v1 = buff.pop(0)
        v2 = buff.pop(0)
        ret += chr(( v1* 16) + v2)

    return ret

def buff2hex(buff):
    ret = b""
    for i in range(0,len(buff)):
        if 0 <= buff[i] and buff[i] <= 9:
            ret += chr(buff[i] + ord("0"))
            continue

        if 10 <= buff[i] and buff[i] <= 15:
            ret += chr(buff[i] - 10 + ord('a'))
            continue

        print("EEEEERRRRRRRRRRRRROOOOOOOORRRRRRRR")

    return ret

def str2buff(hex_str):
    hex_digits = []
    for c in hex_str:
        hex_digits.append(int(c, 16))

    return hex_digits

def base64_2hex(str):
    b = []
    for c in str:
        if ord(c) in range(ord('A'), ord('Z') + 1):
            b.append(ord(c) - ord('A'))
            continue
        if ord(c) in range(ord('a'), ord('z') + 1):
            b.append(ord(c) - ord('a') + 26)
            continue
        if ord(c) in range(ord('0'), ord('9') + 1):
            b.append(ord(c) - ord('0') + 52)
            continue
        if ord(c) == ord("+"):
            b.append(62)
            continue
        b.append(ord("/"))

    if not ((len(b) % 2) == 0):
        b.insert(0,0)

    hex_buff = []
    for i in range(0,len(b)/2):
        d1 = b.pop(0)
        d2 = b.pop(0)

        v = (d1*64) + d2

        h3 = v % 16
        v = v / 16
        h2 = v % 16
        v = v / 16
        h1 = v % 16

        hex_buff.append(h1)
        hex_buff.append(h2)
        hex_buff.append(h3)

    return buff2hex(hex_buff)



def hex2base64(hex_str):
    hex_digits = str2buff(hex_str)

    # 3 hex digits = 2 base64 digits so pad
    pad = len(hex_digits) % 3
    pad = (3 - pad) % 3
    for i in range(0, pad):
        hex_digits.insert(0,0)

    if not len(hex_digits) % 3 == 0:
        print("ERRROOOOORRRRRR!!!! REEE")

    # now we can group together 3 hex digits to form a 2 digit base 64 val
    base64_digits = []
    for i in range(0, len(hex_digits) / 3):
        temp = []
        temp.append(hex_digits.pop(0))
        temp.append(hex_digits.pop(0))
        temp.append(hex_digits.pop(0))

        val = 0
        val += temp[2]*1
        val += temp[1]*16
        val += temp[0]*256

        base64_digits.append(val / 64)
        base64_digits.append(val % 64)

    # Now just extract the base64 encoding
    out_str = b""
    for i in range(0, len(base64_digits)):
        if base64_digits[i] >= 0 and base64_digits[i] <= 25:
            out_str += chr(base64_digits[i] + ord("A"))
            continue

        if base64_digits[i] >= 26 and base64_digits[i] <= 51:
            out_str += chr(base64_digits[i] - 26 + ord("a"))
            continue

        if base64_digits[i] >= 52 and base64_digits[i] <= 61:
            out_str += chr(base64_digits[i] - 52 + ord("0"))
            continue

        if base64_digits[i] == 62:
            out_str += "+"
            continue

        if base64_digits[i] == 63:
            out_str += "/"
            continue

        print("EEERRRRPPPPRRPRPRP REEEE")

    return out_str

def xor_buff(b1, b2):
    if not len(b1) == len(b2):
        print("ERRRORROORRORRR")
        return []

    ret = []
    for i in range(0, len(b1)):
        ret.append(b1[i] ^ b2[i])

    return ret

def not_alpha(byte):
    byte = ord(byte)
    if byte == ord(' '):
        return 0
    if byte >= ord('a') and byte <= ord('z'):
        return 0
    if byte >= ord('A') and byte <= ord('Z'):
        return 0
    if byte == ord('\''):
        return 0
    if byte == ord('.'):
        return 0
    if byte >= ord('0') and byte <= ord('9'):
        return 0
    if byte == ord(","):
        return 0
    if byte == ord("-"):
        return 0
    if byte == ord("?"):
        return 0
    if byte == ord("\n"):
        return 0
    return 1

def score(ascii_string):
    return sum(map(not_alpha, ascii_string))

def gen_all_byte_keys(size):
    s = 1 << (8*(size))
    ret = []
    for i in range(0,s):
        val = i
        ret.append([])
        for j in range(0,2*size):
            ret[i].append(val % 16)
            val = val / 16

    return ret

def key_buff2val(buff):
    val = 0
    b = 1
    for v in buff:
        val += v*b
        b *= 16
    return val

def find_code(encoded, thresh):
    ret = []
    for i in range(0, 16):
        for j in range(0,16):
            b1 = str2buff(encoded)
            b2 = [i,j]*(len(encoded) / 2)

            out_str = buff2ascii(xor_buff(b1, b2))
            s = score(out_str)
            if s < thresh:
                ret.append( [(i*16 + j) , out_str])
    return ret

def xor_encypt(message, key):
    
    mbuf = ascii2buff(message)
    kbuf_ = ascii2buff(key)
    
    kbuf = []
    while len(kbuf) < len(mbuf):
        kbuf += kbuf_

    while len(kbuf) != len(mbuf):
        kbuf.pop()

    ebuff = xor_buff(mbuf, kbuf)

    return buff2hex(byte2hexdigit(ebuff))

def hamming(s1, s2):
    if len(s1) != len(s2):
        print("Error s1=" +s1 + " s2=" + s2 )
        return -1
    
    b1 = ascii2buff(s1)
    b2 = ascii2buff(s2)

    x = xor_buff(b1, b2)

    c = 0
    for b in x:
        for i in range(0,8):
            c += ((b >> i) & 1)

    return c

def xor_decrypt(msg_hex_str, key_ascii):
    key_ = ascii2buff(key_ascii)
    msg = str2buff(msg_hex_str)

    repeat = (len(msg) / len(key_)) + 1
    key = (key_ * repeat)[0:len(msg)]

    return buff2ascii(xor_buff(msg, key))

case1  = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
soln = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
print("Challange 1)")
print(hex2base64(case1))
print("Pass = " + str(soln == hex2base64(case1)))
print

print("Challange 2)")
in_1 = b"1c0111001f010100061a024b53535009181c"
in_2 = b"686974207468652062756c6c277320657965"
soln = b"746865206b696420646f6e277420706c6179"
ans = buff2hex(xor_buff(str2buff(in_1), str2buff(in_2)))
print(ans)
print("Pass = " + str(soln == ans))
print 

print("Challange 3)")
message = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

possible = find_code(message, 2)
for p in possible:
    print("Key = " + hex(p[0]) + " Code = " + p[1])
print

print("Challange 4) ")
lines = open("data_s1_c4.txt", "r").read().splitlines()
for line in lines:
    possible = find_code(line, 2)
    for p in possible:
        print("Key = " + hex(p[0]) + " Code = " + p[1])
print

print("Challange 5) ")
message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = b"ICE"
soln = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
mine = xor_encypt(message, key)
print(mine)
print("Pass = " + str(mine == soln))
print

print("Challange 6) ")
s_64 = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
s_16  = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
print("Pass = " + str(base64_2hex(s_64) == s_16))
print("Pass = " + str(hex2base64(base64_2hex(s_64)) == s_64))
s1 = "this is a test"
s2 = "wokka wokka!!!"
print("Pass = " + str(hamming(s1, s2) == 37))

lines_ = open("data_s1_c6.txt", "r").read().splitlines()
lines = []
for line in lines_:
    lines.append(base64_2hex(line))

mega_line = b""
for line in lines:
    mega_line += line
    
normed_hamming = [1e10, 1e10]
for keysize in range(2,30):
    # grab keysize byte chunks from string, remember 2 chars = 1 bytes
    s = 0
    s1_index_lo = 0
    index_mid   = 2*keysize
    s2_index_hi = 4*keysize
    counter = 0

    while s2_index_hi < len(mega_line) and index_mid < len(mega_line) and s1_index_lo < len(mega_line):
        s1 = mega_line[s1_index_lo:index_mid]
        s2 = mega_line[index_mid:s2_index_hi]
        
        s += hamming(s1, s2)
        counter += 1

        s1_index_lo += 4*keysize
        index_mid   += 4*keysize
        s2_index_hi += 4*keysize

    avg = float(s) / float(counter)
    normed_hamming.append(float(avg) / float(keysize))

possible_keysizes = [normed_hamming.index(min(normed_hamming))]
print(possible_keysizes)

for key_size in possible_keysizes:
    key = b""
    msgs = []
    l = 0
    strings = [""] * key_size
    index = 0
    for line in lines:
        counter = 0
        for c in line:
            strings[index % key_size] += c
            if counter % 2 == 1:
                index += 1
            counter += 1
    i = 0
    for s in strings:
        ans = find_code(s, 5)
        key += chr(ans[0][0])
        msgs.append(ans[0][1])
        l += len(ans[0][1]) 

    msg = b""
    for j in range(0, len(msgs[0])):
        for i in range(0,len(msgs)):
            if j < len(msgs[i]):
                msg += msgs[i][j]

    print("Key = " + key)
    print("Msg = " + msg)