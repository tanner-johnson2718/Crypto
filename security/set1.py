# soln to https://cryptopals.com/sets/1

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

#for i in range(0, 16):
#    for j in range(0,16):
#        out_str = buff2ascii(xor_buff(str2buff(message), [i,j]*(len(message) / 2)))
#        print ( str(i) + "," + str(j) + ": " +  out_str  )

print("Key = 0x58")
print(buff2ascii(xor_buff(str2buff(message), [5,8]*(len(message) / 2))))