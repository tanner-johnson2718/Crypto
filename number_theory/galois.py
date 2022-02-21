# Take in any integer and convert it to an array of binary values
def galois_hex2binary(v):
    ret = []
    while v > 0:
        ret.insert(0,v & 1)
        v = v >> 1

    return ret

# Take in an array of binary values and return hex value
def galois_binary2hex(a):
    index = 0
    ret = 0

    # copy it so we dont mutate the input
    a_ = [v for v in a]

    while not len(a_) == 0:
        ret += (a_.pop() << index)
        index +=1
    return ret

def galois_equalize_len(a,b):
    if len(a) == len(b):
        return
    if len(a) > len(b):
        while len(b) != len(a):
            b.insert(0,0)
    if len(a) < len(b):
        while len(b) != len(a):
            a.insert(0,0)

# Take in 2 hex value polynimails and xor them i.e. their galois addition
def galois_add(a,b):
    return a ^ b

# Take in 2 hex value polynimials and return their polynomial multiplication
def galois_multi(a,b):
    ret = 0
    a_ = a
    b_ = b

    while a_ and b_:
        if a_ & 1: ret ^= b_
        a_ = a_ >> 1
        b_ = b_ << 1

    return ret

# Return the quotient and remainder of a/b. a and b are hex valued polys.
# assume b < a. Return q,r
def galois_euc_div(a,b):
    if b > a:
        print("galois_euc_div b > a")
        exit()

    q = 0
    a_ = a
    b_ = b

    while 1:
        shift = a_.bit_length() - b_.bit_length()
        if shift < 0: return q,a_
        q ^= (1 << shift)
        a_ = a_ ^ (b_ << shift)
        print(galois_hex2binary(q))
        print(q)



a = 0b11111
b = 0b00101
q,r = galois_euc_div(a,b)
print(galois_hex2binary(q))
print(galois_hex2binary(r))