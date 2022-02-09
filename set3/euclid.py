# Euclidean Algorithm
def gcd(a,b):
    if b == 0:
        return a
    return gcd(b, a%b)

# Solve a = 1 mod m  <==>  an + mk = 1
def modInverse(a_, m_):
    m0 = m_
    y_ = 0
    x_ = 1
 
    if (m_ == 1):
        return 0
 
    while (a_ > 1):
 
        # q is quotient
        q = a_ // m_
 
        t_ = m_
 
        # m is remainder now, process
        # same as Euclid's algo
        m_ = a_ % m_
        a_ = t_
        t_ = y_
 
        # Update x and y
        y_ = x_ - q * y_
        x_ = t_

    return x_, y_

# Mod inverse testing
print("a = ")