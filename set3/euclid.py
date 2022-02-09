# Euclidean Algorithm
def gcd(a,b):
    if b == 0:
        return a
    return gcd(b, a%b)

# Solve a = 1 mod m  <==>  n_1*a + n_2*m = 1
def modInverse(a, b):
    y_ = 0
    n1 = 1
 
    if (b == 1):
        return 0
    while (a > 1):
 
        # q is quotient
        q = a // b
 
        t_ = b
 
        # m is remainder now, process
        # same as Euclid's algo
        b = a % b
        a = t_
        t_ = y_
 
        # Update x and y
        y_ = n1 - q * y_
        n1 = t_

        print("a="+str(a)+" b="+str(b)+" n1="+str(n1))

    return n1

# Mod inverse testing
a = 17
b = 29
print("a = " + str(a) + " b = " + str(b) + " | inv = " + str(modInverse(a,b)))