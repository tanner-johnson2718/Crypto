# iterativly apply y = ax + c % m.

from euclid import *
from prime import *

x = [7]
a = 1103515245
c = 12345
m = 1 << 31

N_gen = 100

# Reccurrence relation
def y(x):
    return (a*x[-1] + c) % m

for i in range(0,N_gen):
    x.append(y(x))

# Find actual period
if 0:
    def find_period(x):
        for starting_index in range(0, m):
            for period in range (1,m+1):
                if x[starting_index] == x[starting_index + period]:
                    return [period, starting_index]

        return [-1,-1]

    period_ret = find_period(x)
    period = period_ret[0]
    period_start = period_ret[1]

    print("a  = " + str(a) + " = " + str(prime_factors(a)))
    print("c  = " + str(c) + " = " + str(prime_factors(c)))
    print("m  = " + str(m) + " = " + str(prime_factors(m)))
    print("x0 = " + str(x[0]) + " = " + str(prime_factors(x[0])))
    print
    print("Period             = " + str(period))
    print("Period Start Index = "  + str(period_start))
    print
    print(x)

# Lets assume we have the series, and want to figure out the reccurence relation
# Just solve a linear system of equations:
# (1) X_1 = A * X_0 + B
# (2) X_2 = A * X_1 + B
#
# (1) - (2) => A = (X_1 - X_2) * inv(X_0 - X_1)
#
# Thus we need to find the inverse of b = X_0 - X_1. And it follows that
# B = X_2 - (A * X_1)

# WHY DOES THIS MATTER??? Need to figure this out
index_start = 7
print("Indicies: " + str([i + index_start for i in range(1,4)]))
t = (x[2+index_start] - x[3+index_start])
b = (x[1+index_start] - x[2+index_start])

if gcd(b, m) != 1:
    print("REEEE")

b_inv = modInverse(b, m) + m
print("t     = " + str(t))
print("b     = " + str(b))
print("b_inv = " + str(b_inv))

A = (t * b_inv) % m
B = (x[2+index_start] - (x[1+index_start]*t*b_inv)) % m

print
print("A = a = " +  str(A) + "  Pass = "  + str(A==a))
print("B = c = " +  str(B) + "  Pass = "  + str(B==c))