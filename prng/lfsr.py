state = (1 << 127) | 1
for i in range(0,100000):
    newbit = (state ^ (state >>1) ^ (state >> 2) ^ (state >> 7)) & 1
    state = (newbit << 127) | (state >> 1)
    print(state & 1, end="")
