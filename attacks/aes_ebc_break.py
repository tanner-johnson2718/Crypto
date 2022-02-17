print("\nChallange 8)")
lines_ = open("data_c8.txt", "r").read().splitlines()
line_no = 0
for line in lines_:
    i = 0
    bytes = []
    while i < len(line):
        bytes.append(ord(line[i])*16 + ord(line[i+1]))
        i += 2

    # now just do a O(n^2) pairwaise check of all 16 byte blocks
    n_blocks = len(bytes) / 16
    for i in range(0, n_blocks):
        for j in range(i+1, n_blocks):
            if bytes[i*16 : (i+1)*16] == bytes[j*16 : (j+1)*16]:
                print("Found AES = line " + str(line_no))

    line_no += 1
