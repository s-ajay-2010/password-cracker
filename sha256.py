

def pad_msg(msg: bytes):
    msg_len = len(msg) * 8
    msg += b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += msg_len.to_bytes(8, 'big')
    return msg


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def shr(x, n):
    return x >> n

def mod32(*args):
    return sum(args) & 0xffffffff

def sum0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sum1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def ch(x, y, z):
    return (x & y) ^ ((~x & 0xffffffff) & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def sha256(msg: bytes) -> str:
    message = pad_msg(msg)

    for block_start in range(0, len(message), 64):
        block = message[block_start : block_start + 64]

        w = [int.from_bytes(block[i*4 : i*4+4], 'big') for i in range(16)]
        for i in range(16, 64):
            w.append(mod32(sum1(w[i-2]), w[i-7], sum0(w[i-15]), w[i-16]))

        a, b, c, d, e, f, g, h = H

        for i in range(64):
            T1 = mod32(h, sigma0(e), ch(e, f, g), K[i], w[i])
            T2 = mod32(sigma1(a), maj(a, b, c))
            h = g
            g = f
            f = e   
            e = mod32(d, T1)
            d = c
            c = b
            b = a
            a = mod32(T1, T2)


        H[0] = mod32(H[0], a)
        H[1] = mod32(H[1], b)
        H[2] = mod32(H[2], c)
        H[3] = mod32(H[3], d)
        H[4] = mod32(H[4], e)
        H[5] = mod32(H[5], f)
        H[6] = mod32(H[6], g)
        H[7] = mod32(H[7], h)

    return ''.join(f"{x:08x}" for x in H)



m = input("enter: ")

print(sha256(b"{m}"))