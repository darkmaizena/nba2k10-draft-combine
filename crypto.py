# NBA 2K10 Draft Combine :1004 auth crypto.
#
# Handshake:
#   - Server sends Blowfish_encrypt(SEED) as the first 16 bytes.
#   - Client Blowfish-decrypts them (key below) -> SEED, seeds a Lagged-Fibonacci
#     keystream. Both sides derive identical RX/TX LFG streams from SEED.
#   - All app traffic after the handshake is XORed with the LFG keystream.
import struct

from Crypto.Cipher import Blowfish

KEY = b"S0m3Things Nev3R ChanGE MyFr1end"  # 32 bytes, recovered from the client
M = 0x19660D
C = 0x3C6EF35F
M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def bf_decrypt(data16):
    return Blowfish.new(KEY, Blowfish.MODE_ECB).decrypt(data16)


def bf_encrypt(data):
    return Blowfish.new(KEY, Blowfish.MODE_ECB).encrypt(data)


def lcg(x):
    return (x * M + C) & M32


class LFG:
    """Lagged Fibonacci keystream (lags 55/24) seeded from the 16-byte handshake seed."""

    def __init__(self, seed16):
        s = list(struct.unpack(">IIII", seed16))
        scr = [0] * 32
        x = s[0]
        for k in range(32):
            x = lcg(x)
            scr[k] = x
        u5 = lcg(x)
        u2 = u5
        pool = [0] * 55
        u1 = 0
        for k in range(55):
            i1 = ((u2 >> 25) & 0x7C) >> 2
            u7 = scr[i1]
            iv8 = lcg(u5)
            i2 = ((u7 >> 25) & 0x7C) >> 2
            scr[i1] = iv8
            u1 = scr[i2]
            u2 = u1
            u5 = lcg(iv8)
            scr[i2] = u5
            pool[k] = (((u7 ^ s[1]) & M32) << 32) | ((u1 ^ s[2]) & M32)
        pool[scr[((u1 >> 25) & 0x7C) >> 2] % 55] |= 1
        self.pool = pool
        self.I = 0x36
        self.J = 0x17
        for _ in range((s[3] % 0xFF) + 0xFF):
            self.next()

    def next(self):
        a = self.pool[self.J]
        b = self.pool[self.I]
        self.J -= 1
        ssum = (b + a) & M64
        self.pool[self.I] = ssum
        if self.J < 0:
            self.J = 0x36
        self.I -= 1
        if self.I < 0:
            self.I = 0x36
        return (ssum + ((ssum & M32) // 0xFF) + 1) & 0xFF

    def ks(self, n):
        return bytes(self.next() for _ in range(n))


def seed_from_greeting(greet16):
    return bf_decrypt(greet16[:16])


def decrypt_stream(greet16, ct):
    lfg = LFG(seed_from_greeting(greet16))
    ks = lfg.ks(len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))
