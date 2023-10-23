import operator
from Randomizer import Randomizer

rnd = Randomizer()

class RC5:

    def left_shift(self, x, l_bits, max_bits):
        l = (x << l_bits % max_bits) & (2 ** max_bits - 1)
        r = ((x & (2 ** max_bits - 1)) >> (max_bits - (l_bits % max_bits)))
        return l | r

    def right_shift(self, x, r_bits, max_bits):
        l = ((x & (2 ** max_bits - 1)) >> r_bits % max_bits)
        r = (x << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))
        return l | r

    def de_padding(self, block):
        return block[:-block[-1]]

    def padding(self, w, block):
        bb = w // 4
        to_add = bb - len(block) if len(block) != bb else bb
        return block.ljust(len(block) + to_add, to_add.to_bytes(1, byteorder='little'))

    def IV(self, w):
        l = rnd.Generate(w // 4)
        l = list(map(lambda x: x % 128, l))
        return bytearray(l)
    def decrypt_block(self, w, block, subkeys, rounds):
        byted = w // 4
        mod = 2 ** w

        A = int.from_bytes(block[:byted // 2], byteorder='little')
        B = int.from_bytes(block[byted // 2:], byteorder='little')

        for i in range(rounds, 0, -1):
            B = self.right_shift(B - subkeys[2 * i + 1], A, w) ^ A
            A = self.right_shift((A - subkeys[2 * i]), B, w) ^ B

        B = (B - subkeys[1]) % mod
        A = (A - subkeys[0]) % mod

        res = A.to_bytes(byted // 2, byteorder='little') + B.to_bytes(byted // 2, byteorder='little')
        return res

    def encrypt_block(self, w, block, subkeys, rounds):
        byted = w // 4
        mod = 2 ** w

        A = int.from_bytes(block[:byted // 2], byteorder='little')
        B = int.from_bytes(block[byted // 2:], byteorder='little')

        A = (A + subkeys[0]) % mod
        B = (B + subkeys[1]) % mod

        for i in range(1, rounds + 1):
            A = (self.left_shift((A ^ B), B, w) + subkeys[2 * i]) % mod
            B = (self.left_shift((A ^ B), A, w) + subkeys[2 * i + 1]) % mod

        res = A.to_bytes(byted // 2, byteorder='little') + B.to_bytes(byted // 2, byteorder='little')
        return res

    def decrypt_block(self, w, block, subkeys, rounds):
        byted = w // 4
        mod = 2 ** w

        A = int.from_bytes(block[:byted // 2], byteorder='little')
        B = int.from_bytes(block[byted // 2:], byteorder='little')

        for i in range(rounds, 0, -1):
            B = self.right_shift(B - subkeys[2 * i + 1], A, w) ^ A
            A = self.right_shift((A - subkeys[2 * i]), B, w) ^ B

        B = (B - subkeys[1]) % mod
        A = (A - subkeys[0]) % mod

        res = A.to_bytes(byted // 2, byteorder='little') + B.to_bytes(byted // 2, byteorder='little')
        return res

    def encrypt_file(self,w, key, rounds, enc, out):
        byted = w // 4

        subkeys = self.rc5_subkeys(key, w, rounds)

        iv = self.IV(w)
        iv_enc = self.encrypt_block(w, iv, subkeys, rounds)
        out.write(iv_enc)
        block = enc.read(byted)

        while block:
            next = enc.read(byted)
            if not next:
                block = self.padding(w, block)

            block = bytes(map(operator.xor, block, iv))

            encrypted_chunk = self.encrypt_block(w, block, subkeys, rounds)

            iv = encrypted_chunk
            block = next

            out.write(encrypted_chunk)
    def rc5_subkeys(self, w, key, rounds, dec, out):
        byted = w // 4
        subkeys = self.rc5_subkeys(key, w, rounds)

        iv_dec = self.decrypt_block(w, dec.read(byted), subkeys, rounds)
        block = dec.read(byted)

        while block:
            next_block = dec.read(byted)
            decrypted_chunk = self.decrypt_block(w, block, subkeys, rounds)
            decrypted = bytes(map(operator.xor, decrypted_chunk, iv_dec))
            iv_dec = block
            block = next_block
            if not block:
                decrypted = self.de_padding(decrypted)

            out.write(decrypted)

    def rc5_subkeys(self, key, w, rounds):
        init_const = {
            8: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15),
        }
        t = 2 * (rounds + 1)

        align = w // 8
        while len(key) % align:
            key += b'\x00'
        L = [int.from_bytes(key[i:i + align], byteorder='little') for i in range(0, len(key), align)]

        P, Q = init_const[w]
        S = [P]
        for i in range(1, t):
            S.append((S[i - 1] + Q) % 2 ** w)

        m = max(len(L), t)
        A = B = i = j = 0

        for k in range(3 * m):
            A = S[i] = self.left_shift(S[i] + A + B, 3, w)
            B = L[j] = self.left_shift(L[j] + A + B, A + B, w)

            i = (i + 1) % t
            j = (j + 1) % len(L)

        return S

    def decrypt_file(self, w, key, rounds, dec, out):
        byted = w // 4
        subkeys = self.rc5_subkeys(key, w, rounds)

        iv_dec = self.decrypt_block(w, dec.read(byted), subkeys, rounds)
        block = dec.read(byted)

        while block:
            next_block = dec.read(byted)
            decrypted_chunk = self.decrypt_block(w, block, subkeys, rounds)
            decrypted = bytes(map(operator.xor, decrypted_chunk, iv_dec))
            iv_dec = block
            block = next_block
            if not block:
                decrypted = self.de_padding(decrypted)

            out.write(decrypted)
