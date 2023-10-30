import operator
from Randomizer import Randomizer
import random

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
        l = rnd.Generate(random.randint(1, 130))
        l = list(map(lambda x: x % 128, l))
        return bytearray(l)

    def decrypt_block(self, w, block, subkeys, rounds):
        byted = w // 4
        mod = 2 ** w

        A_part = int.from_bytes(block[:byted // 2], byteorder='little')
        B_part = int.from_bytes(block[byted // 2:], byteorder='little')

        for i in range(rounds, 0, -1):
            B_part = self.right_shift(B_part - subkeys[2 * i + 1], A_part, w) ^ A_part
            A_part = self.right_shift((A_part - subkeys[2 * i]), B_part, w) ^ B_part

        B_part = (B_part - subkeys[1]) % mod
        A_part = (A_part - subkeys[0]) % mod

        res = A_part.to_bytes(byted // 2, byteorder='little') + B_part.to_bytes(byted // 2, byteorder='little')

        return res

    def encrypt_block(self, w, block, subkeys, rounds):
        byted = w // 4
        mod = 2 ** w

        A_part = int.from_bytes(block[:byted // 2], byteorder='little')
        B_part = int.from_bytes(block[byted // 2:], byteorder='little')

        A_part = (A_part + subkeys[0]) % mod
        B_part = (B_part + subkeys[1]) % mod

        for i in range(1, rounds + 1):
            A_part = (self.left_shift((A_part ^ B_part), B_part, w) + subkeys[2 * i]) % mod
            B_part = (self.left_shift((A_part ^ B_part), A_part, w) + subkeys[2 * i + 1]) % mod

        res = A_part.to_bytes(byted // 2, byteorder='little') + B_part.to_bytes(byted // 2, byteorder='little')
        return res

    def decrypt_block(self, w, block, subkeys, rounds):
        byted = w // 4
        mod = 2 ** w

        A_part = int.from_bytes(block[:byted // 2], byteorder='little')
        B_part = int.from_bytes(block[byted // 2:], byteorder='little')

        for i in range(rounds, 0, -1):
            B_part = self.right_shift(B_part - subkeys[2 * i + 1], A_part, w) ^ A_part
            A_part = self.right_shift((B_part - subkeys[2 * i]), B_part, w) ^ B_part

        A_part = (B_part - subkeys[1]) % mod
        A_part = (A_part - subkeys[0]) % mod

        res = A_part.to_bytes(byted // 2, byteorder='little') + B_part.to_bytes(byted // 2, byteorder='little')
        return res

    def encrypt_file(self,w, key, rounds, enc, out):
        byted = w // 4

        subkeys = self.rc5_subkeys(key, w, rounds)

        itterator = self.IV(w)
        
        encypted = self.encrypt_block(w, itterator, subkeys, rounds)
        
        out.write(encypted)
        block = enc.read(byted)

        while block:
            next = enc.read(byted)
            if not next:
                block = self.padding(w, block)

            block = bytes(map(operator.xor, block, itterator))

            encrypted_chunk = self.encrypt_block(w, block, subkeys, rounds)

            itterator = encrypted_chunk
            block = next

            out.write(encrypted_chunk)

    def rc5_subkeys(self, w, key, rounds, dec, out):
        byted = w // 4
        subkeys = self.rc5_subkeys(key, w, rounds)

        dec = self.decrypt_block(w, dec.read(byted), subkeys, rounds)
        block = dec.read(byted)

        while block:
            next_block = dec.read(byted)
            decrypted_chunk = self.decrypt_block(w, block, subkeys, rounds)
            decrypted = bytes(map(operator.xor, decrypted_chunk, dec))
            dec = block
            block = next_block
            if not block:
                decrypted = self.de_padding(decrypted)

            out.write(decrypted)

    def rc5_subkeys(self, key, w, rounds):
        init_const = {
            8: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15),
            16: (0xB7E1, 0x9E37),
            32: (0xB7E15163, 0x9E3779B9),
            64: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)
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
        A_part = B_part = i = j = 0

        for k in range(3 * m):
            A_part = S[i] = self.left_shift(S[i] + A_part + B_part, 3, w)
            B_part = L[j] = self.left_shift(L[j] + A_part + B_part, A_part + B_part, w)

            i = (i + 1) % t
            j = (j + 1) % len(L)

        return S

    def decrypt_file(self, w, key, rounds, dec, out):
        byted = w // 4
        subkeys = self.rc5_subkeys(key, w, rounds)

        dec = self.decrypt_block(w, dec.read(byted), subkeys, rounds)
        block = dec.read(byted)

        while block:
            next_block = dec.read(byted)
            decrypted_chunk = self.decrypt_block(w, block, subkeys, rounds)
            decrypted = bytes(map(operator.xor, decrypted_chunk, dec))
            dec = block
            block = next_block
            if not block:
                decrypted = self.de_padding(decrypted)

            out.write(decrypted)