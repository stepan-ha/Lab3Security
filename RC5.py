import operator
from Randomizer import Randomizer

rnd = Randomizer()

class RC5:

    def left_shift(self, x, l_bits, max_bits):
        shifted_left = (x << l_bits % max_bits) & (2 ** max_bits - 1)
        shifted_right = ((x & (2 ** max_bits - 1)) >> (max_bits - (l_bits % max_bits)))
        result = shifted_left | shifted_right
        return result

    def right_shift(self, x, r_bits, max_bits):
        shifted_right_l = ((x & (2 ** max_bits - 1)) >> r_bits % max_bits)
        shifted_right_r = (x << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))
        result = shifted_right_l | shifted_right_r
        return result

    def de_padding(self, block):
        last_byte = block[-1]
        unpadded_block = block[:-last_byte]
        return unpadded_block

    def padding(self, w, block):
        block_size = w // 4
        padding_size = block_size - len(block) if len(block) != block_size else block_size
        padding_bytes = padding_size.to_bytes(1, byteorder='little')
        padded_block = block.ljust(len(block) + padding_size, padding_bytes)
        return padded_block

    def IV(self, w):
        random_values = rnd.Generate(w // 4)
        mod_values = map(lambda x: x % 128, random_values)
        iv = bytearray(mod_values)
        return iv

    def decrypt_block(self, w, block, subkeys, rounds):
        byte_length = w // 4
        modulus = 2 ** w

        A_part = int.from_bytes(block[:byte_length // 2], byteorder='little')
        B_part = int.from_bytes(block[byte_length // 2:], byteorder='little')

        for round in range(rounds, 0, -1):
            B_temp = self.right_shift(B_part - subkeys[2 * round + 1], A_part, w) ^ A_part
            A_part = self.right_shift((A_part - subkeys[2 * round]), B_temp, w) ^ B_temp
            B_part = B_temp

        B_part = (B_part - subkeys[1]) % modulus
        A_part = (A_part - subkeys[0]) % modulus

        result_bytes = A_part.to_bytes(byte_length // 2, byteorder='little') + B_part.to_bytes(byte_length // 2, byteorder='little')

        return result_bytes

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

    def encrypt_file(self, word_size, encryption_key, num_rounds, input_data, output_stream):
        block_size_bytes = word_size // 4

        secret_keys = self.rc5_subkeys(encryption_key, word_size, num_rounds)

        initialization_vector = self.IV(word_size)
        encrypted_iv = self.encrypt_block(word_size, initialization_vector, secret_keys, num_rounds)
        output_stream.write(encrypted_iv)

        data_block = input_data.read(block_size_bytes)
        current_iterator = initialization_vector

        while data_block:
            next_block = input_data.read(block_size_bytes)
            if not next_block:
                data_block = self.padding(word_size, data_block)

            data_block = bytes(map(operator.xor, data_block, current_iterator))

            encrypted_data_chunk = self.encrypt_block(word_size, data_block, secret_keys, num_rounds)

            current_iterator = encrypted_data_chunk
            data_block = next_block

            output_stream.write(encrypted_data_chunk)

    def rc5_subkeys(self, word_size, key, num_rounds, encrypted_data, output_stream):
        word_bytes = word_size // 4
        encryption_keys = self.rc5_subkeys(key, word_size, num_rounds)
        iv_decryption = self.decrypt_block_data(word_size, encrypted_data.read(word_bytes), encryption_keys, num_rounds)
        self.process_data_blocks(word_size, encryption_keys, iv_decryption, encrypted_data, output_stream, num_rounds)

    def process_data_blocks(self, word_size, encryption_keys, iv_decryption, encrypted_data, output_stream, num_rounds):
        word_bytes = word_size // 4
        data_block = encrypted_data.read(word_bytes)

        while data_block:
            next_data_block = encrypted_data.read(word_bytes)
            decrypted_chunk = self.decrypt_block_data(word_size, data_block, encryption_keys, num_rounds)
            decrypted_data = bytes(map(operator.xor, decrypted_chunk, iv_decryption))
            iv_decryption = data_block
            data_block = next_data_block

            if not data_block:
                decrypted_data = self.de_padding(decrypted_data)

            output_stream.write(decrypted_data)

    def decrypt_block_data(self, word_size, block, subkeys, num_rounds):
        word_bytes = word_size // 4
        mod = 2 ** word_size

        A = int.from_bytes(block[:word_bytes // 2], byteorder='little')
        B = int.from_bytes(block[word_bytes // 2:], byteorder='little')

        for i in range(num_rounds, 0, -1):
            B = self.right_shift(B - subkeys[2 * i + 1], A, word_size) ^ A
            A = self.right_shift((A - subkeys[2 * i]), B, word_size) ^ B

        B = (B - subkeys[1]) % mod
        A = (A - subkeys[0]) % mod

        return A.to_bytes(word_bytes // 2, byteorder='little') + B.to_bytes(word_bytes // 2, byteorder='little')

    def rc5_subkeys(self, key, w, rounds):
        init_const = {
            8: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15),
            16: (0xB7E1, 0x9E37),
            32: (0xB7E15163, 0x9E3779B9),
            64: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)
        }

        t = 2 * (rounds + 1)
        key = self.align_key(w, key)
        L = self.split_key(key, w)

        P, Q = init_const[w]
        S = self.generate_initial_S(P, Q, w, t)
        S = self.calculate_subkeys(S, L, w, t, P, Q)

        return S

    def align_key(self, w, key):
        align = w // 8
        while len(key) % align:
            key += b'\x00'
        return key

    def split_key(self, key, w):
        align = w // 8
        return [int.from_bytes(key[i:i + align], byteorder='little') for i in range(0, len(key), align)]

    def generate_initial_S(self, P, Q, w, t):
        S = [P]
        for i in range(1, t):
            S.append((S[i - 1] + Q) % (2 ** w))
        return S

    def calculate_subkeys(self, S, L, w, t, P, Q):
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

        iterator = self.decrypt_initial_iterator(w, dec, subkeys, rounds)
        self.process_blocks(w, dec, out, subkeys, iterator, rounds)

    def decrypt_initial_iterator(self, w, dec, subkeys, rounds):
        initial_block = dec.read(w // 4)
        return self.decrypt_block(w, initial_block, subkeys, rounds)

    def process_blocks(self, w, dec, out, subkeys, iterator, rounds):
        block = dec.read(w // 4)
        while block:
            next_block = dec.read(w // 4)
            decrypted_chunk = self.decrypt_block(w, block, subkeys, rounds)
            decrypted = self.combine_blocks(decrypted_chunk, iterator)
            iterator = block
            block = next_block
            if not block:
                decrypted = self.de_padding(decrypted)
            self.write_decrypted_block(out, decrypted)

    def combine_blocks(self, decrypted_chunk, iterator):
        return bytes(map(operator.xor, decrypted_chunk, iterator))

    def write_decrypted_block(self, out, decrypted):
        out.write(decrypted)