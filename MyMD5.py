import math

A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476


class MyMD5:
    def left_rotate(self, x, shift):
        x %= 2 ** 32
        return ((x << shift) | (x >> (32 - shift))) % 2 ** 32

    def md5(self, strng):
        print(type(strng))
        print(strng)
        strng_len = (8 * len(strng)) % 2 ** 64
        strng.append(0x80)

        while len(strng) % 64 != 56:
            strng.append(0)

        strng += strng_len.to_bytes(8, byteorder='little')

        buffer = [A, B, C, D]

        k = [
            lambda i: i,
            lambda i: (5 * i + 1) % 16,
            lambda i: (3 * i + 5) % 16,
            lambda i: (7 * i) % 16
        ]

        f_g_h_i = [
            lambda b, c, d: (b & c) | (~b & d),
            lambda b, c, d: (d & b) | (~d & c),
            lambda b, c, d: b ^ c ^ d,
            lambda b, c, d: c ^ (b | ~d)
        ]

        t = [math.floor(2 ** 32 * abs(math.sin(i + 1))) for i in range(64)]

        s = 4 * [7, 12, 17, 22] + \
            4 * [5, 9, 14, 20] + \
            4 * [4, 11, 16, 23] + \
            4 * [6, 10, 15, 21]

        for x in range(0, len(strng), 64):

            a, b, c, d = buffer
            chunk = strng[x:x + 64]

            for i in range(64):
                temp = f_g_h_i[i // 16](b, c, d)

                j = k[i // 16](i)

                chunk_sum = int.from_bytes(chunk[4 * j:4 * j + 4], byteorder='little') + a + temp + t[i]

                b_ = (b + self.left_rotate(chunk_sum, s[i])) % 2 ** 32

                a, b, c, d = d, b_, b, c

            for i, val in enumerate([a, b, c, d]):
                buffer[i] += val
                buffer[i] %= 2 ** 32

        join = sum(x << (32 * i) for i, x in enumerate(buffer))
        res = join.to_bytes(16, byteorder='little')
        return res