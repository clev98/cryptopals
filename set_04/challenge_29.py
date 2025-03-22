from os import urandom
import struct


def circular_left_shift(num: int, shift: int, bit_size: int = 32):
    shifted = (num << shift) & (2**bit_size - 1)
    reminder = num >> (bit_size - shift)
    return shifted | reminder


class CustomSha1:
    def __init__(self, key_size=16):
        assert int == type(key_size)

        self.key = urandom(key_size)

    def SHA1(
            self,
            msg: bytes,
            h0=0x67452301,
            h1=0xEFCDAB89,
            h2=0x98BADCFE,
            h3=0x10325476,
            h4=0xC3D2E1F0,
            force_len: int = None) -> bytes:

        # message length in bits
        if force_len is None:
            ml = len(msg) * 8
        else:
            ml = force_len * 8

        # Pre-processing:
        # append the bit '1' to the message
        msg += bytes([0x80])

        # append bits '0' to match len of 448 (mod 512) bits
        pad_len = (448 // 8) - (len(msg) % (512 // 8))
        pad_len = (512 // 8) + pad_len if pad_len < 0 else pad_len
        msg += bytes(pad_len)

        # append ml, the original message length in bits,
        # as a 64-bit big-endian integer.
        msg += ml.to_bytes(64 // 8, byteorder='big')

        # the total length is a multiple of 512 bits (64 bytes)
        assert (len(msg) % 64 == 0)

        # break message into 512-bit chunks
        for chunk_idx in range(0, len(msg), 64):
            chunk = msg[chunk_idx:chunk_idx + 64]

            # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
            w = [int.from_bytes(chunk[i:i + 4], 'big')
                 for i in range(0, len(chunk), 4)]

            # extend the sixteen 32-bit words into eighty 32-bit words
            for i in range(16, 80):
                tmp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
                tmp_shifted = circular_left_shift(num=tmp, shift=1)
                w.append(tmp_shifted)

            assert (len(w) == 80)

            # Initialize hash value for this chunk
            a, b, c, d, e = h0, h1, h2, h3, h4

            # Main loop
            for i in range(80):
                if 0 <= i <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = (circular_left_shift(num=a, shift=5) + f + e + k + w[i])
                temp &= 0xFFFFFFFF
                e = d
                d = c
                c = circular_left_shift(num=b, shift=30)
                b = a
                a = temp

            # Add this chunk's hash to result so far
            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF

        # Produce the final hash value (big-endian) as a 160-bit number
        hh = (struct.pack('>I', i) for i in [h0, h1, h2, h3, h4])
        hh = b''.join(hh)
        return hh

    def Secret_Prefix_Hash(self, message: bytes) -> bytes:
        return self.SHA1(self.key + message)

    def Calculate_Padding(self, message_length: int) -> bytes:
        message_length_bits = message_length * 8

        # Add 1000 0000 as the start of the padding
        padding = b"\x80"

        # Get total allowed length
        zero_pad_length = (512 - 64) // 8
        # Remove existing length in bytes
        zero_pad_length -= (len(padding) + message_length) % (512 // 8)

        if 0 > zero_pad_length:
            zero_pad_length += 512 // 8

        padding += bytes(zero_pad_length)
        padding += message_length_bits.to_bytes(64 // 8, byteorder='big')

        assert 0 == (message_length + len(padding)) % 64

        return padding


def attack(
        c_sha: CustomSha1,
        original_hash: bytes,
        old_message: bytes,
        new_message: bytes,
        key_length: int):
    h0, h1, h2, h3, h4 = [
        struct.unpack('>I', original_hash[i:i + 4])[0]
        for i in range(0, 20, 4)]

    padding = c_sha.Calculate_Padding(key_length + len(old_message))
    final_message = old_message + padding + new_message
    new_length = len(final_message) + key_length

    return final_message, c_sha.SHA1(
        new_message, h0=h0, h1=h1, h2=h2, h3=h3, h4=h4, force_len=new_length)


if __name__ == "__main__":
    key_length = 16
    c_sha = CustomSha1(key_length)
    plaintext = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20"
    plaintext += b"a%20pound%20of%20bacon"
    addition = b";admin=true"

    original_hash = c_sha.Secret_Prefix_Hash(plaintext)
    final_message, new_hash = attack(
        c_sha, original_hash, plaintext, addition, key_length)
    expected_hash = c_sha.Secret_Prefix_Hash(final_message)

    print(new_hash)
    print(expected_hash)
