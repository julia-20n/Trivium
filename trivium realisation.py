from collections import deque

_hex_codes = {f"{i:02X}": i for i in range(256)}

def _hex_to_bytes(s):
    return [_hex_codes[s[i:i+2].upper()] for i in range(0, len(s), 2)]

def hex_to_bits(s):
    return [(b >> i) & 1 for b in _hex_to_bytes(s) for i in range(7, -1, -1)]

def bits_to_bytes(bits):
    bytes_out = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] << (7 - j))
        bytes_out.append(byte)
    return bytes(bytes_out)

class Trivium:
    def __init__(self, key_hex, iv_hex):
        self.InitCipher(key_hex, iv_hex)

    def InitCipher(self, key_hex, iv_hex):
        assert len(key_hex) == 20
        assert len(iv_hex) == 20

        self.key = key_hex
        self.iv = iv_hex

        key_bits = hex_to_bits(key_hex)[::-1]
        iv_bits = hex_to_bits(iv_hex)[::-1]

        state = [0] * 288
        state[0:80] = key_bits
        state[93:173] = iv_bits
        state[285:288] = [1, 1, 1]

        self.state = deque(state)

        for _ in range(4 * 288):
            self.Next()

    def Stream(self):
        s = self.state
        t1 = s[65] ^ s[92]
        t2 = s[161] ^ s[176]
        t3 = s[242] ^ s[287]
        return t1 ^ t2 ^ t3

    def Next(self):
        s = self.state
        t1 = s[65] ^ s[92]
        t2 = s[161] ^ s[176]
        t3 = s[242] ^ s[287]

        s1 = t1 ^ (s[90] & s[91]) ^ s[170]
        s2 = t2 ^ (s[174] & s[175]) ^ s[263]
        s3 = t3 ^ (s[285] & s[286]) ^ s[68]

        s.rotate(1)
        s[0] = s3
        s[93] = s1
        s[177] = s2

    def keystream(self, bits_count):
        for _ in range(bits_count):
            bit = self.Stream()
            self.Next()
            yield bit

def EncryptData(data, key_hex, iv_hex):
    data_bits = []
    for byte in data:
        for i in range(7, -1, -1):
            data_bits.append((byte >> i) & 1)
    
    cipher = Trivium(key_hex, iv_hex)
    keystream_bits = list(cipher.keystream(len(data_bits)))
    encrypted_bits = [data_bits[i] ^ keystream_bits[i] for i in range(len(data_bits))]
    encrypted_data = bits_to_bytes(encrypted_bits)
    
    return encrypted_data

def DecryptData(encrypted_data, key_hex, iv_hex):
    return EncryptData(encrypted_data, key_hex, iv_hex)
