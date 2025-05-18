from collections import deque
import unittest

_hex_codes = {f"{i:02X}": i for i in range(256)}

def _hex_to_bytes(s):
    return [_hex_codes[s[i:i+2].upper()] for i in range(0, len(s), 2)]

def hex_to_bits(s):
    return [(b >> i) & 1 for b in _hex_to_bytes(s) for i in range(0, 8)]

def bits_to_bytes(bits):
    bytes_out = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] << j)
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
        for i in range(0, 8):
            data_bits.append((byte >> i) & 1)
    
    cipher = Trivium(key_hex, iv_hex)
    keystream_bits = list(cipher.keystream(len(data_bits)))
    encrypted_bits = [data_bits[i] ^ keystream_bits[i] for i in range(len(data_bits))]
    encrypted_data = bits_to_bytes(encrypted_bits)
    
    return encrypted_data

def DecryptData(encrypted_data, key_hex, iv_hex):
    return EncryptData(encrypted_data, key_hex, iv_hex)


class VerboseTestResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        print(f"Тест `{test}` пройдено успішно.")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print(f"Тест `{test}` не пройдено.")

    def addError(self, test, err):
        super().addError(test, err)
        print(f"Помилка при виконанні тесту `{test}`.")


class TestTriviumLSB(unittest.TestCase):

    def test_hex_to_bits_and_back(self):
        """Перевірка конверсії hex <-> bits"""
        hex_str = "DEADBEEF"
        bits = hex_to_bits(hex_str)
        result = bits_to_bytes(bits).hex().upper()
        expected = hex_str
        print(f"hex_to_bits('{hex_str}') → bits = {bits}")
        print(f"bits_to_bytes(...) → '{result}'")
        self.assertEqual(result, expected)

    def test_invalid_key_length(self):
        """Перевірка на assert при неправильній довжині ключа"""
        with self.assertRaises(AssertionError) as cm:
            Trivium("1234", "288FF65DC42B92F960C7")
        print(f"Caught expected AssertionError: {cm.exception}")

    def test_keystream_length(self):
        """Перевірка, що довжина потоку відповідає запиту"""
        key = "0F62B5085BAE0154A7FA"
        iv = "288FF65DC42B92F960C7"
        trivium = Trivium(key, iv)
        stream = list(trivium.keystream(128))
        print(f"Keystream (128 bits): {stream}")
        self.assertEqual(len(stream), 128)
        self.assertTrue(all(bit in (0, 1) for bit in stream))

    def test_keystream_output(self):
        """Перевірка правильності виводу перших 128 бітів"""
        key_hex = "0F62B5085BAE0154A7FA"
        iv_hex = "288FF65DC42B92F960C7"
        trivium = Trivium(key_hex, iv_hex)
        keystream_bits = list(trivium.keystream(128))
        keystream_bytes = bits_to_bytes(keystream_bits)
        hex_output = keystream_bytes.hex().upper()
        expected_hex = "A4386C6D7624983FEA8DBE7314E5FE1F"
        print(f"Keystream bits: {keystream_bits}")
        print(f"Keystream hex: {hex_output}")
        self.assertEqual(len(keystream_bytes), 16)
        self.assertEqual(hex_output, expected_hex)

    def test_encrypt_decrypt_text(self):
        """Шифрування і розшифрування тексту"""
        key_hex = "0F62B5085BAE0154A7FA"
        iv_hex = "288FF65DC42B92F960C7"
        plaintext = b"Hello, Trivium!"
        ciphertext = EncryptData(plaintext, key_hex, iv_hex)
        decrypted = DecryptData(ciphertext, key_hex, iv_hex)
        print(f"Plaintext: {plaintext}")
        print(f"Ciphertext: {ciphertext.hex().upper()}")
        print(f"Decrypted: {decrypted}")
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_bytes(self):
        """Шифрування і розшифрування байтів"""
        key_hex = "0F62B5085BAE0154A7FA"
        iv_hex = "288FF65DC42B92F960C7"
        original_data = bytes(range(16))
        ciphertext = EncryptData(original_data, key_hex, iv_hex)
        decrypted = DecryptData(ciphertext, key_hex, iv_hex)
        print(f"Original:   {original_data}")
        print(f"Ciphertext: {ciphertext.hex().upper()}")
        print(f"Decrypted:  {decrypted}")
        self.assertEqual(decrypted, original_data)


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestTriviumLSB)
    runner = unittest.TextTestRunner(verbosity=0, resultclass=VerboseTestResult)
    result = runner.run(suite)

    if result.wasSuccessful():
        print("\nУсі тести Trivium LSB пройдено успішно!")
    else:
        print("\nДеякі тести завершились помилкою.")

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestTriviumLSB)
    runner = unittest.TextTestRunner(verbosity=0, resultclass=VerboseTestResult)
    result = runner.run(suite)

    if result.wasSuccessful():
        print("\nУсі тести Trivium LSB пройдено успішно!")
    else:
        print("\nДеякі тести завершились помилкою.")
