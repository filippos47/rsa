from utils import *
import config

# This class contains all the necessary functions to perform textbook
# RSA encryption and decryption in 4 different modes:
# 1) ECB, 2) OFB, 3) CTR, 4) CBC
class Encrypter:
    # This function initializes our encrypter object, reading the block size
    # and creating public and private keys.
    def __init__(self, ):
        self.public_key, self.private_key = self.__keygen()
        self.block_size = config.BLOCK_SIZE

    # Creates the public and private keys. The process followed
    # is the following:
    # 1) Choose two random primes, p and q.
    # 2) Compute n = p * q.
    # 3) Compute totient = φ(p) * φ(q) = (p - 1) * (q - 1)
    # 4) Choose an integer e, so that 1 < e < totient and e coprime with totient.
    # 5) Determine d, the modular multiplicative inverse of e modulo totient.
    def __keygen(self):
        rnd1 = produceRandom()
        rnd2 = produceRandom()
        with open(config.FILENAME, 'r') as fp:
            lines = fp.read().splitlines()
        
        p = int(lines[rnd1])
        q = int(lines[rnd2])
        n = p * q
        totient = (p - 1) * (q - 1)
        e = chooseE(totient)
        gcd, x, y = xgcd(e, totient)
        d = x if x >= 0 else x + totient

        return (e, n), (d, n)

    # Encodes a block --> (block ^ e) % n
    def __rsaEncoder(self, block):
        e, n = self.public_key
        return pow(block, e, n)

    # Decodes a block --> (block ^ d) % n
    def __rsaDecoder(self, block):
        d, n = self.private_key
        return pow(block, d, n)

    # Performs RSA encryption using Electronic Code Book cipher mode. Every
    # message block is directly encrypted to ciphertext. The most insecure way.
    def __encryptECB(self, message):
        block_size = self.block_size
        message = pad(message)
        encrypted_blocks = []

        for i in range(0, len(message), block_size):
            block = stringToOrds(message[i : i + block_size])
            encrypted_blocks.append(str(self.__rsaEncoder(block)))

        return " ".join(encrypted_blocks)

    # Performs RSA decryption using Electronic Code Book cipher mode. Every
    # cipher block is directly decrypted to plaintext.
    def __decryptECB(self, cipher):
        block_size = self.block_size
        encrypted_blocks = cipher.split(' ')
        message = ""

        for block in encrypted_blocks:
            message_segment = ""
            block = self.__rsaDecoder(int(block))

            message += reversedOrdsToString(block)

        return unpad(message)
    
    # Performs RSA encryption using Output FeedBack cipher mode. Instead of the
    # plaintext, the encrypted output is sent for encryption, and is then xored
    # with the plaintext block to produce the cipher block. For the first
    # encryption, a random initial vector IV is used.
    def __encryptOFB(self, message):
        block_size = self.block_size
        message = pad(message)
        encrypted_blocks = []
        self.IV = generateIV()
        prev = stringToOrds(self.IV)
        
        for i in range(0, len(message), block_size):
            block = self.__rsaEncoder(prev)
            prev = block
            block = xor(block, stringToOrds(message[i : i + block_size]))
            encrypted_blocks.append(str(block))

        return " ".join(encrypted_blocks)

    # Performs RSA decryption using Output FeedBack cipher mode. The process is
    # identical to the encryption, except that for the xor we use the cipher block
    # instead of the plaintext block.
    def __decryptOFB(self, cipher):
        block_size = self.block_size
        encrypted_blocks = cipher.split(' ')
        message = ""
        prev = stringToOrds(self.IV)

        for block in encrypted_blocks:
            message_segment = self.__rsaEncoder(prev)
            prev = message_segment
            message_segment = xor(message_segment, int(block))
            message += str(reversedOrdsToString(message_segment))
        return unpad(message)

    # Performs RSA encryption using Counter cipher mode. Every time, a counter 
    # initiated value is encrypted and then xored with the plaintext block to
    # produce the cipler block. The counter is at first initialized to a random
    # value. For every step, the counter is increased by one bit.
    def __encryptCTR(self, message):
        block_size = self.block_size
        message = pad(message)
        encrypted_blocks = []
        self.IV = generateIV()
        nonce = stringToOrds(self.IV)

        for i in range(0, len(message), block_size):
            block = xor(self.__rsaEncoder(nonce), \
                stringToOrds(message[i : i + block_size]))
            nonce = increaseCounter(nonce)
            encrypted_blocks.append(str(block))

        return " ".join(encrypted_blocks)


    # Performs RSA decryption using Counter cipher mode. The process is identical 
    # to the encryption, except that for the xor we use the cipher block instead
    # of the plaintext block.
    def __decryptCTR(self, cipher):
        block_size = self.block_size
        encrypted_blocks = cipher.split(' ')
        message = ""
        nonce = stringToOrds(self.IV)

        for block in encrypted_blocks:
            message_segment = xor(self.__rsaEncoder(nonce), int(block))
            nonce = increaseCounter(nonce)
            message += str(reversedOrdsToString(message_segment))
        return unpad(message)

    # Performs RSA encryption using Cipher Block Chaining cipher mode.
    # The previous encrypted output is xored with the plaintext block and then
    # encrypted. For the first encryption, a random initial vector IV is used.
    def __encryptCBC(self, message):
        block_size = self.block_size
        message = pad(message)
        encrypted_blocks = []
        self.IV = generateIV()
        prev = stringToOrds(self.IV)

        for i in range(0, len(message), block_size):
            block = xor(prev, stringToOrds(message[i : i + block_size]))
            block = self.__rsaEncoder(block)
            prev = block
            encrypted_blocks.append(str(block))

        return " ".join(encrypted_blocks)

    # Performs RSA decryption using Cipher Block Chaining cipher mode.
    # The cipher block is decrypted and then xored with the previous cipher 
    # block. For the first decryption, the IV is used(initialized at the
    # encryption).
    def __decryptCBC(self, cipher):
        block_size = self.block_size
        encrypted_blocks = cipher.split(' ')
        message = ""
        prev = stringToOrds(self.IV)

        for block in encrypted_blocks:
            message_segment = xor(self.__rsaDecoder(int(block)), prev)
            prev = int(block)
            message += str(reversedOrdsToString(message_segment))
        return unpad(message)

    def encrypt(self, message, mode):
        if mode == 'ECB':
            return self.__encryptECB(message)
        elif mode == 'OFB':
            return self.__encryptOFB(message)
        elif mode == 'CTR':
            return self.__encryptCTR(message)
        elif mode == 'CBC':
            return self.__encryptCBC(message)

    def decrypt(self, cipher, mode):
        if mode == 'ECB':
            return self.__decryptECB(cipher)
        elif mode == 'OFB':
            return self.__decryptOFB(cipher)
        elif mode == 'CTR':
            return self.__decryptCTR(cipher)
        elif mode == 'CBC':
            return self.__decryptCBC(cipher)
