import secrets
import string
import config

# Calculates the greatest common divisor of two numbers.
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

# Extended Euclidean algorithm formula:
# gcd(a, b) = a * X + b * Y
# This function calculates and returns gcd, X and Y.
def xgcd(a, b):
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = xgcd(b % a, a)
    return gcd, y1 - (b // a) * x1, x1

# Produces a cryptographically secure random number from a selected range.
def produceRandom():
    return secrets.SystemRandom().randrange(config.POOL_START, config.POOL_END)

# Chooses a cryptographically secure random number, coprime with the totient 
# and smaller than it.
def chooseE(totient):
    while True:
        e = secrets.SystemRandom().randrange(2, totient)
        if gcd(e, totient) == 1:
            return e

# Generates Initialization Vector with BLOCK_SIZE size(in bytes). Each byte is 
# a securely chosen ascii letter or digit.
def generateIV():
    alphabet = string.ascii_letters + string.digits
    IV = "".join((secrets.choice(alphabet)) for i in range(config.BLOCK_SIZE))
    return IV

# Transforms a string of characters into a string of their ASCII values.
def stringToOrds(str1):
    res = 0
    for c in str1:
        res = res * 1000 + ord(c)
    return res

# Transforms a string of ASCII values into a string of their 
# character representations.
def reversedOrdsToString(int1):
    res = ''
    while int1 != 0:
        res = chr(int1 % 1000) + res
        int1 //= 1000
    return res

# Transforms an integer into an array containing its bit representation.
def intToBits(int1):
    retval = []
    if int1 == 0:
        return [0]
    else:
        while int1 > 0:
            retval.insert(0, int1 % 2)
            int1 //= 2
    return retval

# Transforms an array containing the bit representation of a number into this number.
def bitsToInt(bits):
    res = 0
    for bit in bits:
        res = res * 2 + bit
    return res

# Pads the input string so that its last block is complete. If it's already
# complete, it inserts another complete block in the end.
def pad(text):
    padding_len = config.BLOCK_SIZE - (len(text) % config.BLOCK_SIZE)
    padding = ([str(padding_len)] * padding_len)
    return text + "".join(padding)

# Removes the added padding from a string.
def unpad(text):
    padding_len = int(text[-1])
    return text[:-padding_len]

# Calculates the xor value of two numbers.
def xor(int1, int2):
    int1 = intToBits(int1)
    int2 = intToBits(int2)
    min_length, bigger_num = (len(int1), int2) if (len(int1) < len(int2)) else (len(int2), int1)
    res = bigger_num[:-min_length] + [int1[-b] ^ int2[-b] for b in range(min_length, 0, -1)]
    return bitsToInt(res)

# Increases an integer(counter) by one bit. If counter reaches its
# max value, it's reset to zero.
def increaseCounter(counter):
    counter = intToBits(counter)
    for i in reversed(range(len(counter))):
        counter[i] = 0 if counter[i] == 1 else 1
    return bitsToInt(counter)
