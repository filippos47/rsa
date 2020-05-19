# A simple driver program.

from encrypter import Encrypter
import signal
import sys

messageMsg = 'Type the message you want to encrypt. ' \
    'Your message should not be blank.'
modeMsg = 'Select your preferred mode of encryption. Offered modes:\n' \
    '1) ECB, 2) OFB, 3) CTR, 4) CBC --> Either type the name or the number of the mode.'
modeSetMsg = 'Ciphering mode set to '
cipherReadyMsg = 'Your encrypted ciphertext is:\n'
decryptMsg = 'Would you like to decrypt the ciphertext? y/n'
decryptionDoneMsg = 'Your decrypted cipher and starting message is:\n'
loopMsg = 'Want to encrypt another message? y/n'
errorMsg = 'Please read the instructions carefully.'
byeMsg = 'Goodbye then!'

def signal_handler(sig, frame):
    print('\n' + byeMsg)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
encrypter = Encrypter()
stop = False

while True:
    print(messageMsg)
    while True:
        message = input()
        if message != '':
            break
        print(errorMsg)

    print(modeMsg)
    while True:
        mode = input()
        if mode == '1' or mode == 'ECB':
            mode = 'ECB'
            break
        elif mode == '2' or mode == 'OFB':
            mode = 'OFB'
            break
        elif mode == '3' or mode == 'CTR':
            mode = 'CTR'
            break
        elif mode == '4' or mode == 'CBC':
            mode = 'CBC'
            break
        print(errorMsg)
    print(modeSetMsg + mode + '.')

    ciphertext = encrypter.encrypt(message, mode)
    print(cipherReadyMsg + str(ciphertext.replace(' ', '')))

    print(decryptMsg)
    while True:
        decrypt = input()
        if decrypt == 'y':
            decryptedCipher = encrypter.decrypt(ciphertext, mode)
            print(decryptionDoneMsg + str(decryptedCipher))
            break
        elif decrypt == 'n':
            break
        print(errorMsg)

    print(loopMsg)
    while True:
        loop = input()
        if loop == 'y':
            break
        elif loop == 'n':
            stop = True
            break
        print(errorMsg)

    if stop:
        print(byeMsg)
        break
