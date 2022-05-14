import random

"""
ElGamal encryption [ELG85] is based on the Diffie-Hellman Key Exchange method. 
It uses the same domain parameters (p,q, primRoot) and private/public key pair (xA,yA=primRoot**xAmodp) for a recipient yA. 
The plaintext message to be encrypted needs to be encoded as an integer m in the range [1,p−2]. 
"""

""" 
params: 
   - message : string
   - q : int

returns the original message string, converted to a list of integers less than q.
"""

def convertLettersToIntChunks(message, q):
    msgInBinary = (''.join(format(ord(letter), '08b') for letter in message))
    msgAsIntString = str(int(msgInBinary, 2))
    print("original message as int string: ", msgAsIntString, "\n")
    msgChunks = []

    # Create chunks of integers less than q and append to list of chunks
    i = 0
    j = 1
    while i < len(msgAsIntString):
        chunk = 0
        while ((int(msgAsIntString[i:j]) <= (q-1))):
            chunk = int(msgAsIntString[i:j])
            if(chunk == 0):
                j += 1
                break
            if (j == len(msgAsIntString) + 1):
                break
            j += 1
        msgChunks.append(chunk)
        i = j - 1
    print("original message as int string split into blocks of less than q: ", msgChunks, "\n")
    return msgChunks

""" 
params: 
   - q : int
   - primRoot : int

returns the private key and public key.
"""
def keyGen(q, primRoot):
    # 2 and q-1 both included
    xA = random.randint(2, q-1)
    yA = (primRoot ** xA) % q

    prKey = xA
    pubKey = (q, primRoot, yA)

    return prKey, pubKey

""" 
params: 
   - pubKey : int tuple
   - message : int

returns 
   - c1 : primRoot**kmodp.
   - c2: m*yA**.
   for one int chunk.
"""

def encrypt_operation(pubKey, message):
    k = random.randint(1, q-1)
    oneTimeKey = (pubKey[2] ** k) % pubKey[0]
    c1 = (pubKey[1] ** k) % pubKey[0]
    c2 = (oneTimeKey * message) % pubKey[0]
    return c1, c2

""" 
params: 
   - messageInChunks : list of int
   - pubKey : int tuple

returns c1 and c2 for all int chunks.
"""

def encrypt(messageInChunks, pubKey):
    cipherTupleList = []
    for chunk in messageInChunks:
        c1, c2 = encrypt_operation(pubKey, chunk)
        cipherTupleList.append((c1,c2))
    return cipherTupleList

""" 
params: 
   - cipherPair : int list
   - prKey : int

returns the original message after decryption for one cipher pair.
"""

def decrypt_operation(cipherPair, prKey):
    c1 = cipherPair[0]
    c2 = cipherPair[1]
    k = (c1 ** prKey) % q
    message = (c2 * pow(k, -1, q)) % q
    return message

""" 
params: 
   - cipher : int list
   - prKey : int

returns the whole decrypted message.
"""

def decrypt(cipher, prKey):
    messageAsIntString = ""
    for cipherPair in cipher:
        messageAsIntString += str(decrypt_operation(cipherPair, prKey))
    messageAsInt = int(messageAsIntString)
    originalMessage = messageAsInt.to_bytes((messageAsInt.bit_length() + 7) // 8, 'big').decode()
    return originalMessage

# main sequence

q = 71
primRoot = 12
message = "This class is CSI4108"

print("q: ", q)
print("primitive root: ", primRoot)
print("Original Message: ", message + "\n")

prKey, pubKey = keyGen(q, primRoot)
messageIntoIntChunks = convertLettersToIntChunks(message, 71)

cipher = encrypt(messageIntoIntChunks, pubKey)
print("cipher (Pairs of (c1, c2) as blocks that are smaller than q):")
print(cipher, "\n")
originalMessage = decrypt(cipher, prKey)
print("Decoded message: ", originalMessage)








