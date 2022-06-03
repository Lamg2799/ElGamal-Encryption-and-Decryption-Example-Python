import random

"""
Converts letters into integer chunks less than q.

Args:
    message: A message as a string.
    q: Max int chunk size as integer.

Returns:
    A list of integer chunks less than q
"""
def convertLettersToIntChunks(message, q):
    msg_in_binary = (''.join(format(ord(letter), '08b') for letter in message))
    msg_as_int_string = str(int(msg_in_binary, 2))
    print("original message as int string: ", msg_as_int_string, "\n")
    msg_chunks = []

    # Create chunks of integers less than q and append to list of chunks
    i = 0
    j = 1
    while i < len(msg_as_int_string):
        chunk = 0
        while ((int(msg_as_int_string[i:j]) <= (q-1))):
            chunk = int(msg_as_int_string[i:j])
            if(chunk == 0):
                j += 1
                break
            if (j == len(msg_as_int_string) + 1):
                break
            j += 1
        msg_chunks.append(chunk)
        i = j - 1
    print("original message as int string split into blocks of less than q:\n", msg_chunks, "\n")
    return msg_chunks

"""
Generates a private and public key pair.

Args:
    q: Prime as integer.
    prim_root: Primitive root as integer.

Returns:
    Private key and public key as integers.
"""
def keyGen(q, prim_root):
    # 2 and q-1 both included
    x_A = random.randint(2, q-1)
    y_A = (prim_root ** x_A) % q

    pr_key = x_A
    pub_key = (q, prim_root, y_A)

    return pr_key, pub_key

"""
A single encrypt operation for an int chunk.

Args:
    pub_key: Public key as an integer.
    chunk: An integer chunk of a larger message.

Returns:
    c1 and c2 as integers.
"""
def encrypt_operation(pub_key, chunk, q):
    k = random.randint(1, q-1)
    one_time_key = (pub_key[2] ** k) % pub_key[0]
    c1 = (pub_key[1] ** k) % pub_key[0]
    c2 = (one_time_key * chunk) % pub_key[0]
    return c1, c2

"""
Encryption operation for a message.

Args:
    message_in_chunks: A list of int chunks.
    pub_key: Public key as integer.

Returns:
    The encrypted message as a list of tuples.
"""

def encrypt(message_in_chunks, pub_key, q):
    cipherTupleList = []
    for chunk in message_in_chunks:
        c1, c2 = encrypt_operation(pub_key, chunk, q)
        cipherTupleList.append((c1,c2))
    return cipherTupleList

"""
A single decrypt operation for an int chunk.

Args:
    cipher_pair: Cipher tuple for one int chunk.
    pr_key: Private key as an integer.

Returns:
    The decrypted chunk as an integer.
"""
def decrypt_operation(cipher_pair, pr_key, q):
    c1 = cipher_pair[0]
    c2 = cipher_pair[1]
    k = (c1 ** pr_key) % q
    decrypted_chunk = (c2 * pow(k, -1, q)) % q
    return decrypted_chunk

"""
Decryption operation for a message.

Args:
    cipher: The list of tuples of integers for an encrypted message.
    pr_key: Private key as an integer.

Returns:
    The decrypted message as a string.
"""
def decrypt(cipher, pr_key, q):
    message_as_int_string = ""
    for cipher_pair in cipher:
        message_as_int_string += str(decrypt_operation(cipher_pair, pr_key, q))
    message_as_int = int(message_as_int_string)
    original_message = message_as_int.to_bytes((message_as_int.bit_length() + 7) // 8, 'big').decode()
    return original_message

"""
ElGamal encryption [ELG85] is based on the Diffie-Hellman Key Exchange method. 
It uses the same domain parameters (p,q, prim_root) and private/public key pair (x_A,y_A=prim_root**x_Amodp) for a recipient y_A. 
The plaintext message to be encrypted needs to be encoded as an integer m in the range [1,p−2]. 
"""
def main():
    q = 71
    prim_root = 12
    message = "This class is CSI4108"

    print("q: ", q)
    print("primitive root: ", prim_root)
    print("Original Message: ", message + "\n")

    pr_key, pub_key = keyGen(q, prim_root)
    message_into_int_chunks = convertLettersToIntChunks(message, 71)

    cipher = encrypt(message_into_int_chunks, pub_key, q)
    print("cipher (Pairs of (c1, c2) as blocks that are smaller than q):")
    print(cipher, "\n")
    original_message = decrypt(cipher, pr_key, q)
    print("Decoded message: ", original_message)

if __name__ == "__main__":
    main()








