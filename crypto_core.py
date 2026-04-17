import secrets
import hashlib
import os

# ==================================================
# derive AES key and reference IV from my id
# ==================================================

student_id = "1220168"   

# AES-128 key derived using MD5
aes_key = hashlib.md5(student_id.encode("utf-8")).digest()

# reference IV derived from SHA256 
reference_iv = hashlib.sha256(student_id.encode("utf-8")).digest()[:16]

# ==================================================
# basic helper functions for CBC and AES
# ==================================================

BLOCK_SIZE = 16   # AES block size is 16 bytes

def xor_bytes(a, b):
    # XOR two byte arrays of equal length
    result = b""
    for i in range(len(a)):
        result += bytes([a[i] ^ b[i]])
    return result

def pkcs7_pad(data):
    # add PKCS#7 padding to make length multiple of 16
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([pad_len]) * pad_len
    return data + padding

def pkcs7_unpad(data):
    # remove PKCS#7 padding
    pad_len = data[-1]
    return data[:-pad_len]

def random_iv():
    # generate random IV 
    return os.urandom(BLOCK_SIZE)

def split_blocks(data):
    # split padded data into 16-byte blocks
    blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        blocks.append(data[i:i + BLOCK_SIZE])
    return blocks

###################################################################################################################################
#################################################### AES Implemntaion #############################################################
###################################################################################################################################

# ==================================================
#                   AES SubBytes
# ==================================================

def bytes_to_state(block16):
    # convert 16 bytes into 4x4 AES state
    state = [[0, 0, 0, 0] for _ in range(4)]
    index = 0
    for col in range(4):
        for row in range(4):
            state[row][col] = block16[index]
            index += 1
    return state

def state_to_bytes(state):
    # convert AES state back to 16 bytes
    out = []
    for col in range(4):
        for row in range(4):
            out.append(state[row][col])
    return bytes(out)

SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

def sub_bytes(state):
    # apply S-box substitution to each byte in the state
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]
    return state

# ==================================================
#                   AES shiftRows
# ==================================================
def shift_rows(state):
    # row 0: no shift
    state[0] = state[0]

    # row 1: shift left by 1
    state[1] = state[1][1:] + state[1][:1]

    # row 2: shift left by 2
    state[2] = state[2][2:] + state[2][:2]

    # row 3: shift left by 3
    state[3] = state[3][3:] + state[3][:3]

    return state

# ==================================================
#                   AES mix coulmn
# ==================================================
def xtime(a):
    # multiply by 2 in GF(2^8)
    a = a & 0xFF
    a2 = a << 1
    if a & 0x80:           # if highest bit was 1
        a2 = a2 ^ 0x1B     # reduce with AES polynomial
    return a2 & 0xFF

def mul_by_2(a):
    return xtime(a)

def mul_by_3(a):
    # 3*a = (2*a) XOR a
    return xtime(a) ^ a

def mix_single_column(col):
    # col is a list of 4 bytes: [a0,a1,a2,a3]
    a0, a1, a2, a3 = col[0], col[1], col[2], col[3]

    b0 = mul_by_2(a0) ^ mul_by_3(a1) ^ a2 ^ a3
    b1 = a0 ^ mul_by_2(a1) ^ mul_by_3(a2) ^ a3
    b2 = a0 ^ a1 ^ mul_by_2(a2) ^ mul_by_3(a3)
    b3 = mul_by_3(a0) ^ a1 ^ a2 ^ mul_by_2(a3)

    return [b0 & 0xFF, b1 & 0xFF, b2 & 0xFF, b3 & 0xFF]

def mix_columns(state):
    # apply MixColumns on each column of the state
    for c in range(4):
        col = [state[0][c], state[1][c], state[2][c], state[3][c]]
        mixed = mix_single_column(col)
        state[0][c] = mixed[0]
        state[1][c] = mixed[1]
        state[2][c] = mixed[2]
        state[3][c] = mixed[3]
    return state

# ==================================================
#                   AES AddRoundKey
# ==================================================
def add_round_key(state, round_key16):
    # round_key16 is 16 bytes (one round key)

    idx = 0
    for col in range(4):
        for row in range(4):
            state[row][col] = state[row][col] ^ round_key16[idx]
            idx += 1

    return state

###################################################################################################################################
############################################## Key Expansion  #####################################################################
###################################################################################################################################

# ==================================================
#           helpers
# ==================================================

def rot_word(word4):
    # rotate left: [a0,a1,a2,a3] -> [a1,a2,a3,a0]
    return word4[1:] + word4[:1]

def sub_word(word4):
    # apply S-box to each byte in the word
    return [SBOX[b] for b in word4]

# rcon values for AES-128 (10 rounds)
# each entry is 4 bytes: [RC, 0x00, 0x00, 0x00]
RCON = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
]

def xor_words(w1, w2):
    # XOR two 4-byte words 
    return [w1[i] ^ w2[i] for i in range(4)]

# ==================================================
#           generate all key words
# ==================================================
def key_expansion(key16):
    # key16 is original AES key (16 bytes)
    # the output result is list of 44 words, each word is 4 bytes
    words = []

    #1) split original key into 4 words (w0 to w3)
    for i in range(4):
        word = [
            key16[4*i],
            key16[4*i + 1],
            key16[4*i + 2],
            key16[4*i + 3]
        ]
        words.append(word)

    #2) generate remaining words (w4 to w43)
    i = 4
    while i < 44:
        temp = words[i - 1].copy()

        # apply g func
        if i % 4 == 0:
            temp = rot_word(temp)              # RotWord
            temp = sub_word(temp)              # SubWord
            temp = xor_words(temp, RCON[i//4 - 1])  # XOR with Round coefficient

        # generate new word
        new_word = xor_words(words[i - 4], temp)
        words.append(new_word)

        i += 1
    return words

# ==================================================
#           build round keys (11 keys)
# ==================================================

def words_to_round_keys(words):

    round_keys = []

    # each round key = 4 words = 16 bytes
    # round 0 key = w0..w3
    # round 1 key = w4..w7
    # ...
    # round 10 key = w40..w43
    for r in range(11):
        start = r * 4
        rk_bytes = []

        # collect 4 words
        for w in range(start, start + 4):
            rk_bytes += words[w]   # add the 4 bytes of the word

        round_keys.append(bytes(rk_bytes))  # 16 bytes

    return round_keys

###################################################################################################################################
############################################## AES ENC Block ######################################################################
###################################################################################################################################

def aes_encrypt_block(block16, round_keys):
    # block16: 16 bytes plaintext block
    # round_keys: list of 11 round keys (each is 16 bytes)

    # convert input block to AES state (4x4)
    state = bytes_to_state(block16)

    # initial step: AddRoundKey (round 0 key)
    state = add_round_key(state, round_keys[0])

    # rounds 1..9 (full rounds)
    for r in range(1, 10):
        state = sub_bytes(state)               # SubBytes
        state = shift_rows(state)              # ShiftRows
        state = mix_columns(state)             # MixColumns
        state = add_round_key(state, round_keys[r])  # AddRoundKey

    # final round (round 10) - no MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    # convert state back to bytes
    return state_to_bytes(state)

###################################################################################################################################
############################################## AES decryption  ####################################################################
###################################################################################################################################

# ==================================================
# AES-128 decryption for one 16-byte block 
# ==================================================

# inverse S-box (fixed table)
INV_SBOX = [
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
]

def inv_sub_bytes(state):
    # inverse substitution using INV_SBOX
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]
    return state

def inv_shift_rows(state):
    # inverse of ShiftRows (shift right instead of left)
    state[0] = state[0]                             # no shift
    state[1] = state[1][-1:] + state[1][:-1]         # right by 1
    state[2] = state[2][-2:] + state[2][:-2]         # right by 2
    state[3] = state[3][-3:] + state[3][:-3]         # right by 3
    return state

def gf_mul(a, b):
    a = a & 0xFF
    b = b & 0xFF
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return res & 0xFF

def inv_mix_single_column(col):
    # inverse MixColumns uses constants: 0e 0b 0d 09
    a0, a1, a2, a3 = col[0], col[1], col[2], col[3]

    b0 = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9)
    b1 = gf_mul(a0, 9)  ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13)
    b2 = gf_mul(a0, 13) ^ gf_mul(a1, 9)  ^ gf_mul(a2, 14) ^ gf_mul(a3, 11)
    b3 = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9)  ^ gf_mul(a3, 14)

    return [b0 & 0xFF, b1 & 0xFF, b2 & 0xFF, b3 & 0xFF]

def inv_mix_columns(state):
    # apply inverse MixColumns on each column of the state
    for c in range(4):
        col = [state[0][c], state[1][c], state[2][c], state[3][c]]
        mixed = inv_mix_single_column(col)
        state[0][c] = mixed[0]
        state[1][c] = mixed[1]
        state[2][c] = mixed[2]
        state[3][c] = mixed[3]
    return state

def aes_decrypt_block(block16, round_keys):
    # block16: 16 bytes ciphertext block
    # round_keys: list of 11 round keys 

    state = bytes_to_state(block16)

    # start with last round key
    state = add_round_key(state, round_keys[10])

    # inverse final round steps
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)

    # rounds 9..1 (inverse full rounds)
    for r in range(9, 0, -1):
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

    # finish with round 0 key
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)

###################################################################################################################################
############################################## CBC ENC/DEC  #######################################################################
###################################################################################################################################

# ==================================================
#           CBC encryption    
# ==================================================

def cbc_encrypt(plaintext_bytes, key16):
    # plaintext_bytes: bytes
    # key16: 16 bytes AES key
    # returns: (iv, ciphertext)

    # build round keys from the main key
    words = key_expansion(key16)
    round_keys = words_to_round_keys(words)

    # pad plaintext then split into blocks
    padded = pkcs7_pad(plaintext_bytes)
    blocks = split_blocks(padded)

    # generate random IV
    iv = random_iv()

    ciphertext = b""
    previous = iv

    for block in blocks:
        x = xor_bytes(block, previous)                 # Pi XOR previous
        c = aes_encrypt_block(x, round_keys)           # AES encrypt one block
        ciphertext += c
        previous = c                                   # chaining

    return iv, ciphertext

# ==================================================
#           CBC decryption    
# ==================================================
def cbc_decrypt(iv, ciphertext_bytes, key16):
    # iv: 16 bytes
    # ciphertext_bytes: bytes (multiple of 16)
    # key16: 16 bytes AES key
    # returns: plaintext bytes

    # build round keys
    words = key_expansion(key16)
    round_keys = words_to_round_keys(words)

    blocks = split_blocks(ciphertext_bytes)

    plaintext_padded = b""
    previous = iv

    for block in blocks:
        x = aes_decrypt_block(block, round_keys)       # AES decrypt one block
        p = xor_bytes(x, previous)                     # XOR with previous
        plaintext_padded += p
        previous = block                               # previous ciphertext

    # remove padding
    return pkcs7_unpad(plaintext_padded)

def encrypt_message(plaintext_str, key16):
    # plaintext_str: normal text (string)
    # key16: 16-byte AES key
    # returns iv and ciphertext as hex strings (easy to copy/send)

    plaintext_bytes = plaintext_str.encode("utf-8")
    iv, ct = cbc_encrypt(plaintext_bytes, key16)

    return iv.hex(), ct.hex()

def decrypt_message(iv_hex, ct_hex, key16):
    # iv_hex, ct_hex: hex strings
    # key16: 16-byte AES key
    # returns plaintext as string

    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)

    plaintext_bytes = cbc_decrypt(iv, ct, key16)
    return plaintext_bytes.decode("utf-8", errors="replace")

###################################################################################################################################
############################################## Phase 2  ###########################################################################
###################################################################################################################################

# =============================================
# RSA part (key generation, signing, verifying)
# =============================================

# Extended Euclidean Algorithm: to find modular inverse
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

# find inverse of a modulo m: to compute RSA private key d
def modinv(a, m):
    result = egcd(a, m)
    g = result[0] 
    x = result[1]  
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

# check if number is prime (Miller–Rabin)
def is_probable_prime(n, rounds=8):
    if n < 2:
        return False

    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# generate a prime number of given bit size
def gen_prime(bits):
    while True:
        x = secrets.randbits(bits)

        # make it odd
        if x % 2 == 0:
            x = x + 1

        # ensure correct size
        min_val = 1 << (bits - 1)
        if x < min_val:
            x = x + min_val

        if is_probable_prime(x):
            return x

# store RSA keys
class RSAKeyPair:
    def __init__(self, n, e, d):
        self.n = n
        self.e = e
        self.d = d

# generate RSA-128 key pair
def rsa_generate_128():
    p = gen_prime(64)
    q = gen_prime(64)
    while p == q:
        q = gen_prime(64)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if egcd(e, phi)[0] != 1:
        raise ValueError("Bad e")

    d = modinv(e, phi)
    return RSAKeyPair(n, e, d)

# SHA-256 hash function
def sha256(data):
    hash_object = hashlib.sha256(data)
    hash_value = hash_object.digest()
    return hash_value

# RSA signing
def rsa_sign(message, private_key):
    hash_bytes = sha256(message)
    h = int.from_bytes(hash_bytes, "big")
    h = h % private_key.n
    signature = pow(h, private_key.d, private_key.n)
    return signature


# RSA verification
def rsa_verify(message, signature, n, e):
    hash_bytes = sha256(message)
    h = int.from_bytes(hash_bytes, "big")
    h = h % n
    recovered_hash = pow(signature, e, n)
    return recovered_hash == h

# ============================================
#           Diffie–Hellman part
# ============================================

# public DH parameters (agreed by both sides)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)

# generator
DH_G = 2  

# generate random DH private value
def dh_private():
    random_value = secrets.randbelow(DH_P - 2)
    private_value = random_value + 2
    return private_value

# compute DH public value
def dh_public(x):
    return pow(DH_G, x, DH_P)

# compute DH shared secret
def dh_shared(their_public, my_private):
    return pow(their_public, my_private, DH_P)

# convert integer to bytes
def int_to_bytes(x):
    bits = x.bit_length()
    bytes_len = (bits + 7) // 8
    if bytes_len == 0:
        bytes_len = 1
    return x.to_bytes(bytes_len, "big")


# derive session key from shared secret: session_Key = SHA256(s)[0:16]
def derive_session_key(shared_secret):
    secret_bytes = int_to_bytes(shared_secret)
    full_hash = sha256(secret_bytes)
    session_key = full_hash[:16]
    return session_key

# ============================================
#           Signed message format
# ============================================

# bind DH value to my id
def signed_data(sender_id, receiver_id, dh_value):
    sender = sender_id
    receiver = receiver_id
    dh_str = str(dh_value)
    message = sender + "|" + receiver + "|" + dh_str
    return message.encode()