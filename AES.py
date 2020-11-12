#!/usr/bin/env python3

from BitVector import *

num_rounds = 14
AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []  # SBox for encryption
invSubBytesTable = []  # SBox for decryption
round_keys = [None for i in range(num_rounds + 1)]


def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        a = a.get_bitvector_in_hex()
        subBytesTable.append(a)
        # For the decryption Sbox:
        b = BitVector(intVal=i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        if type(b) == int:
            b = BitVector(hexstring='00')
        b = b.get_bitvector_in_hex()
        invSubBytesTable.append(b)


def key_initialize():
    key_bv = get_key_from_user()
    key_words = gen_key_schedule_256(key_bv)
    key_schedule = []
    for word_index, word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i * 8:i * 8 + 8].intValue())
        key_schedule.append(keyword_in_ints)
    for i in range(num_rounds + 1):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] + key_words[i * 4 + 3]).get_bitvector_in_hex()


def g(keyword, round_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=byte_sub_table[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_constant


def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    # We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    # 256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    # block with. Subsequently, each of the 14 rounds uses 4 keywords from the key
    # schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i * 32: i * 32 + 32]
    for i in range(8, 60):
        if i % 8 == 0:
            kwd, round_constant = g(key_words[i - 1], round_constant, byte_sub_table)
            key_words[i] = key_words[i - 8] ^ kwd
        elif (i - (i // 8) * 8) < 4:
            key_words[i] = key_words[i - 8] ^ key_words[i - 1]
        elif (i - (i // 8) * 8) == 4:
            key_words[i] = BitVector(size=0)
            for j in range(4):
                key_words[i] += BitVector(intVal=byte_sub_table[key_words[i - 1][8 * j:8 * j + 8].intValue()], size=8)
            key_words[i] ^= key_words[i - 8]
        elif ((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8):
            key_words[i] = key_words[i - 8] ^ key_words[i - 1]
    return key_words


def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable


def get_key_from_user():
    keyfile = open(sys.argv[3])
    key = keyfile.read()
    key_bv = BitVector(textstring=key.strip())
    return key_bv


genTables()
key_initialize()


'''---------------------------------------------------------------------------------------------'''


def aes_encrypt():
    text_bv = BitVector(size=0)
    bv = BitVector(filename=sys.argv[2])

    #Reading the plain text
    while bv.more_to_read:
        rnd = 1     # Round counter
        bitvec = bv.read_bits_from_file(128)
        if len(bitvec) != 128:
            bitvec.pad_from_right(128 - len(bitvec))
        bitvec = bitvec ^ hex_to_bin(round_keys[0])     # First round addition with round key

        # Converting bitvec to 4x4 state vector
        state_vec = []
        for i in range(4):
            temp = []
            for j in range(i * 8, 128, 32):
                temp.append(bitvec[j:j + 8].get_bitvector_in_hex())
            state_vec.append(temp)

        # For loop for 13 rounds of AES
        for i in range(num_rounds - 1):
            sub_bytes(state_vec)
            shift_rows(state_vec)
            state_vec = mix_columns(state_vec)
            enc = add_roundkey(state_vec, rnd)

            # Converting enc bitvector to 4x4 state vector
            state_vec = []
            for x in range(4):
                temp = []
                for j in range(x * 8, 128, 32):
                    temp.append(enc[j:j + 8].get_bitvector_in_hex())
                state_vec.append(temp)

            rnd += 1

        # 14th round excluding the mix columns step
        sub_bytes(state_vec)
        shift_rows(state_vec)
        enc = add_roundkey(state_vec, rnd)

        text_bv += enc

    # Writing encrypted text to file
    answer = text_bv.get_bitvector_in_hex()
    text_file = open(sys.argv[4], 'w')
    text_file.write(answer)
    text_file.close()


def aes_decrypt():
    text_bv = BitVector(size=0)
    round_keys.reverse()    # Reversing the round keys array

    # Reading encrypted text from file
    text_file = open(sys.argv[2])
    bv = BitVector(hexstring=text_file.read())

    for i in range(int(len(bv) / 128)):     # Till end of the encrypted text file
        bitvec = bv[i * 128:(i + 1) * 128]      # Slicing for 128 bits block
        bitvec = bitvec ^ hex_to_bin(round_keys[0])     # First round addition with round key
        rnd = 1     # Round counter

        # To create 4x4 state vector from bitvec
        state_vec = []
        for i in range(4):
            temp = []
            for j in range(i * 8, 128, 32):
                temp.append(bitvec[j:j + 8].get_bitvector_in_hex())
            state_vec.append(temp)

        # For loop for 13 rounds of AES
        for i in range(num_rounds - 1):
            inv_shift_rows(state_vec)
            inv_sub_bytes(state_vec)
            enc = add_roundkey(state_vec, rnd)

            # To create 4x4 state vector from enc bitvector
            state_vec = []
            for x in range(4):
                temp = []
                for j in range(x * 8, 128, 32):
                    temp.append(enc[j:j + 8].get_bitvector_in_hex())
                state_vec.append(temp)

            state_vec = inv_mix_columns(state_vec)

            rnd += 1

        # For the final round of decryption excluding inv mix columns
        inv_shift_rows(state_vec)
        inv_sub_bytes(state_vec)
        enc = add_roundkey(state_vec, rnd)

        text_bv += enc

    # To write the decrypted text to file
    answer = text_bv.get_bitvector_in_ascii()
    text_file = open(sys.argv[4], 'w')
    text_file.write(answer)
    text_file.close()


# To convert hex strings to bitvectors
def hex_to_bin(hex_str):
    return BitVector(hexstring=hex_str)


def sub_bytes(state_vec):
    for i in range(4):
        for j in range(4):
            # Converting hex to int to index sub bytes table
            state_vec[i][j] = subBytesTable[int(str(hex_to_bin(state_vec[i][j])), 2)]


def inv_sub_bytes(state_vec):
    for i in range(4):
        for j in range(4):
            # Converting hex to int to index inv sub bytes table
            state_vec[i][j] = invSubBytesTable[int(str(hex_to_bin(state_vec[i][j])), 2)]


def shift_rows(state_vec):
    for i in range(4):
        # Shift left using list slicing
        state_vec[i] = state_vec[i][i:] + state_vec[i][:i]


def inv_shift_rows(state_vec):
    for i in range(4):
        # Shift right using list slicing
        state_vec[i] = state_vec[i][-i:] + state_vec[i][:-i]


def mix_columns(state_vec):
    # To create bitvectors of '0x02' and '0x03' for multiplication
    bin2 = BitVector(hexstring='02')
    bin3 = BitVector(hexstring='03')

    # Creating copy of the state vector
    temp_vec = [[0 for i in range(4)] for j in range(4)]
    for i in range(4):
        for j in range(4):
            temp_vec[i][j] = state_vec[i][j]

    # Using mix columns formula for each row elements
    for i in range(4):
        temp = bin2.gf_multiply_modular(hex_to_bin(state_vec[0][i]), AES_modulus, 8) ^ bin3.gf_multiply_modular(hex_to_bin(state_vec[1][i]), AES_modulus, 8) ^ hex_to_bin(state_vec[2][i]) ^ hex_to_bin(state_vec[3][i])
        temp_vec[0][i] = temp.get_bitvector_in_hex()

        temp = hex_to_bin(state_vec[0][i]) ^ bin2.gf_multiply_modular(hex_to_bin(state_vec[1][i]), AES_modulus, 8) ^ bin3.gf_multiply_modular(hex_to_bin(state_vec[2][i]), AES_modulus, 8) ^ hex_to_bin(state_vec[3][i])
        temp_vec[1][i] = temp.get_bitvector_in_hex()

        temp = hex_to_bin(state_vec[0][i]) ^ hex_to_bin(state_vec[1][i]) ^ bin2.gf_multiply_modular(hex_to_bin(state_vec[2][i]), AES_modulus, 8) ^ bin3.gf_multiply_modular(hex_to_bin(state_vec[3][i]), AES_modulus, 8)
        temp_vec[2][i] = temp.get_bitvector_in_hex()

        temp = bin3.gf_multiply_modular(hex_to_bin(state_vec[0][i]), AES_modulus, 8) ^ hex_to_bin(state_vec[1][i]) ^ hex_to_bin(state_vec[2][i]) ^ bin2.gf_multiply_modular(hex_to_bin(state_vec[3][i]), AES_modulus, 8)
        temp_vec[3][i] = temp.get_bitvector_in_hex()

    return temp_vec


def inv_mix_columns(state_vec):
    # To create bitvectors of '0x0E', '0x0B', '0x0D' and '0x09' for multiplication
    binE = BitVector(hexstring='0E')
    binB = BitVector(hexstring='0B')
    binD = BitVector(hexstring='0D')
    bin9 = BitVector(hexstring='09')

    # Creating copy of the state vector
    temp_vec = [[0 for i in range(4)] for j in range(4)]
    for i in range(4):
        for j in range(4):
            temp_vec[i][j] = state_vec[i][j]

    # Using inv mix columns formula for each row elements
    for i in range(4):
        temp = binE.gf_multiply_modular(hex_to_bin(state_vec[0][i]), AES_modulus, 8) ^ binB.gf_multiply_modular(hex_to_bin(state_vec[1][i]), AES_modulus, 8) ^ binD.gf_multiply_modular(hex_to_bin(state_vec[2][i]), AES_modulus, 8) ^ bin9.gf_multiply_modular(hex_to_bin(state_vec[3][i]), AES_modulus, 8)
        temp_vec[0][i] = temp.get_bitvector_in_hex()

        temp = bin9.gf_multiply_modular(hex_to_bin(state_vec[0][i]), AES_modulus, 8) ^ binE.gf_multiply_modular(hex_to_bin(state_vec[1][i]), AES_modulus, 8) ^ binB.gf_multiply_modular(hex_to_bin(state_vec[2][i]), AES_modulus, 8) ^ binD.gf_multiply_modular(hex_to_bin(state_vec[3][i]), AES_modulus, 8)
        temp_vec[1][i] = temp.get_bitvector_in_hex()

        temp = binD.gf_multiply_modular(hex_to_bin(state_vec[0][i]), AES_modulus, 8) ^ bin9.gf_multiply_modular(hex_to_bin(state_vec[1][i]), AES_modulus, 8) ^ binE.gf_multiply_modular(hex_to_bin(state_vec[2][i]), AES_modulus, 8) ^ binB.gf_multiply_modular(hex_to_bin(state_vec[3][i]), AES_modulus, 8)
        temp_vec[2][i] = temp.get_bitvector_in_hex()

        temp = binB.gf_multiply_modular(hex_to_bin(state_vec[0][i]), AES_modulus, 8) ^ binD.gf_multiply_modular(hex_to_bin(state_vec[1][i]), AES_modulus, 8) ^ bin9.gf_multiply_modular(hex_to_bin(state_vec[2][i]), AES_modulus, 8) ^ binE.gf_multiply_modular(hex_to_bin(state_vec[3][i]), AES_modulus, 8)
        temp_vec[3][i] = temp.get_bitvector_in_hex()

    return temp_vec


def add_roundkey(state_vec, rnd):
    # To create single hex string from 4x4 state array
    arr = []
    for i in range(4):
        temp = []
        for j in range(4):
            temp += state_vec[j][i]
        temp = ''.join(temp)
        arr += temp
    arr = ''.join(arr)

    enc_text = hex_to_bin(arr) ^ hex_to_bin(round_keys[rnd])    # Adding round key based on rnd counter

    return enc_text


if __name__ == '__main__':
    if sys.argv[1] == '-e':
        aes_encrypt()
    if sys.argv[1] == '-d':
        aes_decrypt()
