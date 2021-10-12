import os
import sys
from constants import AES_KEY, INV_BOX, IV

from constants import S_BOX, R_CON
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def add_round_key(matrix, expanded_keys):
    for i in range(4):
        for j in range(4):
            matrix[i][j] ^= expanded_keys[i][j]

def convert_to_matrix(cb_msg):
    assert len(cb_msg) % 16 == 0
    matrix = []
    for i in range(0, len(cb_msg), 4):
        matrix.append([cb_msg[i + x] for x in range(4)])
    return matrix

def expand_key(key):
    matrix = convert_to_matrix(key)
    i = 1
    while len(matrix) < 44:
        mtx = list(matrix[-1])
        if len(matrix) % (len(key)//4) == 0:
            mtx.append(mtx.pop(0))
            mtx = [S_BOX[b] for b in mtx]
            mtx[0] ^= R_CON[i]
            i += 1

        mtx = bytes(i^j for i, j in zip(mtx, matrix[-(len(key)//4)]))
        matrix.append(mtx)

    return [matrix[4*i:4*(i+1)] for i in range(len(matrix) // 4)]

def shift_matrix(matrix):
    matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1] = matrix[1][1], matrix[2][1], matrix[3][1], matrix[0][1]
    matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2] = matrix[2][2], matrix[3][2], matrix[0][2], matrix[1][2]
    matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3] = matrix[3][3], matrix[0][3], matrix[1][3], matrix[2][3]

def _encrypt(text, key):
    assert len(text) % 16 == 0
    expanded_key = expand_key(key)
    matrix = convert_to_matrix(text)
    add_round_key(matrix, expanded_key[0])
    
    for i in range(1, 10):
        for j in range(4):
            for k in range(4):
                matrix[j][k] = S_BOX[matrix[j][k]]
        shift_matrix(matrix)
        for j in range(4):
            xor_matrix = matrix[j][0] ^ matrix[j][1] ^ matrix[j][2] ^ matrix[j][3]
            temp = matrix[j][0]
            matrix[j][0] ^= xor_matrix ^ xtime(matrix[j][0] ^ matrix[j][1])
            matrix[j][1] ^= xor_matrix ^ xtime(matrix[j][1] ^ matrix[j][2])
            matrix[j][2] ^= xor_matrix ^ xtime(matrix[j][2] ^ matrix[j][3])
            matrix[j][3] ^= xor_matrix ^ xtime(matrix[j][3] ^ temp)
        add_round_key(matrix, expanded_key[i])
    for j in range(4):
        for k in range(4):
            matrix[j][k] = S_BOX[matrix[j][k]]

    shift_matrix(matrix)
    add_round_key(matrix, expanded_key[-1])
    print(convert_to_bytes(matrix))
    return convert_to_bytes(matrix)

def encrypt(filename):
    try:
        file = open(filename, 'rb')
        text_byte = file.read()
        file.close()
    except Exception as e:
        raise Exception('Error encrypting data')

    data_to_pad = text_byte
    padding_len = 16-len(data_to_pad)%16
    padding = bytes([padding_len])*padding_len
    total_text_byte = data_to_pad + padding
    encrypt_data = _encrypt(total_text_byte, AES_KEY)
    file = open("{}.b".format(filename), "wb")
    file.write(bytes(encrypt_data))
    file.close()

def inv_shift_rows(matrix):
    matrix[0][1], matrix[1][1], matrix[2][1], matrix[3][1] = matrix[3][1], matrix[0][1], matrix[1][1], matrix[2][1]
    matrix[0][2], matrix[1][2], matrix[2][2], matrix[3][2] = matrix[2][2], matrix[3][2], matrix[0][2], matrix[1][2]
    matrix[0][3], matrix[1][3], matrix[2][3], matrix[3][3] = matrix[1][3], matrix[2][3], matrix[3][3], matrix[0][3]

def _decrypt(text, key):
    expanded_keys = expand_key(key)
    assert len(text) % 16 == 0

    matrix = convert_to_matrix(text)

    add_round_key(matrix, expanded_keys[-1])
    inv_shift_rows(matrix)
    for i in range(4):
        for j in range(4):
            matrix[i][j] = INV_BOX[matrix[i][j]]


    for i in range(9, 0, -1):
        add_round_key(matrix, expanded_keys[i])
        for j in range(4):
            u = xtime(xtime(matrix[i][0] ^ matrix[i][2]))
            v = xtime(xtime(matrix[i][1] ^ matrix[i][3]))
            matrix[i][0] ^= u
            matrix[i][1] ^= v
            matrix[i][2] ^= u
            matrix[i][3] ^= v
        for j in range(4):
            xor_matrix = matrix[j][0] ^ matrix[j][1] ^ matrix[j][2] ^ matrix[j][3]
            temp = matrix[j][0]
            matrix[j][0] ^= xor_matrix ^ xtime(matrix[j][0] ^ matrix[j][1])
            matrix[j][1] ^= xor_matrix ^ xtime(matrix[j][1] ^ matrix[j][2])
            matrix[j][2] ^= xor_matrix ^ xtime(matrix[j][2] ^ matrix[j][3])
            matrix[j][3] ^= xor_matrix ^ xtime(matrix[j][3] ^ temp)
        inv_shift_rows(matrix)
        for j in range(4):
            for k in range(4):
                matrix[j][k] = INV_BOX[matrix[j][k]]

    add_round_key(matrix, expanded_keys[0])
    return convert_to_bytes(matrix)

def decrypt (filename):
    try:
        file = open(filename, 'rb')
        ct_bytes = file.read()
        file.close()
    except Exception as e:
        raise Exception('Error decrypting data')
    padded_data = bytes(_decrypt(ct_bytes, AES_KEY))
    pdata_len = len(ct_bytes)
    padding_len = padded_data[-1]
    total_text_byte = padded_data[:-padding_len]
    file = open(filename[:-2], "wb")
    file.write(total_text_byte)
    file.close()
    os.remove(os.path.abspath(filename))


def convert_to_bytes(matrix):
    byte = []
    for m in matrix:
        for n in m: byte.append(n)
    return byte