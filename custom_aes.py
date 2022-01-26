import os
from constants import AES_KEY, INV_BOX, IV, S_BOX, R_CON

def convert_to_matrix(cb_msg):
    assert len(cb_msg) % 16 == 0
    matrix = []
    for i in range(0, len(cb_msg), 4):
        matrix.append([cb_msg[i + x] for x in range(4)])
    return matrix

def convert_to_bytes(matrix):
    byte = []
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            byte.append(matrix[j][i])
    return byte

def convert_to_list(matrix):
    l = []
    for m in matrix:
        for i in m:
            l.append(i)
    return l

def key_expansion(key):
    key_mtx = convert_to_matrix(key)
    rot_word = sub_word = None
    for i in range(11):
        for j in range(4):
            if i > 0:
                if j == 0:
                    key_mtx.append([key_mtx[(i-1)*4+j][k] ^ res[k] for k in range(4)])
                else:
                    key_mtx.append([key_mtx[(i-1)*4+j][k] ^ key_mtx[(i)*4+j-1][k] for k in range(4)])
            if (i*4+j) % 4 == 3:
                rot_word = [key_mtx[i*4+j][1], key_mtx[i*4+j][2], key_mtx[i*4+j][3], key_mtx[i*4+j][0]]
                sub_word =  [S_BOX[rot_word[0]], S_BOX[rot_word[1]], S_BOX[rot_word[2]], S_BOX[rot_word[3]]]
                res = [sub_word[0] ^ R_CON[i+1], sub_word[1], sub_word[2], sub_word[3]]
    res = []
    for k in range(11):
        mtx = []
        for i in range(4):
            mtx.append([key_mtx[j + k*4][i] for j in range(4)])
        res.append(mtx)
    return res

def adding_round_key(text, key_expand):
    for i in range(4):
        for j in range(4):
            text[i][j] ^= key_expand[i][j]

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]

def shift_rows(state):
    for i in range(len(state)):
        state[i] = state[i][i:] + state[i][0: i]

def gmul(v):
    s = v << 1
    s &= 0xff
    if (v & 128) != 0:
        s = s ^ 0x1b
    return s

def mult_three(val, result=None):
    if result is None:
        return val ^ gmul(val)
    else:
        return val ^ gmul(result)

def mix_columns(state):
    mtx = []
    temp = []
    for i in range(4):
        temp.append(gmul(state[0][i]) ^ mult_three(state[1][i]) ^ state[2][i] ^  state[3][i])
    mtx.append(temp)
    temp = []
    for i in range(4):
        temp.append(state[0][i] ^ gmul(state[1][i]) ^ mult_three(state[2][i]) ^ state[3][i])
    mtx.append(temp)
    temp = []
    for i in range(4):
        temp.append(state[0][i] ^  state[1][i] ^ gmul(state[2][i]) ^ mult_three(state[3][i]))
    mtx.append(temp)
    temp = []
    for i in range(4):
        temp.append(mult_three(state[0][i]) ^ state[1][i] ^  state[2][i] ^ gmul(state[3][i]))
    mtx.append(temp)
    return mtx

def init_state(text):
    state = []
    for i in range (len(text)//4):
        state.append([text[i+4*j] for j in range(4)])
    return state

def _encrypt(text, key):
    assert len(text) % 16 == 0
    key_expand = key_expansion(key)
    state = init_state(text)
    adding_round_key(state, key_expand[0])
    for i in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        state = mix_columns(state)
        adding_round_key(state, key_expand[i])

    sub_bytes(state)
    shift_rows(state)
    adding_round_key(state, key_expand[-1])
    return convert_to_bytes(state)

def init_default_encryption(text, key):
    encrypt_data = []
    for i in range (0, len(text), 16):
        data = _encrypt(text[i:i+16], key)
        encrypt_data.extend(data)
    return encrypt_data

def init_cbc_encryption(text, iv, key):
    vector = convert_to_matrix(iv)
    encrypt_data = []
    for i in range (0, len(text), 16):
        txt_matrix = convert_to_matrix(text[i:i+16])
        adding_round_key(txt_matrix, vector)
        data = _encrypt(convert_to_list(txt_matrix), key)
        vector = convert_to_matrix(data)
        encrypt_data.extend(data)
    return encrypt_data

def shifted_register(encrypt_data, vector, current_idx, segment_size):
    vector = vector[segment_size:] + vector[0:segment_size]
    temp = encrypt_data[current_idx:current_idx + segment_size]
    vector = vector[0:16-segment_size] + temp
    return vector

def init_cfb_encryption(text, iv, key, segment_size):
    vector = convert_to_list(convert_to_matrix(iv))
    plain_text = convert_to_list(convert_to_matrix(text))
    for i in range(0, len(plain_text), segment_size):
        encrypt_data = _encrypt(vector, key)
        for j in range(segment_size):
            plain_text[i+j] ^= encrypt_data[j]
        vector = shifted_register(plain_text, vector, i, segment_size)
    return plain_text

def handle_encryption(text, mode):
    if mode == "cbc":
        encrypt_data = init_cbc_encryption(text, IV, AES_KEY)
    elif mode == "cfb":
        encrypt_data = init_cfb_encryption(text, IV, AES_KEY, 8)
    else:
        encrypt_data = init_default_encryption(text, AES_KEY)
    return encrypt_data

def encrypt(filename, mode):
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
    file = open("{}.b".format(filename), "wb")
    encrypt_data = handle_encryption(total_text_byte, mode)
    file.write(bytes(encrypt_data))
    file.close()

def inverse_shift_rows(state):
    for i in range(len(state)):
        state[i] = state[i][len(state[i])-i:] + state[i][0: len(state[i])-i]

def inverse_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_BOX[state[i][j]]

def inverse_mix_columns(state):
    mtx = []
    temp = []
    for i in range(4):
        res = gmul(mult_three(state[0][i], mult_three(state[0][i]))) ^ mult_three(state[1][i], mult_three(state[1][i], gmul(state[1][i]))) \
                ^ mult_three(state[2][i], gmul(mult_three(state[2][i]))) ^ mult_three(state[3][i], gmul(gmul(state[3][i])))
        temp.append(res)
    mtx.append(temp)
    temp = []
    for i in range(4):
        res = mult_three(state[0][i], gmul(gmul(state[0][i]))) ^ gmul(mult_three(state[1][i], mult_three(state[1][i]))) \
        ^ mult_three(state[2][i], mult_three(state[2][i], gmul(state[2][i]))) ^ mult_three(state[3][i], gmul(mult_three(state[3][i])))
        temp.append(res)
    mtx.append(temp)
    temp = []
    for i in range(4):
        res = mult_three(state[0][i], gmul(mult_three(state[0][i]))) ^ mult_three(state[1][i], gmul(gmul(state[1][i]))) \
        ^ gmul(mult_three(state[2][i], mult_three(state[2][i]))) ^ mult_three(state[3][i], mult_three(state[3][i], gmul(state[3][i]))) 
        temp.append(res)
    mtx.append(temp)
    temp = []
    for i in range(4):
        res = mult_three(state[0][i], mult_three(state[0][i], gmul(state[0][i]))) ^ mult_three(state[1][i], gmul(mult_three(state[1][i]))) \
            ^ mult_three(state[2][i], gmul(gmul(state[2][i]))) ^ gmul(mult_three(state[3][i], mult_three(state[3][i]))) 
        temp.append(res)
    mtx.append(temp)
    return mtx

def _decrypt(text, key):
    assert len(text) % 16 == 0
    key_expand = key_expansion(key)
    state = init_state(text)
    adding_round_key(state, key_expand[-1])
    
    for i in range(9, 0, -1):
        inverse_shift_rows(state)
        inverse_sub_bytes(state)
        adding_round_key(state, key_expand[i])
        state = inverse_mix_columns(state)
        
    inverse_shift_rows(state)
    inverse_sub_bytes(state)
    adding_round_key(state, key_expand[0])
    return convert_to_bytes(state)

def init_cbc_decryption(text, iv, key):
    padded_data = []
    vector = convert_to_matrix(iv)
    for i in range (0, len(text), 16):
        data = convert_to_matrix(text[i: i+16])
        decrypt_data = _decrypt(text[i: i+16], key)
        data_matrix = convert_to_matrix(decrypt_data)
        adding_round_key(data_matrix, vector)
        vector = data
        padded_data.extend(convert_to_list(data_matrix))
    return padded_data

def init_default_decryption(text, key):
    padded_data = []
    for i in range (0, len(text), 16):
        decrypt_data = _decrypt(text[i: i+16], key)
        padded_data.extend(decrypt_data)
    return padded_data

def init_cfb_decryption(text, iv, key, segment_size):
    vector = convert_to_list(convert_to_matrix(iv))
    text_matrix = convert_to_list(convert_to_matrix(text))
    decrypted_text = []
    for i in range(0, len(text_matrix), segment_size):
        encrypt_data = _encrypt(vector, key)
        for j in range(segment_size):
            decrypted_text.append(text_matrix[i+j] ^ encrypt_data[j])
        vector = shifted_register(text_matrix, vector, i, segment_size)
    return decrypted_text

def handle_decryption(text, mode):
    if mode == "cbc":
        decrypt_data = init_cbc_decryption(text, IV, AES_KEY)
    elif mode == "cfb":
        decrypt_data = init_cfb_decryption(text, IV, AES_KEY, 8)
    else:
        decrypt_data = init_default_decryption(text, AES_KEY)
    return decrypt_data

def decrypt (filename, mode):
    try:
        file = open(filename, 'rb')
        ct_bytes = file.read()
        file.close()
    except Exception as e:
        raise Exception('Error decrypting data')
    padded_data = handle_decryption(ct_bytes, mode)
    padding_len = padded_data[-1]
    total_text_byte = padded_data[:-padding_len]
    file = open(f"{filename[:-2]}.wb", "wb")
    file.write(bytes(total_text_byte))
    file.close()
    os.remove(os.path.abspath(filename))