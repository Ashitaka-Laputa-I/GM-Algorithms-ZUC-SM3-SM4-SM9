import binascii
from math import ceil

# 初始向量
INITIAL_VECTOR = [
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
]

# 常量 T_j
CONSTANT_T = [
                 2043430169] * 16 + [2055708042] * 48


# 循环左移函数
def rotate_left(x, n):
    """对x进行循环左移n位"""
    return ((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)


# 定义布尔函数 FF
def boolean_function_FF(x, y, z, j):
    """定义布尔函数FF"""
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret


# 定义布尔函数 GG
def boolean_function_GG(x, y, z, j):
    """定义布尔函数GG"""
    if 0 <= j < 16:
        ret = x ^ y ^ z
    elif 16 <= j < 64:
        ret = (x & y) | ((~ x) & z)
    return ret


# 定义置换函数 P0
def permutation_function_P0(x):
    """定义置换函数P0"""
    return x ^ (rotate_left(x, 9 % 32)) ^ (rotate_left(x, 17 % 32))


# 定义置换函数 P1
def permutation_function_P1(x):
    """定义置换函数P1"""
    return x ^ (rotate_left(x, 15 % 32)) ^ (rotate_left(x, 23 % 32))


# CF函数
def sm3_compress(v_i, b_i):
    """定义CF函数"""
    w = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i * 4, (i + 1) * 4):
            data = data + b_i[k] * weight
            weight = int(weight / 0x100)
        w.append(data)

    for j in range(16, 68):
        w.append(0)
        w[j] = permutation_function_P1(w[j - 16] ^ w[j - 9] ^ (rotate_left(w[j - 3], 15 % 32))) ^ (
            rotate_left(w[j - 13], 7 % 32)) ^ w[j - 6]

    w_1 = []
    for j in range(64):
        w_1.append(0)
        w_1[j] = w[j] ^ w[j + 4]

    a, b, c, d, e, f, g, h = v_i

    for j in range(64):
        ss_1 = rotate_left((rotate_left(a, 12 % 32) + e + rotate_left(CONSTANT_T[j], j % 32)) & 0xffffffff, 7 % 32)
        ss_2 = ss_1 ^ (rotate_left(a, 12 % 32))
        tt_1 = (boolean_function_FF(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
        tt_2 = (boolean_function_GG(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
        d = c
        c = rotate_left(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = rotate_left(f, 19 % 32)
        f = e
        e = permutation_function_P0(tt_2)

        a, b, c, d, e, f, g, h = map(
            lambda x: x & 0xFFFFFFFF, [a, b, c, d, e, f, g, h])

    v_j = [a, b, c, d, e, f, g, h]
    return [v_j[i] ^ v_i[i] for i in range(8)]


# SM3哈希函数
def sm3_hash(message):
    """计算SM3哈希值"""
    length = len(message)
    reserve = length % 64
    message.append(0x80)
    reserve = reserve + 1

    range_end = 56
    if reserve > range_end:
        range_end = range_end + 64

    for i in range(reserve, range_end):
        message.append(0x00)

    bit_length = (length) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        message.append(bit_length_str[7 - i])

    group_count = round(len(message) / 64)

    blocks = []
    for i in range(group_count):
        blocks.append(message[i * 64:(i + 1) * 64])

    V = []
    V.append(INITIAL_VECTOR)
    for i in range(group_count):
        V.append(sm3_compress(V[i], blocks[i]))

    y = V[i + 1]
    result = ""
    for num in y:
        result = '%s%08x' % (result, num)
    return result


# 定义SM3密钥派生函数
def sm3_key_derivation_function(z, key_length):
    """使用SM3进行密钥派生"""
    key_length = int(key_length)
    count = 0x00000001
    rounds = ceil(key_length / 32)
    z_bytes = [i for i in bytes.fromhex(z.decode('utf8'))]
    derived_key = ""
    for i in range(rounds):
        msg = z_bytes + [i for i in binascii.a2b_hex(('%08x' % count).encode('utf8'))]
        derived_key += sm3_hash(msg)
        count += 1
    return derived_key[0: key_length * 2]


if __name__ == '__main__':
    # 要哈希的消息
    message = '202420213004426liuhaoran'

    # 将消息转换为字节数组
    message_bytes = bytearray(message, 'utf-8')

    # 使用SM3哈希函数进行哈希
    hash_result = sm3_hash(message_bytes)

    # 打印哈希结果
    print(f'哈希结果: {hash_result}')
