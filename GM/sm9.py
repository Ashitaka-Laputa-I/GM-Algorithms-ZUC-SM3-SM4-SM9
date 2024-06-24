import binascii
from math import ceil, floor, log
from sm3 import sm3_key_derivation_function, sm3_hash
from random import SystemRandom
import optimized_curve as ec
import optimized_pairing as ate

FAILURE = False
SUCCESS = True


# 计算素域内的逆
def prime_field_inverse(a, n):
    """
    计算素域内元素的逆
    :param a: 被求逆元素
    :param n: 模数
    :return: 素域内元素的逆
    """
    if a == 0:
        return 0
    lm, hm = 1, 0  # 初始化 lm 和 hm
    low, high = a % n, n  # 初始化 low 和 high
    while low > 1:
        r = high // low  # 计算商
        nm, new = hm - lm * r, high - low * r  # 更新 nm 和 new
        lm, low, hm, high = nm, new, lm, low  # 交换 lm, low, hm 和 high
    return lm % n  # 返回结果


# 计算整数的二进制位长度
def bit_length(n):
    """
    计算整数的二进制位长度
    :param n: 整数
    :return: 二进制位长度
    """
    return floor(log(n, 2) + 1)  # 计算位长度


# 整数转换为定长字符串
def int_to_fixed_length_str(m, l):
    """
    整数转换为定长字符串
    :param m: 整数
    :param l: 长度
    :return: 定长字符串
    """
    format_m = ('%x' % m).zfill(l * 2).encode('utf-8')  # 将整数转换为定长字符串
    octets = [j for j in binascii.a2b_hex(format_m)]  # 转换为字节
    octets = octets[0:l]  # 截取前 l 个字节
    return ''.join(['%02x' % oc for oc in octets])  # 转换为字符串


# 有限域元素转换为字符串
def field_element_to_str(fe):
    """
    有限域元素转换为字符串
    :param fe: 有限域元素
    :return: 字符串
    """
    fe_str = ''.join(['%x' % c for c in fe.coeffs])  # 提取有限域元素的系数
    if (len(fe_str) % 2) == 1:
        fe_str = '0' + fe_str  # 补齐字符串长度
    return fe_str  # 返回结果


# 椭圆曲线点转换为字符串
def elliptic_curve_point_to_str(P):
    """
    椭圆曲线点转换为字符串
    :param P: 椭圆曲线点
    :return: 字符串
    """
    ec_str = ''.join([field_element_to_str(fe) for fe in P])  # 转换为字符串
    return ec_str  # 返回结果


# 字符串转换为十六进制字节数组
def string_to_hex_bytes(str_in):
    """
    字符串转换为十六进制字节数组
    :param str_in: 字符串
    :return: 十六进制字节数组
    """
    return [b for b in str_in.encode('utf-8')]  # 转换为字节数组


# 哈希到有限域元素
def hash_to_field_element(i, z, n):
    """
    哈希到有限域元素
    :param i: 整数索引
    :param z: 字节串
    :param n: 有限域的阶
    :return: 有限域元素
    """
    l = 8 * ceil((5 * bit_length(n)) / 32)  # 计算长度
    msg = int_to_fixed_length_str(i, 1).encode('utf-8')  # 转换索引为字符串
    ha = sm3_key_derivation_function(msg + z, l)  # 计算哈希值
    h = int(ha, 16)  # 转换为整数
    return (h % (n - 1)) + 1  # 返回有限域元素


# 初始化设置
def setup(scheme):
    """
    初始化设置
    :param scheme: 使用的方案
    :return: 公钥和私钥
    """
    P1 = ec.G2  # 初始化椭圆曲线点 P1
    P2 = ec.G1  # 初始化椭圆曲线点 P2

    rand_gen = SystemRandom()  # 随机数生成器
    s = rand_gen.randrange(ec.curve_order)  # 生成私钥

    if (scheme == 'sign'):  # 如果是签名方案
        Ppub = ec.multiply(P2, s)  # 计算公钥
        g = ate.pairing(P1, Ppub)  # 计算双线性对
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):  # 如果是密钥协商或加密方案
        Ppub = ec.multiply(P1, s)  # 计算公钥
        g = ate.pairing(Ppub, P2)  # 计算双线性对
    else:
        raise Exception('Invalid scheme')  # 抛出异常

    master_public_key = (P1, P2, Ppub, g)  # 构造主公钥
    return (master_public_key, s)  # 返回主公钥和主私钥


# 提取私钥
def extract_private_key(scheme, master_public, master_secret, identity):
    """
    提取私钥
    :param scheme: 使用的方案
    :param master_public: 主公钥
    :param master_secret: 主私钥
    :param identity: 用户身份标识
    :return: 用户私钥
    """
    P1 = master_public[0]  # 提取主公钥的P1
    P2 = master_public[1]  # 提取主公钥的P2

    user_id = sm3_hash(string_to_hex_bytes(identity))  # 计算用户ID的哈希值
    m = hash_to_field_element(1, (user_id + '01').encode('utf-8'), ec.curve_order)  # 计算有限域元素
    m = master_secret + m  # 计算中间值
    if (m % ec.curve_order) == 0:  # 检查中间值是否为零
        return FAILURE  # 返回失败
    m = master_secret * prime_field_inverse(m, ec.curve_order)  # 计算私钥

    if (scheme == 'sign'):  # 如果是签名方案
        Da = ec.multiply(P1, m)  # 计算用户私钥
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):  # 如果是密钥协商或加密方案
        Da = ec.multiply(P2, m)  # 计算用户私钥
    else:
        raise Exception('Invalid scheme')  # 抛出异常

    return Da  # 返回用户私钥


# 提取公钥
def extract_public_key(scheme, master_public, identity):
    """
    提取公钥
    :param scheme: 使用的方案
    :param master_public: 主公钥
    :param identity: 用户身份标识
    :return: 用户公钥
    """
    P1, P2, Ppub, g = master_public  # 提取主公钥

    user_id = sm3_hash(string_to_hex_bytes(identity))  # 计算用户ID的哈希值
    h1 = hash_to_field_element(1, (user_id + '01').encode('utf-8'), ec.curve_order)  # 计算有限域元素

    if (scheme == 'sign'):  # 如果是签名方案
        Q = ec.multiply(P2, h1)  # 计算用户公钥
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):  # 如果是密钥协商或加密方案
        Q = ec.multiply(P1, h1)  # 计算用户公钥
    else:
        raise Exception('Invalid scheme')  # 抛出异常

    Q = ec.add(Q, Ppub)  # 计算最终公钥

    return Q  # 返回用户公钥


# 签名
def sign(master_public, Da, msg):
    """
    签名
    :param master_public: 主公钥
    :param Da: 用户私钥
    :param msg: 消息
    :return: 签名
    """
    g = master_public[3]  # 提取主公钥中的g

    rand_gen = SystemRandom()  # 随机数生成器
    x = rand_gen.randrange(ec.curve_order)  # 生成随机数
    w = g ** x  # 计算 w

    msg_hash = sm3_hash(string_to_hex_bytes(msg))  # 计算消息哈希值
    z = (msg_hash + field_element_to_str(w

                                         )).encode('utf-8')  # 构造 z
    h = hash_to_field_element(2, z, ec.curve_order)  # 计算 h
    l = (x - h) % ec.curve_order  # 计算 l

    S = ec.multiply(Da, l)  # 计算签名 S
    return (h, S)  # 返回签名


# 验证签名
def verify(master_public, identity, msg, signature):
    """
    验证签名
    :param master_public: 主公钥
    :param identity: 用户身份标识
    :param msg: 消息
    :param signature: 签名
    :return: 验证结果
    """
    (h, S) = signature  # 提取签名

    if (h < 0) | (h >= ec.curve_order):  # 检查 h 的合法性
        return FAILURE  # 返回失败
    if not ec.is_on_curve(S, ec.b2):  # 检查 S 是否在曲线上
        return FAILURE  # 返回失败

    Q = extract_public_key('sign', master_public, identity)  # 提取用户公钥

    g = master_public[3]  # 提取主公钥中的 g
    u = ate.pairing(S, Q)  # 计算 u
    t = g ** h  # 计算 t
    wprime = u * t  # 计算 w'

    msg_hash = sm3_hash(string_to_hex_bytes(msg))  # 计算消息哈希值
    z = (msg_hash + field_element_to_str(wprime)).encode('utf-8')  # 构造 z
    h2 = hash_to_field_element(2, z, ec.curve_order)  # 计算 h2

    if h != h2:  # 检查 h 和 h2 是否相等
        return FAILURE  # 返回失败
    return SUCCESS  # 返回成功


# 生成临时密钥
def generate_ephemeral_key(master_public, identity):
    """
    生成临时密钥
    :param master_public: 主公钥
    :param identity: 用户身份标识
    :return: 临时密钥
    """
    Q = extract_public_key('keyagreement', master_public, identity)  # 提取用户公钥

    rand_gen = SystemRandom()  # 随机数生成器
    x = rand_gen.randrange(ec.curve_order)  # 生成随机数
    R = ec.multiply(Q, x)  # 计算临时密钥

    return (x, R)  # 返回临时密钥


# 生成会话密钥
def generate_session_key(idA, idB, Ra, Rb, D, x, master_public, entity, l):
    """
    生成会话密钥
    :param idA: 实体A的标识
    :param idB: 实体B的标识
    :param Ra: 实体A的临时密钥
    :param Rb: 实体B的临时密钥
    :param D: 实体的私钥
    :param x: 临时私钥
    :param master_public: 主公钥
    :param entity: 实体标识
    :param l: 密钥长度
    :return: 会话密钥
    """
    P1, P2, Ppub, g = master_public  # 提取主公钥

    if entity == 'A':
        R = Rb  # 如果实体是A，则R为Rb
    elif entity == 'B':
        R = Ra  # 如果实体是B，则R为Ra
    else:
        raise Exception('Invalid entity')  # 抛出异常

    g1 = ate.pairing(R, D)  # 计算 g1
    g2 = g ** x  # 计算 g2
    g3 = g1 ** x  # 计算 g3

    if entity == 'B':
        (g1, g2) = (g2, g1)  # 如果实体是B，则交换 g1 和 g2

    uidA = sm3_hash(string_to_hex_bytes(idA))  # 计算实体A的哈希值
    uidB = sm3_hash(string_to_hex_bytes(idB))  # 计算实体B的哈希值

    kdf_input = uidA + uidB  # 构造KDF输入
    kdf_input += elliptic_curve_point_to_str(Ra) + elliptic_curve_point_to_str(Rb)  # 添加Ra和Rb
    kdf_input += field_element_to_str(g1) + field_element_to_str(g2) + field_element_to_str(g3)  # 添加g1, g2, g3

    session_key = sm3_key_derivation_function(kdf_input.encode('utf-8'), l)  # 生成会话密钥

    return session_key  # 返回会话密钥


# 加密

def key_encapsulation_mechanism_encap(master_public, identity, l):
    """
    密钥封装
    :param master_public: 主公钥
    :param identity: 用户身份标识
    :param l: 密钥长度
    :return: 密钥和密文
    """
    P1, P2, Ppub, g = master_public  # 提取主公钥

    Q = extract_public_key('encrypt', master_public, identity)  # 提取用户公钥

    rand_gen = SystemRandom()  # 随机数生成器
    x = rand_gen.randrange(ec.curve_order)  # 生成随机数

    C1 = ec.multiply(Q, x)  # 计算密文 C1
    t = g ** x  # 计算 t

    uid = sm3_hash(string_to_hex_bytes(identity))  # 计算用户ID的哈希值
    kdf_input = elliptic_curve_point_to_str(C1) + field_element_to_str(t) + uid  # 构造KDF输入
    k = sm3_key_derivation_function(kdf_input.encode('utf-8'), l)  # 生成密钥

    return (k, C1)  # 返回密钥和密文


def key_encapsulation_mechanism_decap(master_public, identity, D, C1, l):
    """
    密钥解封
    :param master_public: 主公钥
    :param identity: 用户身份标识
    :param D: 用户私钥
    :param C1: 密文
    :param l: 密钥长度
    :return: 密钥
    """
    if not ec.is_on_curve(C1, ec.b2):  # 检查 C1 是否在曲线上
        return FAILURE  # 返回失败

    t = ate.pairing(C1, D)  # 计算 t

    uid = sm3_hash(string_to_hex_bytes(identity))  # 计算用户ID的哈希值
    kdf_input = elliptic_curve_point_to_str(C1) + field_element_to_str(t) + uid  # 构造KDF输入
    k = sm3_key_derivation_function(kdf_input.encode('utf-8'), l)  # 生成密钥

    return k  # 返回密钥


# 混合加密
def kem_dem_encrypt(master_public, identity, message, v):
    """
    混合加密
    :param master_public: 主公钥
    :param identity: 用户身份标识
    :param message: 消息
    :param v: 验证码长度
    :return: 密文
    """
    hex_msg = string_to_hex_bytes(message)  # 将消息转换为十六进制字节
    mbytes = len(hex_msg)  # 计算消息字节数
    mbits = mbytes * 8  # 计算消息比特数

    k, C1 = key_encapsulation_mechanism_encap(master_public, identity, mbits + v)  # 进行密钥封装
    k = string_to_hex_bytes(k)  # 转换密钥为十六进制字节
    k1 = k[:mbytes]  # 分割密钥
    k2 = k[mbytes:]  # 分割密钥

    C2 = []
    for i in range(mbytes):
        C2.append(hex_msg[i] ^ k1[i])  # 计算 C2

    hash_input = C2 + k2  # 构造哈希输入
    C3 = sm3_hash(hash_input)[:int(v / 8)]  # 计算 C3

    return (C1, C2, C3)  # 返回密文


def kem_dem_decrypt(master_public, identity, D, ct, v):
    """
    混合解密
    :param master_public: 主公钥
    :param identity: 用户身份标识
    :param D: 用户私钥
    :param ct: 密文
    :param v: 验证码长度
    :return: 明文
    """
    C1, C2, C3 = ct  # 提取密文

    mbytes = len(C2)  # 计算消息字节数
    l = mbytes * 8 + v  # 计算长度

    k = key_encapsulation_mechanism_decap(master_public, identity, D, C1, l)  # 进行密钥解封

    k = string_to_hex_bytes(k)  # 转换密钥为十六进制字节
    k1 = k[:mbytes]  # 分割密钥
    k2 = k[mbytes:]  # 分割密钥

    hash_input = C2 + k2  # 构造哈希输入
    C3prime = sm3_hash(hash_input)[:int(v / 8)]  # 计算 C3'

    if C3 != C3prime:  # 检查 C3 和 C3' 是否相等
        return FAILURE  # 返回失败

    pt = []
    for i in range(mbytes):
        pt.append(chr(C2[i] ^ k1[i]))  # 计算明文

    message = ''.join(pt)  # 生成明文

    return message  # 返回明文


if __name__ == '__main__':
    # 加密 "2024liuhaoran"
    master_public, master_secret = setup('encrypt')
    identity = "2024liuhaoran"
    Da = extract_private_key('encrypt', master_public, master_secret, identity)
    encrypted_data = kem_dem_encrypt(master_public, identity, identity, 16)

    print("Encrypted data:", encrypted_data)

    # 解密加密的数据
    decrypted_message = kem_dem_decrypt(master_public, identity, Da, encrypted_data, 16)

    print("Decrypted message:", decrypted_message)
