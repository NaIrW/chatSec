from Crypto.Util.number import *
from hashlib import sha256
from db import DB
import ctypes


lib = ctypes.CDLL('./secp256k1.so')

lib.scalar_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.scalar_multiplication.restype = ctypes.c_int

lib.point_multiplication.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.point_multiplication.restype = ctypes.c_int

lib.point_addition.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.point_addition.restype = ctypes.c_int

lib.init_secp256_lib()


pqlib = ctypes.CDLL('./pq-crystals.so')

pqlib.kem_key.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
pqlib.kem_key.restype = ctypes.c_int

pqlib.kem_enc.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
pqlib.kem_enc.restype = ctypes.c_int

pqlib.kem_dec.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
pqlib.kem_dec.restype = ctypes.c_int

pqlib.sign_key.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
pqlib.sign_key.restype = ctypes.c_int

pqlib.sign.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
pqlib.sign.restype = ctypes.c_int

pqlib.verify.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
pqlib.verify.restype = ctypes.c_int

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def kG(k):
    res = b'\x00' * 65
    k = hex(k)[2:].zfill(64).encode('ascii')
    lib.scalar_multiplication(k, res)
    return bytes(bytearray(res))


def kP(k, P):
    res = b'\x00' * 65
    k = k.to_bytes(32, 'big')
    lib.point_multiplication(P, k, res)
    return bytes(bytearray(res))


def add(P, Q):
    res = b'\x00' * 65
    lib.point_addition(P, Q, res)
    return bytes(bytearray(res))


def randPoint():
    x = getRandomRange(2, n)
    return x, kG(x)


def Hash(msg):
    return sha256(msg).hexdigest()


def nizkPoK(point, sk):
    r, R = randPoint()
    c = int(Hash(point + R), 16)
    z = r + c * sk
    return R.hex() + hex(z % n)[2:]


def verifzk(nizk, point):
    R, z = bytes.fromhex(nizk[:130]), int(nizk[130:], 16)
    c = int(Hash(point + R), 16)
    return kG(z) == add(R, kP(c, point))


def kem_keypair():
    pk, sk = b''.zfill(1568), b''.zfill(3168)
    pqlib.kem_key(pk, sk)
    pk, sk = bytes(bytearray(pk)), bytes(bytearray(sk))
    return pk, sk


def enc(pk):
    ct = b''.zfill(1568)
    ss = b''.zfill(32)
    pqlib.kem_enc(ct, ss, pk)
    ss, ct = bytes(bytearray(ss)), bytes(bytearray(ct))
    return ss, ct


def dec(ct, sk):
    ano = b''.zfill(32)
    pqlib.kem_dec(ano, ct, sk)
    return bytes(bytearray(ano))


def sign_keypair():
    pk, sk = b''.zfill(2592), b''.zfill(4864)
    pqlib.sign_key(pk, sk)
    pk, sk = bytes(bytearray(pk)), bytes(bytearray(sk))
    return pk, sk


def sign(m, sk):
    sig = b''.zfill(4595)
    pqlib.sign(sig, 4595, m, len(m), sk)
    return bytes(bytearray(sig))


def verify(sig, m, pk):
    return pqlib.verify(sig, 4595, m, len(m), pk) == 0


def handleChat(item_dict):
    db = DB('chatSecret.msg')
    try:
        action = item_dict['action']
        if action == 'SENDMSG':
            pk, nizk, to, c = map(item_dict.__getitem__, ['pk', 'nizk', 'to', 'c'])
            assert verifzk(nizk, bytes.fromhex(pk))
            db.insert({'from': pk, 'to': to, 'c': c})
            return {'msg': 'ok'}

        elif action == 'RECVMSG':
            pk, nizk = map(item_dict.__getitem__, ['pk', 'nizk'])
            assert verifzk(nizk, bytes.fromhex(pk))
            msgs = [*db.db.find({'to': pk})]
            [db.delete(_['_id']) for _ in msgs]
            msgs = [{'from':_['from'], 'c': _['c']} for _ in msgs]
            return {'msg': 'ok', 'msgs': msgs}
    except KeyError:
        return {'msg': 'ERROR'}
    except AssertionError:
        return {'msg': '?'}
