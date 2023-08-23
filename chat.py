from Crypto.Util.number import *
from hashlib import sha256
from db import DB
import ctypes


lib = ctypes.CDLL('./secp256k1.so')
lib.init_secp256_lib()

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
