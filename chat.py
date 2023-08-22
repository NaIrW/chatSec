from Crypto.Util.number import *
from hashlib import sha256
from db import DB
from sympy.ntheory.residue_ntheory import _sqrt_mod_prime_power
from sympy.ntheory import is_quad_residue


class EllipticCurvePoint:
    def __init__(self, point, ainvs, p, n=None):
        if point[0] is not None:
            self.x = point[0] % p
        else:
            self.x = None
        if point[1] is not None:
            self.y = point[1] % p
        else:
            self.y = None
        self.ainvs = ainvs
        if len(ainvs) == 2:
            self.a1 = 0
            self.a2 = 0
            self.a3 = 0
            self.a4 = ainvs[0]
            self.a6 = ainvs[1]
        elif len(ainvs) == 5:
            self.a1 = ainvs[0]
            self.a2 = ainvs[1]
            self.a3 = ainvs[2]
            self.a4 = ainvs[3]
            self.a6 = ainvs[4]
        self.p = p
        self.n = n
        assert self.is_on_curve()

    def is_on_curve(self):
        if self.x is None and self.y is None:
            return True
        x, y = self.x, self.y
        return (y * y + self.a1 * x * y + self.a3 * y - x * x * x - self.a2 * x * x - self.a4 * x - self.a6) % self.p == 0

    def __neg__(self):
        assert self.is_on_curve()
        if self.x is None and self.y is None:
            return EllipticCurvePoint((None, None), self.ainvs, self.p)
        x, y = self.x, self.y
        return EllipticCurvePoint((x, (-y - self.a1 * x - self.a3) % self.p), self.ainvs, self.p)

    def __sub__(self, other):
        return self.__add__(-other)

    def __add__(self, other):
        assert self.ainvs == other.ainvs and self.p == other.p
        if self.x is None and self.y is None:
            return other
        if other.x is None and other.y is None:
            return self
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        if x1 == x2 and y1 == (-y2 - self.a1 * x2 - self.a3) % self.p:
            return EllipticCurvePoint((None, None), self.ainvs, self.p)
        if x1 == x2 and y1 == y2:
            m = (3 * x1 * x1 + 2 * self.a2 * x1 + self.a4 - self.a1 * y1) * inverse(2 * y1 + self.a1 * x1 + self.a3, self.p)
        else:
            m = (y1 - y2) * inverse(x1 - x2, self.p)
        x3 = -x1 - x2 - self.a2 + m * (m + self.a1)
        y3 = -y1 - self.a3 - self.a1 * x3 + m * (x1 - x3)
        return EllipticCurvePoint((x3, y3), self.ainvs, self.p)

    def __mul__(self, k):
        if k < 0:
            return -k * -self
        result = EllipticCurvePoint((None, None), self.ainvs, self.p)
        addend = self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def __rmul__(self, other):
        return self * other

    def __str__(self):
        return f'({self.x}, {self.y})'

    def hex(self):
        return '{:064x}{:064x}'.format(self.x, self.y)


class EllipticCurve:
    def __init__(self, ainvs, p):
        assert isPrime(p)
        self.ainvs = [each % p for each in ainvs]
        self.p = p

    def __call__(self, point, n=None):
        return EllipticCurvePoint(point, self.ainvs, self.p, n)

    def fromHex(self, point):
        return self.__call__((int(point[:64], 16), int(point[64:], 16)))


# secp256k1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
q = n
E = EllipticCurve([a, b], p)
G = E(G, n)

square = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17
sqrt = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c


def randPoint():
    x = getRandomRange(2, n)
    return x, x * G


def Hash(msg):
    return sha256(msg.encode()).hexdigest().encode()


def nizkPoK(point, sk):
    r = getRandomRange(2, q)
    R = r * G
    c = int(Hash(point.hex() + R.hex()), 16)
    z = r + c * sk
    return R.hex() + hex(z % q)[2:]


def verifzk(nizk, point):
    R, z = E.fromHex(nizk[:128]), int(nizk[128:], 16)
    c = int(Hash(point.hex() + R.hex()), 16)
    return (z * G).hex() == (R + c * point).hex()


def encrypt(pk, msg):
    assert len(msg) <= 31
    msg = bytes_to_long(msg) << 8
    for _ in range(256):
        x = msg + _
        y2 = (x**3 + a * x + b) % p
        if pow(y2, square, p) == 1:
            y = pow(y2, sqrt, p)
            msg = E((x, y), n)
            break
    else:
        raise RuntimeError
    r, c1 = randPoint()
    c2 = r * pk + msg
    return c1.hex(), c2.hex()


def decrypt(sk, c1, c2, embed=True):
    c1 = E.fromHex(c1)
    c2 = E.fromHex(c2)
    if embed:
        msg = long_to_bytes((c2 - sk * c1).x >> 8)
    else:
        msg = long_to_bytes((c2 - sk * c1).x)
    return msg


def handleChat(item_dict):
    db = DB('chatSecret.msg')
    try:
        action = item_dict['action']
        if action == 'SENDMSG':
            pk = E.fromHex(item_dict['pk'])
            nizk = item_dict['nizk']
            assert verifzk(nizk, pk)
            to = E.fromHex(item_dict['to'])
            c1 = E.fromHex(item_dict['c1'])
            c2 = E.fromHex(item_dict['c2'])
            db.insert({
                'from': pk.hex(),
                'to': to.hex(),
                'c1': c1.hex(),
                'c2': c2.hex()
            })
            return {'msg': 'ok'}

        elif action == 'RECVMSG':
            pk = E.fromHex(item_dict['pk'])
            nizk = item_dict['nizk']
            assert verifzk(nizk, pk)
            msgs = [*db.db.find({'to': pk.hex()})]
            for each in msgs:
                db.delete(each['_id'])
            msgs = [{
                'from':_['from'],
                'c1': _['c1'],
                'c2': _['c2']
            } for _ in msgs]
            return {
                'msg': 'ok',
                'msgs': msgs
            }
    except KeyError:
        return {'msg': 'ERROR'}
    except AssertionError:
        return {'msg': '?'}
