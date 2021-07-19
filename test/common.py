# rough copy of: http://karpathy.github.io/2021/06/21/blockchain/

from dataclasses import dataclass
from enum import Enum
import hashlib
from functools import singledispatch
import random

## Bitcoin constants
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# the order of the elliptic curve used in bitcoin
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
TESTNET = b'\x6f'
b58alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# ===== Utility encoding functions =====

def b58encode(b: bytes) -> str:
    assert len(b) == 25 # version is 1 byte, pkb_hash 20 bytes, checksum 4 bytes
    origlen, newlen = len(b), len(b.lstrip(b'\0'))

    string = ''
    n = int.from_bytes(b, byteorder='big')
    while n:
        n, idx = divmod(n, 58)
        string = b58alphabet[idx] + string

    return '1' * (origlen - newlen) + string

def sha256(b: bytes):
    return hashlib.new("sha256", b).digest()

def ripemd160(b: bytes):
    return hashlib.new("ripemd160", b).digest()


@dataclass
class Point:
    """ An integer point (x,y) on a Curve """
    x: int
    y: int

    def add(self, other):
        """elliptic cruve addition
        """
        # handle special case of P + 0 = 0 + P = 0
        if self == INF:
            return other
        if other == INF:
            return self
        # handle special case of P + (-P) = 0
        if self.x == other.x and self.y != other.y:
            return INF
        if self.x == other.x:
            m = (3 * self.x**2) * pow(2 * self.y, -1, P)
        else:
            m = (self.y - other.y) * pow(self.x - other.x, -1, P)

        rx = (m**2 - self.x - other.x) % P
        ry = (-(m*(rx - self.x) + self.y)) % P

        return Point(rx, ry)

    def __mul__(self, k):
        """double and add - optimization for adding G 
        to itself a very large number of times
        """
        assert isinstance(k, int) and k >= 0
        result = INF
        while k:
            if k % 2 == 1: 
                result = self.add(result)

            self = self.add(self)
            k >>= 1
        return result
    __rmul__ = __mul__

    def encode(self):
        """ return the SEC bytes encoding of the point, compressed by default """
        prefix = [b'\x02', b'\x03'][self.y % 2]
        return prefix + self.x.to_bytes(32, 'big') # little ?

    def address(self):
        """ return the associated bitcoin address for this point """

        # encode pk into bytes with the prepended version (0x6f for test network)
        pkb_hash = TESTNET + ripemd160(sha256(self.encode()))

        checksum = sha256(sha256(pkb_hash))[:4]

        # append to get the full 25-byte bitcoin address
        byte_address = pkb_hash + checksum

        # return the b58 encoded address
        return b58encode(byte_address)


INF = Point(None, None)

# Generator point
G = Point(
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
)

class Opcode(Enum):
    DUP = 118
    HASH160 = 169
    EQUALVERIFY = 136
    CHECKSIG = 172

    def encode(self):
        return self.value.to_bytes(1, 'little')

@singledispatch
def encode(arg):
    raise NotImplementedError

@encode.register
def _(arg: Opcode):
    return arg.encode()

@encode.register
def _(arg: int):
    out = arg.to_bytes((arg.bit_length() + 7) // 8, 'little')
    return out

@encode.register
def _(arg: bytes):
    return len(arg).to_bytes(1, 'little') + arg

@dataclass
class Script:
    cmds: list

    ops = {
        Opcode.HASH160: lambda x: ripemd160(sha256(x))
    }

    def encode(self):
        out = b''
        cmds = iter(self.cmds)
        for cmd in cmds:
            out += encode(cmd)
            if cmd in self.ops:
                out += encode(self.ops[cmd](next(cmds)))

        return encode(len(out)) + out 

@dataclass
class TxIn:
    prev_tx: bytes # prev transaction ID: hash256 of prev tx contents (UTXO) (32 bytes)
    prev_index: int # the index number of the UTXO to be spent (4 bytes)
    sequence: int = 0xffffffff # originally intended for "high frequency trades", with locktime (4 bytes)
    script_sig: Script = None # unlocking script that fulfills the coditions of the UTXO locking script

    def encode(self):
        out = b''
        out += self.prev_tx[::-1] # little endian vs big endian encodings (reverse byte order)
        out += self.prev_index.to_bytes(4, 'little') # The index number of the UTXO to be spent; first one is 0

        # Either script_sig (unlocking script) or prev_tx_script_pubkey
        out += self.script_sig.encode()

        out += self.sequence.to_bytes(4, 'little') # Used for locktime or disabled (0xFFFFFFFF)
        return out

@dataclass
class TxOut:
    amount: int # in units of satoshi (1e-8 of a bitcoin) (8 bytes)
    script_pubkey: Script = None # locking script defining the conditions needed to spend the output

    def encode(self):
        out = b''
        out += self.amount.to_bytes(8, 'little')
        out += self.script_pubkey.encode()
        return out

@dataclass
class Tx:
    version: int
    tx_ins: list # vin
    tx_outs: list # vout
    locktime: int = 0

    def encode(self, sighash=False) -> bytes:
        out = b''
        # encode metadata
        out += self.version.to_bytes(4, 'little')

        # encode inputs
        out += encode(len(self.tx_ins))
        out += b''.join(tx_in.encode() for tx_in in self.tx_ins)

        # encode outputs
        out += encode(len(self.tx_outs))
        out += b''.join(tx_out.encode() for tx_out in self.tx_outs)

        # encode locktime
        out += self.locktime.to_bytes(4, 'little')

        if sighash:
            out += int.to_bytes(1, 4, 'little') # 1 = SIGHASH_ALL
        return out

    def id(self) -> str:
        return sha256(sha256(self.encode()))[::-1].hex() # little/big endian conventions require byte order swap

@dataclass
class Signature:
    r: int
    s: int

    def encode(self) -> bytes:
        """ return the DER encoding of this signature """

        rb = self.r.to_bytes(32, byteorder='big')
        if rb[1] < 0x80:
            rb = rb.lstrip(b'\x00') # strip leading zeros

        sb = self.s.to_bytes(32, byteorder='big')
        if sb[1] < 0x80:
            sb = sb.strip(b'\x00') # strip leading zeros

        out = b''
        # indicates the start of a DER sequence
        out += b'\x30'
        sequence = b'\x02' # an integer value follows
        sequence += bytes([len(rb)]) # the length of the integer
        sequence += rb
        sequence += b'\x02' # another integer follows
        sequence += bytes([len(sb)]) # the length of the integer
        sequence += sb
        # the length of the sequence
        out += bytes([len(sequence)])
        # the actual sequence
        out += sequence
        # A suffix indicating the type of hash used (SIGHASH_ALL)
        #out += b'\x01'
        return out

    @classmethod
    def sign(cls, secret_key: int, message: bytes):
        """ sign using ECDSA """

        # double hash the message and convert to integer
        z = int.from_bytes(sha256(sha256(message)), 'big')

        # generate a new secret/public key pair at random
        sk = random.randrange(1, n)
        P = G * sk

        # calculate the signature
        r = P.x
        s = pow(sk, -1, n) * (z + secret_key * r) % n
        if s > n / 2:
            s = n - s

        sig = cls(r, s)
        return sig

# Broadcast transaction: https://blockstream.info/testnet/tx/push