import bitcoin
import common

def test_ecc_mul():
    G1 = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    G2 = common.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    G1 = G1 * 1337
    G2 = G2 * 1337

    G1 = common.Point(G1.x, G1.y)
    assert G1 == G2

def test_encode_small_point():
    G1 = bitcoin.Point(
        x = 5,
        y = 6
    )

    G2 = common.Point(
        x = 5,
        y = 6
    )

    assert len(G1.encode()) == len(G2.encode())
    assert G1.encode() == G2.encode()

def test_encode_big_point():
    G1 = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    G2 = common.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    assert len(G1.encode()) == len(G2.encode())
    assert G1.encode() == G2.encode()

    G1 = G1 * 123
    G2 = G2 * 123

    assert len(G1.encode()) == len(G2.encode())
    assert G1.encode() == G2.encode()

    G1 = G1 * 123
    G2 = G2 * 123

    assert len(G1.encode()) == len(G2.encode())
    assert G1.encode() == G2.encode()


def test_encode_decode_point():
    p = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    q = bitcoin.Point.decode(p.encode())

    assert p.x == q.x
    assert p.y == q.y

    p = p * 123

    q = bitcoin.Point.decode(p.encode())

    assert p.x == q.x
    assert p.y == q.y


def test_generate_bitcoin_addr():
    # Generator point
    G = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    secret_key = int.from_bytes(b'Hello world', 'big')
    public_key = G * secret_key

    # Generate our bitcoin address
    address = public_key.address()

    assert address == 'mtuFXC3oACRqVMMqN32L5VG7ZCbaE7aZxi'

def test_encode_output_script():
    secret_key = int.from_bytes(b'Hello world', 'big')
    public_key = common.G * secret_key

    s1 = common.Script([
        common.Opcode.DUP, 
        common.Opcode.HASH160, 
        common.hash160(public_key.encode()),
        common.Opcode.EQUALVERIFY, 
        common.Opcode.CHECKSIG
    ])

    G = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    secret_key = int.from_bytes(b'Hello world', 'big')
    public_key = G * secret_key

    s2 = bitcoin.Script([118, 169, bitcoin.hash160(public_key.encode()), 136, 172])

    assert s1.encode() == s2.encode()

def test_decode_sig():
    sig_bin = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')[:-1]

    sig1 = common.Signature.decode(sig_bin)
    sig2 = bitcoin.Signature.decode(sig_bin)

    assert sig1.r == sig2.r
    assert sig1.s == sig2.s

    assert sig_bin == common.Signature.decode(sig_bin).encode()

def test_evaluate_script():
    # Programming Bitcoin - page 115
    z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
    sec = bytes.fromhex('02887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c')
    sig = bytes.fromhex('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601')
    
    script_pubkey = bitcoin.Script([sec, 0xac]) # 0xac = 172 = OP_CHECKSIG
    script_sig = bitcoin.Script([sig])
    combined_script = script_sig + script_pubkey

    # check for successful sig verification
    equal_script = bitcoin.Script([b'\x01', 136])
    combined_script = combined_script + equal_script

    assert combined_script.evaluate(z)
