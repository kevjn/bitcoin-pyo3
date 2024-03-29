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

def test_encode_input_transaction():
    G = bitcoin.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    secret_key = int.from_bytes(b'Test', 'big')
    public_key = G * secret_key

    source_script = bitcoin.Script([
        118,
        169,
        bitcoin.hash160(public_key.encode()),
        136,
        172
    ])
 
    tx_in = bitcoin.TxIn(
        prev_tx = bytes.fromhex('46325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2')[::-1],
        prev_idx = 1,
        script_sig = source_script
    )

    assert tx_in.encode().hex() == 'b2364d6ba4cbfd3dad8d6dc8dde1095f959bac4ee4ee7c4b8ab99fc885503246010000001976a91483ff579e048aee325a2cfa8b00c27581f8c7302988acffffffff'

def test_encode_transaction():
    common = bitcoin

    G = common.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    secret_key = int.from_bytes(b'test secret', 'big')
    public_key = G * secret_key

    secret_key2 = int.from_bytes(b"test secret2", 'big')
    public_key2 = G * secret_key2
    
    source_script = common.Script([
        118,
        169, # operation
        common.hash160(public_key.encode()), # element
        136,
        172
    ])

    tx_in = common.TxIn(
        prev_tx = bytes.fromhex('46325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2')[::-1],
        prev_idx = 1,
        script_sig = source_script, # this field will later have the digital signature
    )

    tx_out1 = common.TxOut(
        amount = 50000, # we will send this 50,000 sat to our target wallet
        script_pubkey = common.Script([
            118,
            169,
            common.hash160(public_key2.encode()),
            136,
            172
        ])
    )

    tx_out2 = common.TxOut(
        amount = 47500, # back to us
        script_pubkey = common.Script([
            118,
            169,
            common.hash160(public_key.encode()),
            136,
            172
        ])
    )

    tx = common.Tx(
        version = 1,
        tx_ins = [tx_in],
        tx_outs = [tx_out1, tx_out2],
    )

    message = tx.encode()

    assert message.hex() == '0100000001b2364d6ba4cbfd3dad8d6dc8dde1095f959bac4ee4ee7c4b8ab99fc885503246010000001976a9140e829f27b30f9cbc3005b574b060733587022d1d88acffffffff0250c30000000000001976a914d3724822e571c563e37ccee951fd2d4e4cd48c3888ac8cb90000000000001976a9140e829f27b30f9cbc3005b574b060733587022d1d88ac00000000'

def test_encode_signed_transaction():
    common = bitcoin

    G = common.Point(
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    )

    secret_key = int.from_bytes(b'test secret', 'big') 
    public_key = G * secret_key

    secret_key2 = int.from_bytes(b"test secret2", 'big') 
    public_key2 = G * secret_key2
    
    # use the script sig from the previous ScriptPubKey
    source_script = common.Script([
        118,
        169,
        common.hash160(public_key.encode()),
        136,
        172
    ])

    tx_in = common.TxIn(
        prev_tx = bytes.fromhex('46325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2')[::-1],
        prev_idx = 1,
        script_sig = source_script # this field will later have the digital signature
    )

    tx_out1 = common.TxOut(
        amount = 50000, # we will send this 50,000 sat to our target wallet
        script_pubkey = common.Script([
            118,
            169,
            common.hash160(public_key2.encode()),
            136,
            172
        ])
    )

    tx_out2 = common.TxOut(
        amount = 47500, # back to us
        script_pubkey = common.Script([
            118,
            169,
            common.hash160(public_key.encode()),
            136,
            172
        ])
    )

    tx = common.Tx(
        version = 1,
        tx_ins = [tx_in],
        tx_outs = [tx_out1, tx_out2],
    )

    message = tx.encode()

    sig = common.Signature.sign(secret_key, message)
    sig_bytes = sig.encode()

    assert sig_bytes.hex() == '30440220687a2a84aeaf387d8c6e9752fb8448f369c0f5da9fe695ff2eceb7fd6db8b728022069cece6f22680eeddb691e08192cf292eaa48eb3e449f48ac55b180b1efff93d'

    # Append 1 (= SIGHASH_ALL flag), indicating this DER signature we created encoded "ALL" of the tx (by far most common)
    sig_bytes_and_type = sig_bytes + b'\x01'

    script_sig = common.Script([sig_bytes_and_type, public_key.encode()])

    assert tx.encode().hex() == '0100000001b2364d6ba4cbfd3dad8d6dc8dde1095f959bac4ee4ee7c4b8ab99fc885503246010000001976a9140e829f27b30f9cbc3005b574b060733587022d1d88acffffffff0250c30000000000001976a914d3724822e571c563e37ccee951fd2d4e4cd48c3888ac8cb90000000000001976a9140e829f27b30f9cbc3005b574b060733587022d1d88ac00000000'

    tx_in.script_sig = script_sig
    tx.tx_ins = [tx_in]

    assert tx.encode().hex() == '0100000001b2364d6ba4cbfd3dad8d6dc8dde1095f959bac4ee4ee7c4b8ab99fc885503246010000006a4730440220687a2a84aeaf387d8c6e9752fb8448f369c0f5da9fe695ff2eceb7fd6db8b728022069cece6f22680eeddb691e08192cf292eaa48eb3e449f48ac55b180b1efff93d01210261c106858180622a02e05ee4fcd78db8a68293ee8dd7cfe40bcb9d43855f469cffffffff0250c30000000000001976a914d3724822e571c563e37ccee951fd2d4e4cd48c3888ac8cb90000000000001976a9140e829f27b30f9cbc3005b574b060733587022d1d88ac00000000'

def test_decode_transaction():
    # Programming bitcoin chapter 5
    raw = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    tx = bitcoin.Tx.decode(raw);

    # metadata parsing
    assert tx.version == 1
    assert tx.locktime == 410393

    # input parsing
    assert len(tx.tx_ins) == 1
    assert tx.tx_ins[0].prev_tx[::-1].hex() == 'd1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81'
    assert tx.tx_ins[0].prev_idx == 0
    assert tx.tx_ins[0].sequence == 0xfffffffe

    # output parsing
    assert len(tx.tx_outs) == 2
    assert tx.tx_outs[0].amount == 32454049
    assert tx.tx_outs[1].amount == 10011545

    assert tx.encode().hex() == raw.hex()

    # check id
    assert tx.id().hex() == '452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03'

    assert bitcoin.Tx.decode(tx.encode()).encode() == tx.encode()

def test_decode_and_validate_transaction():
    raw = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    tx = bitcoin.Tx.decode(raw);

    script_pubkey = bitcoin.Script([
        118,
        169,
        bytes.fromhex('a802fc56c704ce87c42d7c92eb75e7896bdc41ae'),
        136,
        172
    ])

    assert tx.validate(script_pubkey.encode())

    # test altering the digital signature or public key and make sure the validation breaks
    sig, pkb = tx.tx_ins[0].script_sig.commands
    altered_tx_in = tx.tx_ins[0]

    # alter sig
    new_sig = sig[:5] + bytes([sig[5] % 23]) + sig[6:]
    altered_tx_in.script_sig = bitcoin.Script([new_sig, pkb])
    tx.tx_ins = [altered_tx_in]
    assert not tx.validate(script_pubkey.encode())

    # revert back the signature
    altered_tx_in.script_sig = bitcoin.Script([sig, pkb])
    tx.tx_ins = [altered_tx_in]
    assert tx.validate(script_pubkey.encode())

    # alter public key
    new_pkb = pkb[:5] + bytes([pkb[5] % 23]) + pkb[6:]
    altered_tx_in.script_sig = bitcoin.Script([sig, new_pkb])
    tx.tx_ins = [altered_tx_in]
    assert not tx.validate(script_pubkey.encode())

def test_genesis_block():
    genesis_block_bytes = bytes.fromhex('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')

    block = bitcoin.Block.decode(genesis_block_bytes)
    assert block.version == 1
    assert block.prev_block == b'\x00' * 32
    assert block.merkle_root[::-1].hex() == '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
    assert block.timestamp == 1231006505
    assert block.bits == 0x1d00ffff
    assert block.nonce == 2083236893
    assert block.encode() == genesis_block_bytes

    assert block.id().hex() == '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
    assert block.target() == 0x00000000ffff0000000000000000000000000000000000000000000000000000
    assert block.validate()