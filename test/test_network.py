from bitcoin import VersionMessage, NetworkEnvelope

def test_encode_version_message():
    m = VersionMessage(
        timestamp=0,
        # nonce=b'\x00'*8,
        nonce=0,
        user_agent=b'/programmingbitcoin:0.1/',
    )

    assert m.encode().hex() == '7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000'

def test_verack_message():
    msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')
    network_message = NetworkEnvelope.decode(msg)
    assert network_message.command == "verack"
    assert network_message.encode() == msg

def test_decode_encode_version_message():
    # <MAGIC> <COMMAND> <PAYLOAD LEN> <PAYLOAD CHECKSUM> <PAYLOAD>
    network_bytes = bytes.fromhex("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001")

    network_message = NetworkEnvelope.decode(network_bytes)
    # assert network_message.magic == b"f9beb4d" # main network
    # assert network_message.command == b"version"
    assert network_message.payload.version == 70002
    assert network_message.encode().hex() == "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001"
