import base64


def fixed_xor(ns, ms):
    dec_ns = base64.b16decode(ns.upper())
    dec_ms = base64.b16decode(ms.upper())
    bs = bytearray()
    for n, m in zip(dec_ns, dec_ms):
        r = n ^ m
        bs.append(r)
    return base64.b16encode(bs).lower()


def test_fixed_xor():
    assert fixed_xor(b'1c0111001f010100061a024b53535009181c',
                     b'686974207468652062756c6c277320657965') == b'746865206b696420646f6e277420706c6179'
