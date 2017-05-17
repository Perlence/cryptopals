import base64


def convert_hex_to_base64(s):
    d = base64.b16decode(s.upper())
    return base64.b64encode(d)


def test_convert_hex_to_base64():
    h = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    assert convert_hex_to_base64(h) == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
