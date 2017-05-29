def pkcs7(message, size):
    pad_size = size - len(message)
    if pad_size < 0:
        raise ValueError("message '{}' is longer than size".format(pad_size))
    return message + bytes([pad_size]) * pad_size


def test_pkcs7():
    assert pkcs7(b'YELLOW SUBMARINE', 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
