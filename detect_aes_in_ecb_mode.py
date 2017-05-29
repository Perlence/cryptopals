from base64 import b16decode
from collections import Counter
from itertools import zip_longest


def main():
    with open('detect_aes_in_ecb_mode.txt', 'rb') as fp:
        bss = [b16decode(line.strip().upper()) for line in fp]
    messages = sorted(((bs, max_block_repetitions(bs)) for bs in bss), key=lambda t: t[1], reverse=True)[:3]
    for message in messages:
        print(message)


def max_block_repetitions(bs, n=16):
    groups = grouper(bs, n)
    c = Counter(groups)
    return max(c.values())


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def test_max_block_repetitions():
    assert max_block_repetitions([1, 1, 1], n=1) == 3
    assert max_block_repetitions([1, 1, 1, 2, 2, 2, 2], n=1) == 4


if __name__ == '__main__':
    main()
