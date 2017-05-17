# Unit3-13 Version 1
#
# Write a function, mod_exp that returns
# `a**b % q` and has a runtime that is linear
# in the size of `b` - where the size of `b`
# is the number of bits


def mod_exp(a, b, q):
    if b == 0:
        return 1 % q
    elif b % 2 == 0:
        t = mod_exp(a, b // 2, q)
        return (t * t) % q
    else:
        return (a * mod_exp(a, b-1, q)) % q


def test_mod_exp():
    from time import time

    assert mod_exp(2, 10, 3) == 1024 % 3
    assert mod_exp(3, 3, 5) == 27 % 5
    assert mod_exp(5, 3, 7) == 125 % 7

    start = time()
    for _ in range(1000):
        t = mod_exp(100, 488778445455, 543)
    finish = time()
    assert t == 49
    assert finish - start < 0.5
