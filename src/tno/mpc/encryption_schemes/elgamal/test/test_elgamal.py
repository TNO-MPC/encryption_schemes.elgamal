"""
This module tests the encryption an decryption functionalities of ElGamal and ElGamalAdditive.
"""

import itertools
from math import ceil, floor
from typing import TypeVar, Union

import pytest

from tno.mpc.encryption_schemes.utils.utils import pow_mod

from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal
from tno.mpc.encryption_schemes.elgamal.elgamal_additive import ElGamalAdditive
from tno.mpc.encryption_schemes.elgamal.elgamal_base import (
    WARN_INEFFICIENT_HOM_OPERATION,
    ElGamalBase,
    ElGamalBaseCipherText,
    Plaintext,
)
from tno.mpc.encryption_schemes.elgamal.test import conditional_pywarn

public_key, secret_key = ElGamalBase.generate_key_material(100)

PLAINTEXT_INPUTS = list(range(4)) + [12, 123, 1234, 12345, 123456]
PLAINTEXT_INPUTS = PLAINTEXT_INPUTS + [-x for x in PLAINTEXT_INPUTS]


def limit_to_message_space_multiplicative(value: int, scheme: ElGamal) -> int:
    """
    Limit a value in such a way that it fits in the message space.

    :param value: Value to be limited.
    :param scheme: ElGamal encryption scheme with which the value should be encrypted.
    :return: Limited value
    """
    if value < scheme.min_value or value > scheme.max_value:
        value = int(value % scheme.public_key.p)
    if value > scheme.max_value:
        value = value - scheme.public_key.p
    return value


def limit_to_message_space_additive(
    value: int, scheme: Union[ElGamalAdditive, ElGamal]
) -> int:
    """
    Limit a value in such a way that it fits in the message space.

    :param value: Value to be limited.
    :param scheme: ElGamalAdditive encryption scheme with which the value should be encrypted.
    :return: Limited value
    """
    if value < scheme.min_value or value > scheme.max_value:
        value = int(value % scheme.max_value)
    return value


CT = TypeVar("CT", bound=ElGamalBaseCipherText)


def encrypt_with_freshness(value: Plaintext, scheme: ElGamalBase[CT], safe: bool) -> CT:
    """
    Encrypt a plaintext in safe or unsafe mode.

    Safe mode will yield a fresh ciphertext, unsafe mode will yield a non-fresh ciphertext.

    :param value: Plaintext message to be encrypted
    :param scheme: Scheme to encrypt the message with
    :param safe: Perform safe encrypt if true, unsafe encrypt otherwise
    :return: ElGamalBaseCipherText object with requested freshness
    """
    if safe:
        return scheme.encrypt(value)
    return scheme.unsafe_encrypt(value)


@pytest.fixture(name="elgamal_scheme")
def fixture_elgamal_scheme() -> ElGamal:
    """
    Get ElGamal encryption scheme.

    :return: Initialized ElGamal scheme.
    """
    return ElGamal(public_key, secret_key)


@pytest.fixture(name="elgamaladditive_scheme")
def fixture_elgamaladditive_scheme() -> ElGamalAdditive:
    """
    Get ElGamalAdditive encryption scheme.

    :return: Initialized ElGamalAdditive scheme.
    """
    return ElGamalAdditive(public_key, secret_key)


@pytest.fixture(name="public_elgamal_scheme")
def fixture_public_elgamal_scheme() -> ElGamal:
    """
    Get ElGamal encryption scheme without secret key.

    :return: Initialized ElGamal scheme without secret key.
    """
    return ElGamal(public_key, None)


@pytest.fixture(name="public_elgamaladditive_scheme")
def fixture_public_elgamaladditive_scheme() -> ElGamalAdditive:
    """
    Get ElGamalAdditive encryption scheme without secret key.

    :return: Initialized ElGamalAdditive scheme without secret key.
    """
    return ElGamalAdditive(public_key, None)


@pytest.mark.parametrize("plaintext", PLAINTEXT_INPUTS)
def test_elgamal_encryption(elgamal_scheme: ElGamal, plaintext: int) -> None:
    """
    Test the encryption functionality of an ElGamal scheme.

    :param elgamal_scheme: ElGamal encryption scheme.
    :param plaintext: Value to be encrypted.
    """
    plaintext = limit_to_message_space_multiplicative(plaintext, elgamal_scheme)
    ciphertext = elgamal_scheme.encrypt(plaintext)
    decrypted_ciphertext = elgamal_scheme.decrypt(ciphertext)

    assert ciphertext.fresh
    assert plaintext == decrypted_ciphertext


@pytest.mark.parametrize("plaintext", PLAINTEXT_INPUTS)
def test_elgamaladditive_encryption(
    elgamaladditive_scheme: ElGamalAdditive, plaintext: int
) -> None:
    """
    Test the encryption functionality of an ElGamalAdditive scheme.

    :param elgamaladditive_scheme: ElGamalAdditive encryption scheme.
    :param plaintext: Value to be encrypted.
    """
    plaintext = limit_to_message_space_additive(plaintext, elgamaladditive_scheme)
    ciphertext = elgamaladditive_scheme.encrypt(plaintext)
    decrypted_ciphertext = elgamaladditive_scheme.decrypt(ciphertext)

    assert ciphertext.fresh
    assert plaintext == decrypted_ciphertext


@pytest.mark.parametrize("plaintext", PLAINTEXT_INPUTS)
def test_public_elgamal_encryption(
    elgamal_scheme: ElGamal, public_elgamal_scheme: ElGamal, plaintext: int
) -> None:
    """
    Test the encryption functionality of a public ElGamal scheme.

    :param elgamal_scheme: ElGamal encryption scheme.
    :param public_elgamal_scheme: ElGamal encryption scheme with same public key and no secret key.
    :param plaintext: Value to be encrypted.
    """
    plaintext = limit_to_message_space_multiplicative(plaintext, public_elgamal_scheme)
    ciphertext = public_elgamal_scheme.encrypt(plaintext)
    decrypted_ciphertext = elgamal_scheme.decrypt(ciphertext)

    assert ciphertext.fresh
    assert plaintext == decrypted_ciphertext


@pytest.mark.parametrize("plaintext", PLAINTEXT_INPUTS)
def test_public_elgamaladditive_encryption(
    elgamaladditive_scheme: ElGamalAdditive,
    public_elgamaladditive_scheme: ElGamalAdditive,
    plaintext: int,
) -> None:
    """
    Test the encryption functionality of a public ElGamalAdditive scheme.

    :param elgamaladditive_scheme: ElGamalAdditive encryption scheme.
    :param public_elgamaladditive_scheme: ElGamalAdditive encryption scheme with same public key
        and no secret key.
    :param plaintext: Value to be encrypted.
    """
    plaintext = limit_to_message_space_additive(
        plaintext, public_elgamaladditive_scheme
    )
    ciphertext = public_elgamaladditive_scheme.encrypt(plaintext)
    decrypted_ciphertext = elgamaladditive_scheme.decrypt(ciphertext)

    assert ciphertext.fresh
    assert plaintext == decrypted_ciphertext


@pytest.mark.parametrize("plaintext", PLAINTEXT_INPUTS)
def test_ciphertext_randomization(elgamal_scheme: ElGamal, plaintext: int) -> None:
    """
    Test the rerandomization functionality of ElGamalBase.

    :param elgamal_scheme: ElGamalBase encryption scheme used for encrypting and generating
        randomness.
    :param plaintext: Value to be encrypted.
    """
    plaintext = limit_to_message_space_multiplicative(plaintext, elgamal_scheme)
    ciphertext = elgamal_scheme.encrypt(plaintext)
    raw_value = ciphertext.get_value()  # sets ciphertext.fresh to False
    ciphertext.randomize()
    randomized_raw_value = ciphertext.peek_value()  # does not alter freshness
    decrypted_value = elgamal_scheme.decrypt(ciphertext)

    assert ciphertext.fresh
    assert randomized_raw_value != raw_value
    assert decrypted_value == plaintext


@pytest.mark.parametrize("plaintext", PLAINTEXT_INPUTS)
def test_unsafe_encryption(elgamal_scheme: ElGamal, plaintext: int) -> None:
    """
    Test the unsafe encryption functionality of an ElGamalBase scheme with a secret key.

    :param elgamal_scheme: ElGamalBase encryption scheme with secret key.
    :param plaintext: Value to be encrypted.
    """
    plaintext = limit_to_message_space_multiplicative(plaintext, elgamal_scheme)
    ciphertext = elgamal_scheme.unsafe_encrypt(plaintext)
    decrypted_ciphertext = elgamal_scheme.decrypt(ciphertext)

    assert not ciphertext.fresh
    assert plaintext == decrypted_ciphertext


@pytest.mark.parametrize("plaintext", PLAINTEXT_INPUTS)
def test_encryption_with_randomization(elgamal_scheme: ElGamal, plaintext: int) -> None:
    """
    Test the encryption functionality of an ElGamalBase scheme with a secret key while using
    rerandomization.

    :param elgamal_scheme: ElGamalBase encryption scheme with secret key.
    :param plaintext: Value to be encrypted.
    """
    plaintext = limit_to_message_space_multiplicative(plaintext, elgamal_scheme)
    ciphertext1 = elgamal_scheme.unsafe_encrypt(plaintext)
    ciphertext2 = elgamal_scheme.unsafe_encrypt(plaintext)

    assert not ciphertext1.fresh

    ciphertext1.randomize()

    assert ciphertext1.fresh
    assert ciphertext1 != ciphertext2

    decrypted_ciphertext = elgamal_scheme.decrypt(ciphertext1)

    assert plaintext == decrypted_ciphertext


def test_elgamal_encoding_exception(elgamal_scheme: ElGamal) -> None:
    """
    Test whether trying to encrypt a message out of the message range of an ElGamal scheme
    raises an exception.

    :param elgamal_scheme: ElGamal encryption scheme.
    """
    plaintext = elgamal_scheme.max_value + 1
    with pytest.raises(ValueError) as error:
        elgamal_scheme.encode(plaintext)
    assert (
        str(error.value)
        == f"This encoding scheme only supports values in the range [{elgamal_scheme.min_value};"
        f"{elgamal_scheme.max_value}], {plaintext} is outside that range."
    )


def test_elgamaladditive_encoding_exception(
    elgamaladditive_scheme: ElGamalAdditive,
) -> None:
    """
    Test whether trying to encrypt a message out of the message range of an ElGamalAdditive scheme
    raises an exception.

    :param elgamaladditive_scheme: ElGamalAdditive encryption scheme.
    """
    plaintext = elgamaladditive_scheme.max_value + 1
    with pytest.raises(ValueError) as error:
        elgamaladditive_scheme.encode(plaintext)
    assert (
        str(error.value) == f"This encoding scheme only supports values in the range "
        f"[{elgamaladditive_scheme.min_value};{elgamaladditive_scheme.max_value}], {plaintext} "
        f"is outside that range."
    )


def test_elgamal_zero(elgamal_scheme: ElGamal) -> None:
    """
    Test whether an encrypted zero plaintext can successfully be determined to be zero.

    :param elgamal_scheme: ElGamal scheme.
    """
    encrypted_zero = elgamal_scheme.encrypt(0)
    assert encrypted_zero.is_zero()


@pytest.mark.parametrize("value", [i + -5 for i in range(11) if i != 5])
def test_elgamal_non_zero(elgamal_scheme: ElGamal, value: int) -> None:
    """
    Test whether an encrypted nonzero plaintext can successfully be determined to be nonzero.

    :param elgamal_scheme: ElGamal scheme.
    :param value: Nonzero plaintext to be encrypted.
    """
    encrypted_nonzero = elgamal_scheme.encrypt(value)

    assert not encrypted_nonzero.is_zero()


@pytest.mark.parametrize("is_fresh", (True, False))
@pytest.mark.parametrize(
    "value",
    PLAINTEXT_INPUTS,
)
def test_elgamal_neg(elgamal_scheme: ElGamal, value: int, is_fresh: bool) -> None:
    """
    Test whether an encrypted nonzero plaintext can successfully be negated.

    :param elgamal_scheme: ElGamal scheme with secret key.
    :param value: Plaintext to be encrypted and then negated.
    :param is_fresh: Freshness of ciphertext.
    """
    value = limit_to_message_space_multiplicative(value, elgamal_scheme)

    encrypted_value = encrypt_with_freshness(value, elgamal_scheme, is_fresh)

    with conditional_pywarn(is_fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_neg = elgamal_scheme.neg(encrypted_value)

    assert not encrypted_value.fresh
    assert encrypted_neg.fresh == is_fresh
    assert elgamal_scheme.decrypt(encrypted_neg) == -value


@pytest.mark.parametrize(
    "is_fresh, is_fresh_2",
    itertools.product((True, False), (True, False)),
)
@pytest.mark.parametrize("value", PLAINTEXT_INPUTS)
@pytest.mark.parametrize("value_2", PLAINTEXT_INPUTS)
def test_elgamal_mul(
    elgamal_scheme: ElGamal, value: int, value_2: int, is_fresh: bool, is_fresh_2: bool
) -> None:
    """
    Test whether two ciphertexts can be multiplied (i.e. the plaintexts are multiplied).

    :param elgamal_scheme: ElGamal encryption scheme with secret key.
    :param value: First plaintext message to be encrypted.
    :param value_2: Second plaintext message to be encrypted and multiplied with the first.
    :param is_fresh: Freshness of first ciphertext.
    :param is_fresh_2: Freshness of second ciphertext.
    """
    value = limit_to_message_space_multiplicative(value, elgamal_scheme)
    value_2 = limit_to_message_space_multiplicative(value_2, elgamal_scheme)

    multiplication = value * value_2 % elgamal_scheme.public_key.p
    if multiplication > elgamal_scheme.max_value:
        multiplication -= elgamal_scheme.public_key.p

    encrypted_value = encrypt_with_freshness(value, elgamal_scheme, is_fresh)
    encrypted_value_2 = encrypt_with_freshness(value_2, elgamal_scheme, is_fresh_2)

    with conditional_pywarn(is_fresh or is_fresh_2, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_mul = encrypted_value * encrypted_value_2

    assert not encrypted_value.fresh
    assert not encrypted_value_2.fresh
    assert encrypted_mul.fresh == (is_fresh or is_fresh_2)

    assert elgamal_scheme.decrypt(encrypted_mul) == multiplication

    # test multiplication with unencrypted value
    encrypted_value = encrypt_with_freshness(value, elgamal_scheme, is_fresh)

    with conditional_pywarn(is_fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_mul = encrypted_value * value_2

    assert not encrypted_value.fresh
    assert encrypted_mul.fresh == is_fresh
    assert elgamal_scheme.decrypt(encrypted_mul) == multiplication


@pytest.mark.parametrize("is_fresh", (True, False))
@pytest.mark.parametrize("value", PLAINTEXT_INPUTS)
@pytest.mark.parametrize("power", PLAINTEXT_INPUTS)
def test_elgamal_pow(
    elgamal_scheme: ElGamal, value: int, power: int, is_fresh: bool
) -> None:
    """
    Test whether a ciphertext can be exponentiated with an integer exponent.

    :param elgamal_scheme: ElGamal scheme with secret key.
    :param value: Plaintext to be encrypted and then exponentiated with the power.
    :param power: Power to exponentiate the encrypted plaintext with.
    :param is_fresh: Freshness of ciphertext.
    """
    value = limit_to_message_space_additive(value, elgamal_scheme)
    power = limit_to_message_space_additive(power, elgamal_scheme)
    power = int(round(power))

    try:
        exponentiation = pow_mod(value, power, elgamal_scheme.public_key.p)
    except (ValueError, ZeroDivisionError):
        # For negative powers we can get this error if value is non-invertible mod p
        # Just cancel the test for those values. The zero-division error is specific to python 3.7
        assert power < 0
        return
    exponentiation = limit_to_message_space_multiplicative(
        exponentiation, elgamal_scheme
    )

    encrypted_value = encrypt_with_freshness(value, elgamal_scheme, is_fresh)

    with conditional_pywarn(is_fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_exponentiation = encrypted_value**power

    assert not encrypted_value.fresh
    assert encrypted_exponentiation.fresh == is_fresh
    assert elgamal_scheme.decrypt(encrypted_exponentiation) == exponentiation


@pytest.mark.parametrize("is_fresh", (True, False))
@pytest.mark.parametrize(
    "value",
    PLAINTEXT_INPUTS,
)
def test_elgamaladditive_neg(
    elgamaladditive_scheme: ElGamalAdditive, value: int, is_fresh: bool
) -> None:
    """
    Test whether an encrypted nonzero plaintext can successfully be negated.

    :param elgamaladditive_scheme: ElGamalAdditive scheme with secret key.
    :param value: Plaintext to be encrypted and then negated.
    :param is_fresh: Freshness of ciphertext.
    """
    value = limit_to_message_space_additive(value, elgamaladditive_scheme)

    encrypted_value = encrypt_with_freshness(value, elgamaladditive_scheme, is_fresh)

    with conditional_pywarn(is_fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_neg = elgamaladditive_scheme.neg(encrypted_value)

    assert not encrypted_value.fresh
    assert encrypted_neg.fresh == is_fresh
    assert elgamaladditive_scheme.decrypt(encrypted_neg) == -value


@pytest.mark.parametrize("is_fresh", (True, False))
@pytest.mark.parametrize("value", PLAINTEXT_INPUTS)
@pytest.mark.parametrize("scalar", PLAINTEXT_INPUTS)
def test_elgamaladditive_mul(
    elgamaladditive_scheme: ElGamalAdditive, value: int, scalar: int, is_fresh: bool
) -> None:
    """
    Test whether a ciphertext can be multiplied with a scalar.

    :param elgamaladditive_scheme: ElGamalAdditive scheme with secret key.
    :param value: Plaintext to be encrypted and then multiplied with the scalar.
    :param scalar: Scalar to multiply with the encrypted plaintext.
    :param is_fresh: Freshness of ciphertext.
    """
    value = limit_to_message_space_additive(value, elgamaladditive_scheme)
    scalar = limit_to_message_space_additive(scalar, elgamaladditive_scheme)
    scalar = int(round(scalar))

    # make sure outcome of multiplication fits in message space
    if value * scalar > elgamaladditive_scheme.max_value:
        limit_factor = ceil(value * scalar / elgamaladditive_scheme.max_value)
        value = floor(value / limit_factor)
    elif value * scalar < elgamaladditive_scheme.min_value:
        limit_factor = ceil(value * scalar / elgamaladditive_scheme.min_value)
        value = ceil(value / limit_factor)
    value = int(value)

    multiplication = value * scalar

    encrypted_value = encrypt_with_freshness(value, elgamaladditive_scheme, is_fresh)

    with conditional_pywarn(is_fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_multiplication = encrypted_value * scalar

    assert not encrypted_value.fresh
    assert encrypted_multiplication.fresh == is_fresh

    # Only test correct decryption and multiplication result for cases that can be decrypted in a
    # reasonable amount of time.
    if abs(multiplication) < pow_mod(2, 20, elgamaladditive_scheme.public_key.p - 1):
        assert (
            elgamaladditive_scheme.decrypt(encrypted_multiplication) == multiplication
        )


@pytest.mark.parametrize(
    "is_fresh, is_fresh_2",
    itertools.product((True, False), (True, False)),
)
@pytest.mark.parametrize("value", PLAINTEXT_INPUTS)
@pytest.mark.parametrize("value_2", PLAINTEXT_INPUTS)
def test_elgamaladditive_add(
    elgamaladditive_scheme: ElGamalAdditive,
    value: int,
    value_2: int,
    is_fresh: bool,
    is_fresh_2: bool,
) -> None:
    """
    Test whether two ciphertexts can be added (i.e. their underlying plaintexts are added.)

    :param elgamaladditive_scheme: ElGamalAdditive scheme with secret key.
    :param value: First plaintext message to be encrypted.
    :param value_2: Second plaintext message to be encrypted and added to the first.
    :param is_fresh: Freshness of first ciphertext.
    :param is_fresh_2: Freshness of second ciphertext.
    """
    value = limit_to_message_space_additive(value, elgamaladditive_scheme)
    value_2 = limit_to_message_space_additive(value_2, elgamaladditive_scheme)

    if value + value_2 >= elgamaladditive_scheme.max_value:
        value_2 = elgamaladditive_scheme.max_value - value
    elif value + value_2 <= elgamaladditive_scheme.min_value:
        value_2 = elgamaladditive_scheme.min_value - value
    sum_ = value + value_2

    encrypted_value = encrypt_with_freshness(value, elgamaladditive_scheme, is_fresh)
    encrypted_value_2 = encrypt_with_freshness(
        value_2, elgamaladditive_scheme, is_fresh_2
    )

    with conditional_pywarn(is_fresh or is_fresh_2, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_sum = encrypted_value + encrypted_value_2

    assert not encrypted_value.fresh
    assert not encrypted_value_2.fresh
    assert encrypted_sum.fresh == (is_fresh or is_fresh_2)

    assert elgamaladditive_scheme.decrypt(encrypted_sum) == sum_

    encrypted_value = encrypt_with_freshness(value, elgamaladditive_scheme, is_fresh)

    with conditional_pywarn(is_fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_sum = encrypted_value + value_2

    assert not encrypted_value.fresh
    assert encrypted_sum.fresh == is_fresh
    assert elgamaladditive_scheme.decrypt(encrypted_sum) == sum_


@pytest.mark.parametrize(
    "is_fresh, is_fresh_2",
    itertools.product((True, False), (True, False)),
)
@pytest.mark.parametrize("value", PLAINTEXT_INPUTS)
@pytest.mark.parametrize("value_2", PLAINTEXT_INPUTS)
def test_elgamaladditive_sub(
    elgamaladditive_scheme: ElGamalAdditive,
    value: int,
    value_2: int,
    is_fresh: bool,
    is_fresh_2: bool,
) -> None:
    """
    Test whether two ciphertexts can be subtracted (i.e. their underlying plaintexts are
    subtracted.)

    :param elgamaladditive_scheme: ElGamalAdditive scheme with secret key.
    :param value: First plaintext message to be encrypted.
    :param value_2: Second plaintext message to be encrypted and subtracted from the first.
    :param is_fresh: Freshness of first ciphertext.
    :param is_fresh_2: Freshness of second ciphertext.
    """
    value = limit_to_message_space_additive(value, elgamaladditive_scheme)
    value_2 = limit_to_message_space_additive(value_2, elgamaladditive_scheme)

    if value - value_2 >= elgamaladditive_scheme.max_value:
        value = elgamaladditive_scheme.max_value + value_2
    elif value - value_2 <= elgamaladditive_scheme.min_value:
        value = elgamaladditive_scheme.min_value + value_2

    subtraction = value - value_2

    encrypted_value = encrypt_with_freshness(value, elgamaladditive_scheme, is_fresh)
    encrypted_value_2 = encrypt_with_freshness(
        value_2, elgamaladditive_scheme, is_fresh_2
    )

    with conditional_pywarn(is_fresh or is_fresh_2, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_subtraction = encrypted_value - encrypted_value_2

    assert not encrypted_value.fresh
    assert not encrypted_value_2.fresh
    assert encrypted_subtraction.fresh == (is_fresh or is_fresh_2)

    assert elgamaladditive_scheme.decrypt(encrypted_subtraction) == subtraction

    encrypted_value = encrypt_with_freshness(value, elgamaladditive_scheme, is_fresh)

    with conditional_pywarn(is_fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_subtraction = encrypted_value - value_2

    assert not encrypted_value.fresh
    assert encrypted_subtraction.fresh == is_fresh
    assert elgamaladditive_scheme.decrypt(encrypted_subtraction) == subtraction
