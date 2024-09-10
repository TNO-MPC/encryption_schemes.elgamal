"""
This module tests the equality functions of ElGamalBase.
"""

from typing import Any, List, Tuple, TypeVar

import pytest

from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal
from tno.mpc.encryption_schemes.elgamal.elgamal_additive import ElGamalAdditive
from tno.mpc.encryption_schemes.elgamal.elgamal_base import (
    ElGamalBase,
    ElGamalBaseCipherText,
    KeyMaterial,
)

CT = TypeVar("CT", bound=ElGamalBaseCipherText)

keys: Tuple[KeyMaterial, KeyMaterial] = (
    ElGamalBase.generate_key_material(512),
    ElGamalBase.generate_key_material(512),
)
multiplicative_schemes: Tuple[ElGamal, ElGamal] = (
    ElGamal(*keys[0]),
    ElGamal(*keys[1]),
)
additive_schemes: Tuple[ElGamalAdditive, ElGamalAdditive] = (
    ElGamalAdditive(*keys[0]),
    ElGamalAdditive(*keys[1]),
)

both_schemes = multiplicative_schemes + additive_schemes


@pytest.mark.parametrize(
    "schemes", [list(i) for i in zip(*([multiplicative_schemes] + [additive_schemes]))]
)
def test_keys_equality(schemes: List[ElGamalBase[CT]]) -> None:
    """
    Test whether comparing the same keys used in different schemes works.

    :param schemes: List of 2 different schemes with the same keypairs.
    """
    assert schemes[0].public_key == schemes[1].public_key
    assert schemes[1].secret_key == schemes[0].secret_key


@pytest.mark.parametrize("schemes", [multiplicative_schemes] + [additive_schemes])
def test_keys_inequality(schemes: List[ElGamalBase[CT]]) -> None:
    """
    Test whether inequality of keys holds.

    :param schemes: List of 2 schemes with different keypairs.
    """
    assert schemes[0].public_key != schemes[1].public_key
    assert schemes[0].secret_key != schemes[1].secret_key


@pytest.mark.parametrize("scheme", both_schemes)
def test_cipher_equality(scheme: ElGamalBase[CT]) -> None:
    """
    Test whether equality of two ElGamalCiphertexts and two ElGamalAdditiveCiphertexts was
    implemented properly.

    :param scheme: Scheme used for creating ciphertexts.
    """
    ciphertext = scheme.encrypt(5)
    ciphertext_copy = type(ciphertext)(raw_value=ciphertext.peek_value(), scheme=scheme)
    assert ciphertext == ciphertext_copy


@pytest.mark.parametrize("schemes", [multiplicative_schemes] + [additive_schemes])
def test_cipher_inequality(schemes: List[ElGamalBase[CT]]) -> None:
    """
    Test whether inequality of the same ciphertext encrypted with different keys holds.

    :param schemes: List of 2 schemes with different keypairs.
    """
    ciphertext0 = schemes[0].encrypt(5)
    ciphertext1 = schemes[1].encrypt(5)
    assert ciphertext0 != ciphertext1


@pytest.mark.parametrize(
    "schemes", [list(i) for i in zip(*([multiplicative_schemes] + [additive_schemes]))]
)
def test_different_scheme_type_affects_equality(schemes: List[ElGamalBase[CT]]) -> None:
    """
    Test whether comparing ciphertexts of created by different schemes are not equal.

    :param schemes: List of 2 different schemes with the same keypairs.
    :raise ValueError: When test is initialized with schemes with different keypairs.
    """
    if schemes[0].public_key != schemes[1].public_key:
        raise ValueError("Test meant to work with equal keys")
    assert schemes[0] != schemes[1]
    pub_key = schemes[0].public_key
    assert schemes[0].id_from_arguments(pub_key) != schemes[1].id_from_arguments(
        pub_key
    )
    ciphertext0 = schemes[0].encrypt(5)
    ciphertext1 = schemes[1].encrypt(5)
    assert ciphertext0 != ciphertext1


@pytest.mark.parametrize("scheme", both_schemes)
def test_scheme_equality(scheme: ElGamalBase[Any]) -> None:
    """
    Test whether equality of ElGamal or ElGamalAdditive schemes was implemented properly.

    :param scheme: Scheme that will be compared to itself.
    """
    scheme_copy = type(scheme)(
        public_key=scheme.public_key,
        secret_key=scheme.secret_key,
        share_secret_key=scheme.share_secret_key,
    )
    assert scheme == scheme_copy


@pytest.mark.parametrize("schemes", [multiplicative_schemes, additive_schemes])
def test_scheme_inequality(schemes: Tuple[ElGamalBase[Any], ElGamalBase[Any]]) -> None:
    """
    Test whether inequality of schemes with different keys holds.

    :param schemes: List of 2 schemes with different keypairs.
    """
    assert schemes[0] != schemes[1]
