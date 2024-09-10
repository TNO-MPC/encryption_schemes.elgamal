"""
This module tests the key generation of ElGamalBase.
"""

import pytest

from tno.mpc.encryption_schemes.utils.utils import is_prime, pow_mod

from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal
from tno.mpc.encryption_schemes.elgamal.elgamal_additive import ElGamalAdditive
from tno.mpc.encryption_schemes.elgamal.elgamal_base import (
    ElGamalBase,
    ElGamalPublicKey,
    ElGamalSecretKey,
)

# Different bitlengths for keys to be generated and tested.
key_lengths = [100, 200, 256, 400, 512]
# Set of key pairs, all of different length.
key_pairs = []
# Set of key pairs of different lengths, with multiple different keys for each length.
multiple_key_pairs = []

for i in range(5):
    for length in key_lengths:
        key_pair = ElGamalBase.generate_key_material(length)
        if i == 0:
            key_pairs.append(key_pair)
        multiple_key_pairs.append(key_pair)


@pytest.mark.parametrize("public_key, secret_key", key_pairs)
def test_encryption_creation(
    public_key: ElGamalPublicKey, secret_key: ElGamalSecretKey
) -> None:
    """
    Test whether the creation of the ElGamal and ElgGamalAdditive schemes work with the keys.

    :param public_key: ElGamalPublicKey for ElGamal scheme.
    :param secret_key: ElGamalSecretKey for ElGamal scheme.
    """
    ElGamal(public_key, secret_key)
    ElGamal(public_key, None)
    ElGamalAdditive(public_key, secret_key)
    ElGamalAdditive(public_key, None)

    # Check for no exceptions
    assert 1


@pytest.mark.parametrize("public_key, secret_key", multiple_key_pairs)
def test_key_value_equality(
    public_key: ElGamalPublicKey, secret_key: ElGamalSecretKey
) -> None:
    """
    Test whether the values p and g in an ElGamal keypair
    (ElGamalPublicKey, ElGamalSecretKey) = ((p, g, h), (p, g, x)) are equal.

    :param public_key: Public key for ElGamal scheme.
    :param secret_key: Secret key for ElGamal scheme.
    """
    assert public_key.p == secret_key.p
    assert public_key.g == secret_key.g


@pytest.mark.parametrize("public_key, secret_key", multiple_key_pairs)
def test_key_primality(
    public_key: ElGamalPublicKey, secret_key: ElGamalSecretKey
) -> None:
    """
    Test whether $p$ is prime and whether $p - 1 = 2 * q$ for a prime $q$.

    :param public_key: Public key for ElGamal scheme.
    :param secret_key: Secret key for ElGamal scheme.
    """
    assert is_prime(public_key.p)
    assert is_prime((public_key.p - 1) // 2)


@pytest.mark.parametrize("public_key, secret_key", multiple_key_pairs)
def test_key_generator(
    public_key: ElGamalPublicKey, secret_key: ElGamalSecretKey
) -> None:
    """
    Test whether $g$ generates $Z_p^*$.

    :param public_key: Public key for ElGamal scheme.
    :param secret_key: Secret key for ElGamal scheme.
    """
    assert pow_mod(public_key.g, 2, public_key.p) != 1
    assert pow_mod(public_key.g, (public_key.p - 1) // 2, public_key.p) != 1


@pytest.mark.parametrize("public_key, secret_key", multiple_key_pairs)
def test_key_public_value(
    public_key: ElGamalPublicKey, secret_key: ElGamalSecretKey
) -> None:
    r"""
    Test whether the secret key value $x$ and public key value $h$ are related via $h = g^x \mod p$.

    :param public_key: Public key for ElGamal scheme.
    :param secret_key: Secret key for ElGamal scheme.
    """
    assert public_key.h == pow_mod(public_key.g, secret_key.x, public_key.p)


@pytest.mark.parametrize("bits", [0, -100, -5])
def test_key_values(bits: int) -> None:
    r"""
    Test whether keys trying to generate keys with nonpositive bitlength raises an error.

    :param bits: Nonpositive bitlengths.
    """
    with pytest.raises(ValueError) as error:
        ElGamalBase.generate_key_material(bits)
    assert (
        str(error.value)
        == f"For generating keys we need a positive keylength, {bits} is too low."
    )
