"""
This module tests the serialization of ElGamal and ElGamalAdditive instances.
"""

from __future__ import annotations

import asyncio
import warnings
from typing import Any, Tuple, cast

import pytest

from tno.mpc.communication import Pool
from tno.mpc.encryption_schemes.templates import EncryptionSchemeWarning

from tno.mpc.encryption_schemes.elgamal import (
    ElGamal,
    ElGamalAdditive,
    ElGamalCipherText,
    ElGamalPublicKey,
    ElGamalSecretKey,
)
from tno.mpc.encryption_schemes.elgamal.elgamal_base import (
    WARN_UNFRESH_SERIALIZATION,
    ElGamalBaseCipherText,
)
from tno.mpc.encryption_schemes.elgamal.test.test_elgamal import PLAINTEXT_INPUTS

SECURITY_PARAM = 512
elgamal_pk, elgamal_sk = ElGamal.generate_key_material(bits=SECURITY_PARAM)
elgamaladditive_pk, elgamaladditive_sk = ElGamalAdditive.generate_key_material(
    bits=SECURITY_PARAM
)


@pytest.fixture(name="elgamalbase", params=["elgamal", "elgamal_additive"])
def fixture_elgamalbase(
    request: pytest.FixtureRequest,
) -> ElGamal | ElGamalAdditive:
    """
    Fixture that returns ElGamalBase subschemes.

    :param request: Pytest request fixture.
    :return: ElGamal or ElGamalAdditive scheme.
    """
    if request.param == "elgamal":
        return ElGamal(elgamal_pk, elgamal_sk)
    return ElGamalAdditive(elgamaladditive_pk, elgamaladditive_sk)


def elgamal_scheme() -> ElGamal:
    """
    Constructs an ElGamal scheme.

    :return: Initialized ElGamal scheme.
    """
    return ElGamal.from_security_parameter(bits=SECURITY_PARAM, debug=False)


def elgamaladditive_scheme() -> ElGamalAdditive:
    """
    Constructs an ElGamalAdditive scheme.

    :return: Initialized ElGamalAdditive scheme.
    """
    return ElGamalAdditive.from_security_parameter(bits=SECURITY_PARAM, debug=False)


def test_serialization_public_key(elgamalbase: ElGamal | ElGamalAdditive) -> None:
    """
    Test to determine whether the public key serialization works properly for ElGamalBase
    subschemes.

    :param elgamalbase: ElGamalBase subscheme under test.
    """
    serialized_pk = elgamalbase.public_key.serialize()
    assert elgamalbase.public_key == ElGamalPublicKey.deserialize(serialized_pk)


def test_serialization_secret_key_elgamal(
    elgamalbase: ElGamal | ElGamalAdditive,
) -> None:
    """
    Test to determine whether the secret key serialization works properly for ElGamalBase
    subschemes.

    :param elgamalbase: ElGamalBase subscheme under test.
    """
    serialized_sk = elgamalbase.secret_key.serialize()
    assert elgamalbase.secret_key == ElGamalSecretKey.deserialize(serialized_sk)


@pytest.mark.parametrize("value", PLAINTEXT_INPUTS)
@pytest.mark.parametrize("fresh", (True, False))
def test_serialization_cipher(
    elgamalbase: ElGamal | ElGamalAdditive, value: int, fresh: bool
) -> None:
    """
    Test to determine whether serialization works properly for the ElGamalBaseCiphertext subtypes.

    :param elgamalbase: ElGamalBase subscheme under test.
    :param value: Value to serialize
    :param fresh: Freshness of ciphertext
    """
    if fresh:
        cipher = elgamalbase.encrypt(value)
    else:
        cipher = elgamalbase.unsafe_encrypt(value)
    with warnings.catch_warnings():
        # The unfresh serialization warning is not in scope of this test.
        warnings.filterwarnings("ignore", WARN_UNFRESH_SERIALIZATION, UserWarning)
        deserialized = ElGamalCipherText.deserialize(cipher.serialize())
    assert isinstance(deserialized, ElGamalCipherText)
    assert cipher == deserialized


def test_serialization_no_share(elgamalbase: ElGamal | ElGamalAdditive) -> None:
    """
    Test to determine whether the ElGamal scheme serialization works properly for schemes
    when the secret key SHOULD NOT be serialized.

    :param elgamalbase: ElGamalBase subscheme under test.
    """
    scheme = elgamalbase
    # by default the secret key is not serialized, but equality should then still hold
    serialized_scheme = scheme.serialize()
    assert "seckey" not in serialized_scheme
    scheme_prime = scheme.deserialize(serialized_scheme)
    scheme.shut_down()
    scheme_prime.shut_down()
    # secret key is still shared due to local instance sharing
    assert scheme.secret_key is scheme_prime.secret_key
    assert scheme == scheme_prime

    # this time empty the list of global instances after serialization
    scheme_serialized = scheme.serialize()
    scheme.clear_instances()
    scheme_prime2 = scheme.deserialize(scheme_serialized)
    scheme.shut_down()
    scheme_prime2.shut_down()
    assert scheme_prime2.secret_key is None
    assert scheme == scheme_prime2


def test_serialization_share(elgamalbase: ElGamal | ElGamalAdditive) -> None:
    """
    Test to determine whether the ElGamal scheme serialization works properly for schemes
    when the secret key SHOULD be serialized.

    :param elgamalbase: ElGamalBase subscheme under test.
    """
    scheme = elgamalbase
    scheme.share_secret_key = True
    # We indicated that the secret key should be serialized, so this should be equal
    serialized_scheme = scheme.serialize()
    assert "seckey" in serialized_scheme
    scheme_prime = scheme.deserialize(serialized_scheme)
    scheme_prime.shut_down()
    scheme.shut_down()
    assert scheme == scheme_prime


@pytest.mark.parametrize("value", PLAINTEXT_INPUTS)
def test_serialization_randomization_unfresh(
    elgamalbase: ElGamal | ElGamalAdditive, value: int
) -> None:
    """
    Test to determine whether the ElGamal ciphertext serialization correctly randomizes non-fresh
    ciphertexts.

    :param elgamalbase: ElGamalBase subscheme under test.
    :param value: value to serialize
    """
    scheme = elgamalbase
    ciphertext = scheme.unsafe_encrypt(value)
    val_pre_serialize = ciphertext.peek_value()
    with pytest.warns(EncryptionSchemeWarning, match=WARN_UNFRESH_SERIALIZATION):
        ciphertext.serialize()
    val_post_serialize = ciphertext.peek_value()
    scheme.shut_down()
    assert val_pre_serialize != val_post_serialize
    assert ciphertext.fresh is False


@pytest.mark.parametrize("value", PLAINTEXT_INPUTS)
def test_serialization_randomization_fresh(
    elgamalbase: ElGamal | ElGamalAdditive, value: int
) -> None:
    """
    Test to determine whether the ElGamal ciphertext serialization works properly for fresh
    ciphertexts.

    :param elgamalbase: ElGamalBase subscheme under test.
    :param value: Value to serialize
    """
    scheme = elgamalbase
    ciphertext = scheme.encrypt(value)

    assert ciphertext.fresh

    ciphertext_prime = ElGamalCipherText.deserialize(ciphertext.serialize())

    assert not ciphertext.fresh
    assert not ciphertext_prime.fresh

    scheme.shut_down()
    assert ciphertext == ciphertext_prime


def test_unrelated_instances() -> None:
    """
    Test whether the from_id_arguments and id_from_arguments methods works as intended.
    The share_secret_key variable should not influence the identifier.

    # TODO add cases with elgamal_3 and elgamal_4 when precision is implemented
    """
    scheme = elgamal_scheme()
    public_key = scheme.public_key
    secret_key = scheme.secret_key

    elgamal_1 = ElGamal(public_key=public_key, secret_key=None, share_secret_key=False)
    elgamal_1_prime = ElGamal(
        public_key=public_key, secret_key=secret_key, share_secret_key=True
    )
    assert elgamal_1.identifier == elgamal_1_prime.identifier
    elgamal_1.save_globally()
    elgamal_2 = ElGamal.from_id_arguments(public_key=public_key)

    elgamal_1.shut_down()
    elgamal_1_prime.shut_down()
    elgamal_2.shut_down()
    scheme.shut_down()

    assert elgamal_1 is elgamal_2
    assert elgamal_1 == elgamal_2


def test_related_serialization(elgamalbase: ElGamal | ElGamalAdditive) -> None:
    """
    Test whether deserialization of ElGamal ciphertexts results in correctly deserialized schemes.
    Because ciphertexts are connected to schemes, you want ciphertexts coming from the same scheme
    to still have the same scheme when they are deserialized.

    :param elgamalbase: ElGamalBase subscheme under test.
    """
    scheme = elgamalbase
    ciphertext_1 = scheme.encrypt(1)
    ciphertext_2 = scheme.encrypt(2)
    ser_1 = ciphertext_1.serialize()
    ser_2 = ciphertext_2.serialize()
    new_ciphertext_1 = ciphertext_1.deserialize(ser_1)
    new_ciphertext_2 = ciphertext_1.deserialize(ser_2)

    new_ciphertext_1.scheme.shut_down()
    scheme.shut_down()

    assert (
        new_ciphertext_1.scheme
        is new_ciphertext_2.scheme
        is ciphertext_1.scheme
        is ciphertext_2.scheme
    )


def test_instances_from_security_param_elgamal(
    elgamalbase: ElGamal | ElGamalAdditive,
) -> None:
    """
    Test whether the get_instance_from_sec_param method works as intended. If an ElGamal scheme
    with the given parameters has already been created before, then that exact same scheme should be
    returned. Otherwise, a new scheme should be generated with those parameters.

    :param elgamalbase: ElGamalBase subscheme under test.
    """
    scheme_type = type(elgamalbase)

    new_elgamal_1 = scheme_type.from_security_parameter(256)
    new_elgamal_1.save_globally()
    new_elgamal_2 = scheme_type.from_id(new_elgamal_1.identifier)
    new_elgamal_3 = scheme_type.from_security_parameter(256)

    new_elgamal_1.shut_down()
    new_elgamal_2.shut_down()
    new_elgamal_3.shut_down()

    assert new_elgamal_1 is new_elgamal_2
    assert new_elgamal_1 is not new_elgamal_3
    assert new_elgamal_2 is not new_elgamal_3
    assert new_elgamal_1 != new_elgamal_3
    assert new_elgamal_2 != new_elgamal_3


async def send_and_receive(pools: tuple[Pool, Pool], obj: Any) -> Any:
    """
    Method that sends objects from one party to another.

    :param pools: collection of communication pools
    :param obj: object to be sent
    :return: the received object
    """
    # send from host 1 to host 2
    await pools[0].send("local1", obj)
    item = await pools[1].recv("local0")
    return item


@pytest.mark.asyncio
async def test_sending_and_receiving(
    elgamalbase: ElGamal | ElGamalAdditive, http_pool_duo: tuple[Pool, Pool]
) -> None:
    """
    This test ensures that serialisation logic is correctly loading into the
    communication module.

    :param elgamalbase: ElGamalBase subscheme under test.
    :param http_pool_duo: Collection of two communication pools.
    """
    elgamalbase_prime = await send_and_receive(http_pool_duo, elgamalbase)
    assert type(elgamalbase).from_id(elgamalbase.identifier) is elgamalbase
    assert elgamalbase_prime is elgamalbase
    # the scheme has been sent once, so the httpclients should be in the scheme's client
    # history.
    assert len(elgamalbase.client_history) == 2
    assert elgamalbase.client_history[0] == http_pool_duo[0].pool_handlers["local1"]
    assert elgamalbase.client_history[1] == http_pool_duo[1].pool_handlers["local0"]

    encryption = elgamalbase.encrypt(plaintext=4)
    encryption_prime: ElGamalBaseCipherText = await send_and_receive(
        http_pool_duo, encryption
    )
    encryption_prime.scheme.shut_down()
    assert encryption == encryption_prime

    public_key_prime = await send_and_receive(http_pool_duo, elgamalbase.public_key)
    assert elgamalbase.public_key == public_key_prime

    secret_key_prime = await send_and_receive(http_pool_duo, elgamalbase.secret_key)
    assert elgamalbase.secret_key == secret_key_prime


@pytest.mark.asyncio
async def test_broadcasting(
    elgamalbase: ElGamal | ElGamalAdditive, http_pool_trio: tuple[Pool, Pool, Pool]
) -> None:
    """
    This test ensures that broadcasting ElGamal ciphertexts works as expected.

    :param elgamalbase: ElGamalBase subscheme under test.
    :param http_pool_trio: Collection of three communication pools.
    """
    await asyncio.gather(
        *(
            http_pool_trio[0].send("local1", elgamalbase),
            http_pool_trio[0].send("local2", elgamalbase),
        )
    )
    scheme_prime_1, scheme_prime_2 = await asyncio.gather(
        *(http_pool_trio[1].recv("local0"), http_pool_trio[2].recv("local0"))
    )
    assert type(elgamalbase).from_id(elgamalbase.identifier) is elgamalbase
    assert scheme_prime_1 is elgamalbase
    assert scheme_prime_2 is elgamalbase
    # the scheme has been sent once to each party, so the httpclients should be in the scheme's
    # client history.
    assert len(elgamalbase.client_history) == 3
    assert http_pool_trio[0].pool_handlers["local1"] in elgamalbase.client_history
    assert http_pool_trio[0].pool_handlers["local2"] in elgamalbase.client_history
    assert http_pool_trio[1].pool_handlers["local0"] in elgamalbase.client_history
    assert http_pool_trio[2].pool_handlers["local0"] in elgamalbase.client_history

    encryption = elgamalbase.encrypt(plaintext=42)
    await http_pool_trio[0].broadcast(encryption, "msg_id")
    encryption_prime_1, encryption_prime_2 = cast(
        Tuple[ElGamalBaseCipherText, ElGamalBaseCipherText],
        await asyncio.gather(
            *(
                http_pool_trio[1].recv("local0", "msg_id"),
                http_pool_trio[2].recv("local0", "msg_id"),
            )
        ),
    )

    encryption_prime_1.scheme.shut_down()
    encryption_prime_2.scheme.shut_down()
    assert encryption == encryption_prime_1
    assert encryption == encryption_prime_2
