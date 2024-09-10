"""
Base implementation of the Asymmetric Encryption Scheme known as ElGamal,
which is used for the multiplicative and additive variants of the scheme.
"""

from __future__ import annotations

import warnings
from dataclasses import asdict, dataclass
from functools import partial
from secrets import randbelow
from typing import Any, Tuple, TypedDict, TypeVar

from tno.mpc.encryption_schemes.templates import (
    AsymmetricEncryptionScheme,
    EncodedPlaintext,
    EncryptionSchemeWarning,
    PublicKey,
    RandomizableCiphertext,
    RandomizedEncryptionScheme,
    SecretKey,
    SerializationError,
)
from tno.mpc.encryption_schemes.utils import is_prime, mod_inv, pow_mod, randprime

# Check to see if the communication module is available
try:
    from tno.mpc.communication import RepetitionError, Serialization
    from tno.mpc.communication.httphandlers import HTTPClient

    COMMUNICATION_INSTALLED = True
except ModuleNotFoundError:
    COMMUNICATION_INSTALLED = False

WARN_INEFFICIENT_HOM_OPERATION = (
    "Identified a fresh ciphertext as input to a homomorphic operation, which is no longer fresh "
    "after the operation. This indicates a potential inefficiency if the non-fresh input may also "
    "be used in other operations (unused randomness). Solution: randomize ciphertexts as late as "
    "possible, e.g. by encrypting them with scheme.unsafe_encrypt and randomizing them just "
    "before sending. Note that the serializer randomizes non-fresh ciphertexts by default."
)

WARN_UNFRESH_SERIALIZATION = (
    "Serializer identified and rerandomized a non-fresh ciphertext."
)


@dataclass(frozen=True)
class ElGamalSecretKey(SecretKey):
    r"""
    SecretKey $(p, g, x)$ for the ElGamal encryption scheme,
    such that $p$ is prime and preferably $p-1$ contains a large prime factor (e.g. $p$ is safe),
    $g \in \mathbb{Z}^*_p$ such that $g$ generates $\mathbb{Z}^*_p$,
    and $x$ is a uniformly random integer between $1$ and $p-1$

    Constructor arguments:
    :param p: Modulus of the cyclic group used.
    :param g: Generator of the cyclic group used.
    :param x: Secret key value.
    """

    # pylint: disable=invalid-name
    p: int
    g: int
    x: int
    # pylint: enable=invalid-name

    def __str__(self) -> str:
        """
        Give string representation of this ElGamalSecretKey.

        :return: String representation of secret key prepended by (p, g, x) =
        """
        return f"(p, g, x) = ({self.p}, {self.g}, {self.x})"

    # region Serialization logic

    def serialize(self, **_kwargs: Any) -> dict[str, Any]:
        r"""
        Serialization function for secret keys, which will be passed to the communication module.

        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this ElGamalSecretKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return asdict(self)

    @staticmethod
    def deserialize(obj: dict[str, Any], **_kwargs: Any) -> ElGamalSecretKey:
        r"""
        Deserialization function for secret keys, which will be passed to the communication module

        :param obj: serialized version of a ElGamalSecretKey.
        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized ElGamalSecretKey from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return ElGamalSecretKey(**obj)

    # endregion


@dataclass(frozen=True)
class ElGamalPublicKey(PublicKey):
    r"""
    PublicKey $(p, g, h)$ for the ElGamal encryption scheme,
    such that $p$ is prime and preferably $p-1$ contains a large prime factor (e.g. $p$ is safe),
    $g \in \mathbb{Z}^*_p$ such that $g$ generates $\mathbb{Z}^*_p$,
    and $h = g^x$ for some secret key value $x$.

    Constructor arguments:
    :param p: Modulus of the cyclic group used.
    :param g: Generator of the cyclic group used.
    :param h: Public key value.
    """

    # pylint: disable=invalid-name
    p: int
    g: int
    h: int
    # pylint: enable=invalid-name

    def __str__(self) -> str:
        """
        Give string representation of this ElGamalPublicKey.

        :return: String representation of public key prepended by (p, g, h) =
        """
        return f"(p, g, h) = ({self.p}, {self.g}, {self.h})"

    # region Serialization logic

    def serialize(self, **_kwargs: Any) -> dict[str, Any]:
        r"""
        Serialization function for public keys, which will be passed to the communication module.

        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this ElGamalPublicKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return asdict(self)

    @staticmethod
    def deserialize(obj: dict[str, Any], **_kwargs: Any) -> ElGamalPublicKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module.

        :param obj: serialized version of a ElGamalPublicKey.
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized ElGamalPublicKey from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return ElGamalPublicKey(**obj)

    # endregion


KeyMaterial = Tuple[ElGamalPublicKey, ElGamalSecretKey]
Plaintext = int
RawPlaintext = int
RawCiphertext = Tuple[int, int]

CiphText = TypeVar("CiphText", bound="ElGamalBaseCipherText")


class ElGamalBaseCipherText(
    RandomizableCiphertext[
        KeyMaterial, Plaintext, int, Tuple[int, int], Tuple[int, int]
    ],
):
    """
    Ciphertext for the ElGamal encryption scheme.
    This ciphertext is rerandomizable and supports homomorphic operations.
    """

    scheme: ElGamalBase[Any]

    # This helper factory prevents implementing the actual encryption twice
    @classmethod
    def _unsafe_encrypt_raw(
        cls: type[CiphText],
        plaintext: EncodedPlaintext[int],
        scheme: ElGamalBase[Any],
    ) -> CiphText:
        r"""
        Encrypts an encoded (raw) plaintext value, but does not apply randomization. Given an
        encoded plaintext message $m \in \{0, ..., p-1\}$, we compute the unsafe ciphertext value as
        $(c_0, c_1) = (1, m) \mod p$.

        :param plaintext: EncodedPlaintext object containing the raw value to be encrypted.
        :return: Non-randomized ElGamalCipherText object containing the encrypted plaintext.
        """
        return cls((1, plaintext.value % scheme.public_key.p), scheme)

    def __init__(
        self, raw_value: RawCiphertext, scheme: ElGamalBase[Any], fresh: bool = False
    ) -> None:
        r"""
        Construct a new ElGamalCipherText.

        :param raw_value: Ciphertext pair $(c_1, c_2) \in \mathbb{Z}^*_p$.
        :param scheme: ElGamal scheme that is used to encrypt this ciphertext.
        :param fresh: Indicates whether fresh randomness is already applied to the raw_value.
        :raise TypeError: If the given scheme is not an ElGamal scheme.
        """
        if not isinstance(scheme, ElGamalBase):
            raise TypeError(
                f"Expected scheme of type ElGamalBase, got {scheme} instead"
            )
        super().__init__(raw_value, scheme, fresh=fresh)

    def apply_randomness(self, randomization_value: tuple[int, int]) -> None:
        r"""
        Rerandomize this ciphertext $(c_0, c_1)$ using the given random value pair $g^r, h^r$ by
        taking $(c_0 g^r, c_1 h^r) \mod p$.

        :param randomization_value: Random value used for rerandomization.
        """
        self._raw_value = (
            self._raw_value[0] * randomization_value[0] % self.scheme.public_key.p,
            self._raw_value[1] * randomization_value[1] % self.scheme.public_key.p,
        )

    def __eq__(self, other: object) -> bool:
        """
        Compare this ElGamalBaseCipherText with another object to determine (in)equality.

        :param other: Object to compare this ElGamalBaseCipherText with.
        :raise TypeError: If other object is not of the same type as this ElGamalBaseCipherText.
        :return: Boolean representation of (in)equality of both objects.
        """
        if not isinstance(other, ElGamalBaseCipherText):
            raise TypeError(
                f"Expected comparison with another ElGamalBaseCipherText, "
                f"got {type(other)} instead."
            )
        return self._raw_value == other._raw_value and self.scheme == other.scheme

    # region Serialization logic

    class SerializedElGamalBaseCipherText(TypedDict):
        value: tuple[int, int]
        scheme: ElGamalBase[Any]

    def serialize(
        self, **_kwargs: Any
    ) -> ElGamalBaseCipherText.SerializedElGamalBaseCipherText:
        r"""
        Serialization function for ElGamalBase ciphertexts, which will be passed to the
        communication module.

        If the ciphertext is not fresh, it is randomized before serialization. After serialization,
        it is always marked as not fresh for security reasons.

        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this ElGamalBaseCiphertext.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if not self.fresh:
            warnings.warn(
                WARN_UNFRESH_SERIALIZATION, EncryptionSchemeWarning, stacklevel=2
            )
            self.randomize()
        self._fresh = False
        return {
            "value": self._raw_value,
            "scheme": self.scheme,
        }

    # endregion


ElGamalBaseCipherTextType = TypeVar(
    "ElGamalBaseCipherTextType", bound="ElGamalBaseCipherText"
)


def deserialize_ciphertext(
    elgamalbaseciphertext_cls: type[ElGamalBaseCipherTextType],
    obj: ElGamalBaseCipherText.SerializedElGamalBaseCipherText,
    **_kwargs: Any,
) -> ElGamalBaseCipherTextType:
    r"""
    Deserialization function for ElGamalBase ciphertexts, which will be passed to the
    communication module.

    :param elgamalbaseciphertext_cls: ElGamalBaseCipherText class to deserialize to.
    :param obj: serialized version of a ElGamalBaseCipherText.
    :param \**_kwargs: Optional extra keyword arguments.
    :raise SerializationError: When communication library is not installed.
    :return: Deserialized ElGamalBaseCipherText from the given dict.
    """
    if not COMMUNICATION_INSTALLED:
        raise SerializationError()
    return elgamalbaseciphertext_cls(
        raw_value=obj["value"],
        scheme=obj["scheme"],
    )


class ElGamalBase(
    AsymmetricEncryptionScheme[
        KeyMaterial,
        Plaintext,
        RawPlaintext,
        RawCiphertext,
        CiphText,
        ElGamalPublicKey,
        ElGamalSecretKey,
    ],
    RandomizedEncryptionScheme[
        KeyMaterial, Plaintext, RawPlaintext, RawCiphertext, CiphText, Tuple[int, int]
    ],
):
    """
    ElGamal Encryption Scheme. This is an AsymmetricEncryptionScheme, with a public and secret key.
    This is also a RandomizedEncryptionScheme, thus having internal randomness generation and
    allowing for the use of precomputed randomness.
    """

    public_key: ElGamalPublicKey
    secret_key: ElGamalSecretKey

    def __init__(
        self,
        public_key: ElGamalPublicKey,
        secret_key: ElGamalSecretKey | None,
        share_secret_key: bool = False,
        debug: bool = False,
    ) -> None:
        """
        Construct a new ElGamal encryption scheme.

        :param public_key: Public key for this ElGamal Scheme.
        :param secret_key: Optional Secret Key for this ElGamal Scheme (None when unknown).
        :param share_secret_key: Boolean value stating whether or not the secret key should be
            included in serialization. This should only be set to True if one is really sure of it.
        :param debug: flag to determine whether debug information should be displayed.
        """
        self._generate_randomness = partial(  # type: ignore[method-assign]
            self._generate_randomness_from_args,
            public_p=public_key.p,
            public_g=public_key.g,
            public_h=public_key.h,
        )
        AsymmetricEncryptionScheme.__init__(
            self, public_key=public_key, secret_key=secret_key
        )
        RandomizedEncryptionScheme.__init__(
            self,
            debug=debug,
        )

        # Variable that determines whether a secret key is sent when the scheme is sent
        # over a communication channel
        self.share_secret_key = share_secret_key

        self.client_history: list[HTTPClient] = []

    @staticmethod
    def generate_key_material(bits: int) -> KeyMaterial:
        r"""
        Method to generate key material (ElGamalPublicKey and ElGamalSecretKey), consisting of a
        safe prime $p$ so $Z_p^*$ is a cyclic group of order $p-1$, a generator $g$ of this group
        and a random value $x \in \{1, ..., p - 2\}$, used to calculate $h = g^x$.

        :param bits: Bit length of prime field size $p$.
        :raise ValueError: When the given number of bits is not positive.
        :return: Tuple with first the public key and then the secret key.
        """
        # Pylint does not like our single-letter variables.
        # pylint: disable=invalid-name
        if bits <= 0:
            raise ValueError(
                f"For generating keys we need a positive keylength, {bits} is too low."
            )

        # First we find a safe prime.
        p = 1
        q = 0
        while True:
            q = randprime(2 ** (bits - 2), 2 ** (bits - 1))
            p = 2 * q + 1
            if is_prime(p):
                break

        # Find the smallest generator of the cyclic group of invertible integers mod p,
        # of order p - 1.
        for g in range(2, p - 1):
            if pow_mod(g, q, p) != 1 and pow_mod(g, 2, p) != 1:
                break

        # Choose random private key value x in range [1, p - 2].
        x = randbelow(p - 2) + 1

        # Calculate public key value h = g^x.
        h = pow_mod(g, x, p)

        return ElGamalPublicKey(p, g, h), ElGamalSecretKey(p, g, x)
        # pylint: enable=invalid-name

    def _decrypt_raw(self, ciphertext: ElGamalBaseCipherText) -> EncodedPlaintext[int]:
        """
        Decrypts an ElGamalBaseCipherText to its encoded plaintext value.

        :param ciphertext: ElGamalBaseCipherText object containing the ciphertext to be decrypted.
        :return: EncodedPlaintext object containing the encoded decryption of the ciphertext.
        """
        ciphertext_value = ciphertext.peek_value()
        if self.secret_key is None:
            raise ValueError(
                "This scheme only has a public key. Hence it cannot decrypt."
            )
        helper_value = pow_mod(
            ciphertext_value[0], self.secret_key.x, self.public_key.p
        )
        helper_value_inv = mod_inv(helper_value, self.public_key.p)
        message = ciphertext_value[1] * helper_value_inv
        message %= self.public_key.p
        return EncodedPlaintext(message, self)

    @staticmethod
    def _generate_randomness_from_args(
        public_p: int, public_g: int, public_h: int
    ) -> tuple[int, int]:
        r"""
        Method to generate randomness value pair $g^r, h^r$ with $r \in_R \{1,...,p-2\}$
        for ElGamal.

        :param public_p: Modulus $p$ of a cyclic group.
        :param public_g: Generator $g$ the the cyclic group.
        :param public_h: The public key, a group element such that $h = g^x$ for some random $x$.
        :return: The pair $g^r, h^r$.
        """
        random_element = randbelow(public_p - 2) + 1
        return (
            pow_mod(public_g, random_element, public_p),
            pow_mod(public_h, random_element, public_p),
        )

    def __eq__(self, other: object) -> bool:
        """
        Compare this ElGamalBase scheme with another object to determine (in)equality.

        :param other: Object to compare this ElGamalBase scheme with.
        :return: Boolean representation of (in)equality of both objects.
        """
        return isinstance(other, type(self)) and self.public_key == other.public_key

    @classmethod
    def id_from_arguments(cls, public_key: ElGamalPublicKey) -> int:
        """
        Method that turns the arguments for the constructor into an identifier. This identifier is
        used to find constructor calls that would result in identical schemes.

        :param public_key: ElGamalPublicKey of the ElGamalBase instance
        :return: Identifier of the ElGamalBase instance
        """
        return hash((public_key, cls))

    # region Serialization logic

    class SerializedElGamalBase(TypedDict, total=False):
        scheme_id: int
        pubkey: ElGamalPublicKey
        seckey: ElGamalSecretKey

    def serialize(
        self,
        *,
        destination: HTTPClient | list[HTTPClient] | None = None,
        **_kwargs: Any,
    ) -> ElGamalBase.SerializedElGamalBase:
        r"""
        Serialization function for ElGamalBase schemes, which will be passed to the communication
        module. The sharing of the secret key depends on the attribute share_secret_key.

        :param destination: HTTPClient representing where the message will go if applicable, can
            also be a list of clients in case of a broadcast message.
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this ElGamalBase scheme.
        """
        if isinstance(destination, HTTPClient):
            destination = [destination]
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if self.identifier not in self._instances:
            self.save_globally()
        if destination is not None and all(
            d in self.client_history for d in destination
        ):
            return {
                "scheme_id": self.identifier,
            }
        if destination is not None:
            for dest in destination:
                if dest not in self.client_history:
                    self.client_history.append(dest)
        if self.share_secret_key:
            return self.serialize_with_secret_key()
        return self.serialize_without_secret_key()

    def serialize_with_secret_key(
        self,
    ) -> ElGamalBase.SerializedElGamalBase:
        """
        Serialization function for ElGamalBase schemes, that does include the secret key.

        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this ElGamalBase scheme.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "pubkey": self.public_key,
            "seckey": self.secret_key,
        }

    def serialize_without_secret_key(self) -> ElGamalBase.SerializedElGamalBase:
        """
        Serialization function for ElGamalBase schemes, that does not include the secret key.

        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this ElGamalBase scheme (without the secret key).
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "pubkey": self.public_key,
        }

    # endregion


ElGamalType = TypeVar("ElGamalType", bound=ElGamalBase[Any])


def deserialize(
    elgamal_cls: type[ElGamalType],
    obj: ElGamalBase.SerializedElGamalBase,
    *,
    origin: HTTPClient | None = None,
    **_kwargs: Any,
) -> ElGamalType:
    r"""
    Deserialization function for ElGamalBase schemes, which will be passed to
    the communication module.

    :param elgamal_cls: ElGamal or ElGamalAdditive scheme class to deserialize to.
    :param obj: Serialized version of a scheme.
    :param origin: HTTPClient representing where the message came from if applicable.
    :param \**_kwargs: Optional extra keyword arguments.
    :raise SerializationError: When communication library is not installed.
    :raise ValueError: When a scheme is sent through ID without any prior communication of the
        scheme
    :return: Deserialized ElGamal or ElGamalAdditive scheme from the given dict. Might not have
        a secret key when that was not included in the received serialization.
    """
    if not COMMUNICATION_INSTALLED:
        raise SerializationError()
    if "scheme_id" in obj:
        elgamalbase: ElGamalType = elgamal_cls.from_id(
            obj["scheme_id"]
        )  # not sure whether this type hint works
        if origin is None:
            raise ValueError(
                f"The scheme was sent through an ID, but the origin is {origin}"
            )
        if origin not in elgamalbase.client_history:
            raise ValueError(
                f"The scheme was sent through an ID by {origin.addr}:{origin.port}, "
                f"but this scheme was never"
                "communicated with this party"
            )
    else:
        pubkey = obj["pubkey"]
        # This piece of code is specifically used for the case where sending and receiving
        # happens between hosts running the same python instance (local network).
        # In this case, the ElGamal scheme that was sent is already available before it
        # arrives and does not need to be created anymore.
        identifier = elgamal_cls.id_from_arguments(public_key=pubkey)
        if identifier in elgamal_cls._instances:
            elgamalbase = elgamal_cls.from_id(identifier)
        else:
            elgamalbase = elgamal_cls(
                public_key=pubkey,
                secret_key=obj["seckey"] if "seckey" in obj else None,
            )
            elgamalbase.save_globally()
    if origin is not None and origin not in elgamalbase.client_history:
        elgamalbase.client_history.append(origin)
    return elgamalbase


if COMMUNICATION_INSTALLED:
    try:
        Serialization.register_class(ElGamalPublicKey)
        Serialization.register_class(ElGamalSecretKey)
    except RepetitionError:
        pass
