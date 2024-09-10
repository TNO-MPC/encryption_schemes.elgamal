"""
Base implementation of the Asymmetric Encryption Scheme known as additive ElGamal.
"""

from __future__ import annotations

import warnings
from typing import Any, ClassVar

from tno.mpc.encryption_schemes.templates import (
    EncodedPlaintext,
    EncryptionSchemeWarning,
)
from tno.mpc.encryption_schemes.utils import mod_inv, pow_mod

from tno.mpc.encryption_schemes.elgamal.elgamal_base import (
    WARN_INEFFICIENT_HOM_OPERATION,
    ElGamalBase,
    ElGamalBaseCipherText,
    ElGamalPublicKey,
    ElGamalSecretKey,
    Plaintext,
    deserialize,
    deserialize_ciphertext,
)

# Check to see if the communication module is available
try:
    from tno.mpc.communication import RepetitionError, Serialization
    from tno.mpc.communication.httphandlers import HTTPClient

    COMMUNICATION_INSTALLED = True
except ModuleNotFoundError:
    COMMUNICATION_INSTALLED = False


class ElGamalAdditiveCiphertext(ElGamalBaseCipherText):
    """
    Ciphertext for the ElGamal encryption scheme that is additively homomorphic.
    """

    scheme: ElGamalAdditive

    # region Serialization logic

    @staticmethod
    def deserialize(
        obj: ElGamalBaseCipherText.SerializedElGamalBaseCipherText,
        **_kwargs: Any,
    ) -> ElGamalAdditiveCiphertext:
        r"""
        Deserialization function for ElGamalAdditive ciphertexts, which will be passed to the
        communication module.

        :param obj: serialized version of a ElGamalAdditiveCipherText.
        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized ElGamalAdditiveCiphertext from the given dict.
        """
        return deserialize_ciphertext(ElGamalAdditiveCiphertext, obj=obj, **_kwargs)

    # endregion


class ElGamalAdditive(ElGamalBase[ElGamalAdditiveCiphertext]):
    """
    Construct ElGamalAdditive encryption scheme that is additively homomorphic.
    """

    # Fixed-point decimals will be more dificult here.
    # Especially performance-wise on the decode side.

    # Set the constructor for ElGamalBase's _unsafe_encrypt function to use
    CipherTextConstructor: ClassVar[type[ElGamalBaseCipherText]] = (
        ElGamalAdditiveCiphertext
    )

    def __init__(
        self,
        public_key: ElGamalPublicKey,
        secret_key: ElGamalSecretKey | None,
        share_secret_key: bool = False,
        debug: bool = False,
    ) -> None:
        """
        Construct a new additively homomorphic ElGamal encryption scheme with the given keypair.

        :param public_key: Public key for this ElGamalAdditive scheme.
        :param secret_key: Optional Secret Key for this ElGamalAdditive scheme (None when unknown).
        :param share_secret_key: Boolean value stating whether or not the secret key should be
            included in serialization. This should only be set to True if one is really sure of it.
        :param debug: flag to determine whether debug information should be displayed.
        """
        super().__init__(
            public_key,
            secret_key,
            share_secret_key,
            debug,
        )

        # Range of message values that can be encrypted with this ElGamalAdditive scheme.
        # Here we assume a group with a safe prime modulus $p$ is used and the used generator has
        # order $p-1$
        self.max_value = (public_key.p - 1) // 2
        self.min_value = -((public_key.p - 1) // 2 - 1)

    def encode(self, plaintext: Plaintext) -> EncodedPlaintext[int]:
        r"""
        Encode message $m$ (int) as $g^m \mod p$ (int).

        :param plaintext: Plaintext to be encoded.
        :raise ValueError: If the plaintext is outside the supported range of this ElGamal scheme.
        :return: EncodedPlaintext object containing the encoded value.
        """
        if not self.min_value <= plaintext <= self.max_value:
            raise ValueError(
                f"This encoding scheme only supports values in the range [{self.min_value};"
                f"{self.max_value}], {plaintext} is outside that range."
            )
        return EncodedPlaintext(
            pow_mod(self.public_key.g, plaintext, self.public_key.p), self
        )

    def decode(self, encoded_plaintext: EncodedPlaintext[int]) -> Plaintext:
        """
        Decode an EncodedPlaintext using Pollard's rho algorithm for discrete logarithms.

        :param encoded_plaintext: Encoded plaintext to be decoded.
        :raise ValueError: When ciphertext cannot be decoded because it is out of range.
        :return: Decoded plaintext value.
        """
        g_inv = mod_inv(self.public_key.g, self.public_key.p)
        power = 1
        inv_power = 1
        for i in range(self.max_value + 1):
            if power == encoded_plaintext.value:
                return i
            if inv_power == encoded_plaintext.value:
                return -i
            power *= self.public_key.g
            power %= self.public_key.p
            inv_power *= g_inv
            inv_power %= self.public_key.p
        raise ValueError("Given ciphertext could not be decoded, was out of range")

    # By putting this functionality in the BaseCiphertext we can just reuse it here.
    def _unsafe_encrypt_raw(
        self, plaintext: EncodedPlaintext[int]
    ) -> ElGamalAdditiveCiphertext:
        r"""
        Encrypts an encoded (raw) plaintext value, but does not apply randomization. Given an
        encoded plaintext message $g^m \in \{0, ..., p-1\}$, we compute the unsafe ciphertext value
        as $(c_0, c_1) = (1, g^m) \mod p$.

        :param plaintext: EncodedPlaintext object containing the raw value to be encrypted.
        :return: Non-randomized ElGamalCipherText object containing the encrypted plaintext.
        """
        return ElGamalAdditiveCiphertext._unsafe_encrypt_raw(  # pylint: disable=protected-access
            plaintext, self
        )

    def neg(self, ciphertext: ElGamalAdditiveCiphertext) -> ElGamalAdditiveCiphertext:
        """
        Negate the underlying plaintext of this ciphertext.

        The resulting ciphertext is fresh only if the original ciphertext was fresh. The original
        ciphertext is marked as non-fresh after the operation.

        :param ciphertext: ElGamalAdditiveCiphertext of which the underlying plaintext should be
            negated.
        :return: ElGamalAdditiveCiphertext object corresponding to the negated plaintext.
        """
        if new_ciphertext_fresh := ciphertext.fresh:
            warnings.warn(WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning)

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        old_ciphertext = ciphertext.get_value()
        return ElGamalAdditiveCiphertext(
            (
                mod_inv(old_ciphertext[0], self.public_key.p),
                mod_inv(old_ciphertext[1], self.public_key.p),
            ),
            self,
            fresh=new_ciphertext_fresh,
        )

    def mul(  # type: ignore  # pylint: disable=arguments-renamed
        self, ciphertext: ElGamalAdditiveCiphertext, scalar: int
    ) -> ElGamalAdditiveCiphertext:
        """
        Multiply the underlying plaintext value of this ciphertext with a scalar.

        The resulting ciphertext is fresh only if the original ciphertext was fresh. The original
        ciphertext is marked as non-fresh after the operation.

        :param ciphertext: ElGamalAdditiveCiphertext of which the underlying plaintext is
            multiplied.
        :param scalar: A scalar with which the plaintext underlying this ciphertext should be
            multiplied.
        :raise TypeError: When the scalar is not an integer.
        :return: ElGamalAdditiveCiphertext containing the encryption of the product.
        """
        if not isinstance(scalar, int):
            raise TypeError(
                f"Type of  scalar (second multiplicand) should be an integer and not"
                f" {type(scalar)}."
            )
        if scalar < 0:
            ciphertext = self.neg(ciphertext)
            scalar = -scalar

        if new_ciphertext_fresh := ciphertext.fresh:
            warnings.warn(WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning)

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        ciphertext_value = ciphertext.get_value()
        return ElGamalAdditiveCiphertext(
            (
                pow_mod(ciphertext_value[0], scalar, self.public_key.p),
                pow_mod(ciphertext_value[1], scalar, self.public_key.p),
            ),
            self,
            fresh=new_ciphertext_fresh,
        )

    def add(
        self,
        ciphertext_1: ElGamalAdditiveCiphertext,
        ciphertext_2: ElGamalAdditiveCiphertext | Plaintext,
    ) -> ElGamalAdditiveCiphertext:
        r"""
        Secure addition.

        If ciphertext_2 is another ElGamalAdditiveCiphertext, add the underlying plaintext
        value of ciphertext_1 to the underlying plaintext value of ciphertext_2. If it is a
        Plaintext, add the plaintext value to the underlying value of ciphertext_1.

        The resulting ciphertext is fresh only if at least one of the inputs was fresh. Both inputs
        are marked as non-fresh after the operation.

        :param ciphertext_1: ElGamalAdditiveCiphertext of which the underlying plaintext is added.
        :param ciphertext_2: Either an ElGamalAdditiveCiphertext of which the underlying
            plaintext is used for addition or a Plaintext that is used for addition.
        :raise AttributeError: When ciphertext does not have the same public key as this ciphertext
            object.
        :return: An ElGamalAdditiveCiphertext containing the encryption of the addition.
        """
        if isinstance(ciphertext_2, Plaintext):
            ciphertext_2 = self.unsafe_encrypt(ciphertext_2)
        elif ciphertext_1.scheme != ciphertext_2.scheme:
            raise AttributeError(
                "The public key of your first ciphertext is not equal to the "
                "public key of your second ciphertext."
            )

        if new_ciphertext_fresh := ciphertext_1.fresh or ciphertext_2.fresh:
            warnings.warn(WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning)

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        old_ciphertext_1 = ciphertext_1.get_value()
        old_ciphertext_2 = ciphertext_2.get_value()
        return ElGamalAdditiveCiphertext(
            (
                old_ciphertext_1[0] * old_ciphertext_2[0] % self.public_key.p,
                old_ciphertext_1[1] * old_ciphertext_2[1] % self.public_key.p,
            ),
            self,
            fresh=new_ciphertext_fresh,
        )

    # region Serialization logic

    @staticmethod
    def deserialize(
        obj: ElGamalBase.SerializedElGamalBase,
        *,
        origin: HTTPClient | None = None,
        **_kwargs: Any,
    ) -> ElGamalAdditive:
        r"""
        Deserialization function for ElGamalAdditive schemes, which will be passed to
        the communication module.

        :param obj: serialized version of a ElGamalAdditive scheme.
        :param origin: HTTPClient representing where the message came from if applicable
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :raise ValueError: When a scheme is sent through ID without any prior communication of the
            scheme
        :return: Deserialized ElGamalAdditive scheme from the given dict. Might not have a secret
            key when that was not included in the received serialization.
        """
        return deserialize(ElGamalAdditive, obj=obj, origin=origin, **_kwargs)

    # endregion


if COMMUNICATION_INSTALLED:
    try:
        Serialization.register_class(ElGamalAdditive)
        Serialization.register_class(ElGamalAdditiveCiphertext)
    except RepetitionError:
        pass
