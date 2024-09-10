"""
Base implementation of the Asymmetric Encryption Scheme known as multiplicative ElGamal.
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


class ElGamalCipherText(ElGamalBaseCipherText):
    """
    Ciphertext for the ElGamal encryption scheme that is multiplicatively homomorphic.
    """

    scheme: ElGamal

    def is_zero(self) -> bool:
        """
        Determine if the underlying plaintext of a ciphertext equals 0, without doing a full
        decryption.

        :return: True if plaintext is 0, False otherwise.
        """
        return self.scheme.is_zero(self)

    # region Serialization logic

    @staticmethod
    def deserialize(
        obj: ElGamalBaseCipherText.SerializedElGamalBaseCipherText, **_kwargs: Any
    ) -> ElGamalCipherText:
        r"""
        Deserialization function for ElGamal ciphertexts, which will be passed to the
        communication module.

        :param obj: serialized version of a ElGamalCipherText.
        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized ElGamalCipherText from the given dict.
        """
        return deserialize_ciphertext(ElGamalCipherText, obj=obj, **_kwargs)

    # endregion


class ElGamal(ElGamalBase[ElGamalCipherText]):
    """
    Construct ElGamal encryption scheme that is multiplicatively homomorphic.
    """

    # Set the constructor for ElGamalBase's _unsafe_encrypt function to use
    CipherTextConstructor: ClassVar[type[ElGamalBaseCipherText]] = ElGamalCipherText

    def __init__(
        self,
        public_key: ElGamalPublicKey,
        secret_key: ElGamalSecretKey | None,
        share_secret_key: bool = False,
        debug: bool = False,
    ) -> None:
        """
        Construct a new multiplicatively homomorphic ElGamal encryption scheme with the given
        keypair.

        :param public_key: Public key for this ElGamal scheme.
        :param secret_key: Optional Secret Key for this ElGamal scheme (None when unknown).
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

        # Range of message values that can be encrypted with this ElGamal scheme, allowing for
        # negative numbers
        self.max_value = (public_key.p - 1) // 2
        self.min_value = -(public_key.p - ((public_key.p - 1) // 2 + 1))

    def encode(self, plaintext: Plaintext) -> EncodedPlaintext[Plaintext]:
        """
        Encode integers as integers.

        :param plaintext: Plaintext to be encoded.
        :raise ValueError: If the plaintext is outside the supported range of this ElGamal scheme.
        :return: EncodedPlaintext object containing the encoded value.
        """
        if not self.min_value <= plaintext <= self.max_value:
            raise ValueError(
                f"This encoding scheme only supports values in the range [{self.min_value};"
                f"{self.max_value}], {plaintext} is outside that range."
            )
        return EncodedPlaintext(plaintext, self)

    def decode(self, encoded_plaintext: EncodedPlaintext[int]) -> Plaintext:
        """
        Decode an EncodedPlaintext.

        :param encoded_plaintext: Encoded plaintext to be decoded.
        :return: Decoded plaintext value.
        """
        if 0 <= encoded_plaintext.value <= self.max_value:
            return encoded_plaintext.value
        return encoded_plaintext.value - self.public_key.p

    # By putting this functionality in the BaseCiphertext we can just reuse it here.
    def _unsafe_encrypt_raw(
        self, plaintext: EncodedPlaintext[int]
    ) -> ElGamalCipherText:
        r"""
        Encrypts an encoded (raw) plaintext value, but does not apply randomization. Given an
        encoded plaintext message $m \in \{0, ..., p-1\}$, we compute the unsafe ciphertext value as
        $(c_0, c_1) = (1, m) \mod p$.

        :param plaintext: EncodedPlaintext object containing the raw value to be encrypted.
        :return: Non-randomized ElGamalCipherText object containing the encrypted plaintext.
        """
        # For reasons of avoiding code duplication we implemented this as a static function on the
        # class. This is not meant to be used outside of this module which is why it is marked
        # protected, but we still need to use it here.
        return (
            ElGamalCipherText._unsafe_encrypt_raw(  # pylint: disable=protected-access
                plaintext, self
            )
        )

    def is_zero(self, ciphertext: ElGamalCipherText) -> bool:
        """
        Determine if the underlying plaintext of a ciphertext equals 0, without doing a full
        decryption.

        :param ciphertext: ElGamalCipherText object containing the ciphertext to be checked.
        :return: True if plaintext is 0, False otherwise.
        """
        return ciphertext.peek_value()[1] == 0

    def neg(self, ciphertext: ElGamalCipherText) -> ElGamalCipherText:
        """
        Negate the underlying plaintext of this ciphertext.

        The resulting ciphertext is fresh only if the original ciphertext was fresh. The original
        ciphertext is marked as non-fresh after the operation.

        :param ciphertext: ElGamalCipherText of which the underlying plaintext should be negated.
        :return: ElGamalCiphertext object corresponding to the negated plaintext.
        """
        if new_ciphertext_fresh := ciphertext.fresh:
            warnings.warn(WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning)

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        old_ciphertext = ciphertext.get_value()
        return ElGamalCipherText(
            (old_ciphertext[0], (-1 * old_ciphertext[1]) % self.public_key.p),
            self,
            fresh=new_ciphertext_fresh,
        )

    def mul(
        self,
        ciphertext_1: ElGamalCipherText,
        ciphertext_2: ElGamalCipherText | Plaintext,
    ) -> ElGamalCipherText:
        r"""
        Secure multiplication.

        If ciphertext_2 is another ElGamalCipherText, multiply the underlying plaintext value
        of ciphertext_1 with the underlying plaintext value of ciphertext_2. If it is a Plaintext,
        multiply the plaintext value with the underlying value of ciphertext_1.

        The resulting ciphertext is fresh only if at least one of the inputs was fresh. Both inputs
        are marked as non-fresh after the operation.

        :param ciphertext_1: First ElGamalCipherText of which the underlying plaintext is
            multiplied.
        :param ciphertext_2: Either an ElGamalCipherText of which the underlying plaintext is
            used for multiplication or a Plaintext that is used for multiplication.
        :raise AttributeError: When ciphertext_2 does not have the same public key as ciphertext_1
            object.
        :return: An ElGamalCipherText containing the encryption of the multiplication.
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
        return ElGamalCipherText(
            (
                old_ciphertext_1[0] * old_ciphertext_2[0] % self.public_key.p,
                old_ciphertext_1[1] * old_ciphertext_2[1] % self.public_key.p,
            ),
            self,
            fresh=new_ciphertext_fresh,
        )

    def pow(self, ciphertext: ElGamalCipherText, power: int) -> ElGamalCipherText:
        """
        Take the exponentiation the underlying plaintext value of this ciphertext with power as
        exponent.

        The resulting ciphertext is fresh only if the original ciphertext was fresh. The original
        ciphertext is marked as non-fresh after the operation.

        :param ciphertext: ElGamalAdditiveCiphertext of which the underlying plaintext is
            exponentiated.
        :param power: An integer exponent with which the plaintext underlying this ciphertext should
            be exponentiated.
        :raise TypeError: When the exponent is not an integer.
        :return: ElGamalAdditiveCiphertext containing the encryption of the exponentiation.
        """
        if not isinstance(power, int):
            raise TypeError(
                f"Type of  power should be an integer and not" f" {type(power)}."
            )

        if new_ciphertext_fresh := ciphertext.fresh:
            warnings.warn(WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning)

        ciphertext_value = ciphertext.get_value()

        if power < 0:
            ciphertext = ElGamalCipherText(
                (
                    mod_inv(ciphertext_value[0], self.public_key.p),
                    mod_inv(ciphertext_value[1], self.public_key.p),
                ),
                self,
                fresh=new_ciphertext_fresh,
            )
            power = -power

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        ciphertext_value = ciphertext.get_value()
        return ElGamalCipherText(
            (
                pow_mod(ciphertext_value[0], power, self.public_key.p),
                pow_mod(ciphertext_value[1], power, self.public_key.p),
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
    ) -> ElGamal:
        r"""
        Deserialization function for ElGamal schemes, which will be passed to
        the communication module.

        :param obj: serialized version of a ElGamal scheme.
        :param origin: HTTPClient representing where the message came from if applicable
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :raise ValueError: When a scheme is sent through ID without any prior communication of the
            scheme
        :return: Deserialized ElGamal scheme from the given dict. Might not have a secret
            key when that was not included in the received serialization.
        """
        return deserialize(ElGamal, obj=obj, origin=origin, **_kwargs)

    # endregion


if COMMUNICATION_INSTALLED:
    try:
        Serialization.register_class(ElGamal)
        Serialization.register_class(ElGamalCipherText)
    except RepetitionError:
        pass
