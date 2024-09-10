"""
Root imports for the tno.mpc.encryption_schemes.elgamal package.

This package implements the ElGamal crpytosystem.
It supports both multiplicative and additive homomorphic versions of the system.
The additive version has significant inherent limitations to decryption.

Both versions use the same Public and Secret keys.
"""

#  pylint: disable=useless-import-alias

# Explicit re-export of all functionalities, such that they can be imported properly. Following
# https://www.python.org/dev/peps/pep-0484/#stub-files and
# https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal as ElGamal
from tno.mpc.encryption_schemes.elgamal.elgamal import (
    ElGamalCipherText as ElGamalCipherText,
)
from tno.mpc.encryption_schemes.elgamal.elgamal_additive import (
    ElGamalAdditive as ElGamalAdditive,
)
from tno.mpc.encryption_schemes.elgamal.elgamal_additive import (
    ElGamalAdditiveCiphertext as ElGamalAdditiveCiphertext,
)
from tno.mpc.encryption_schemes.elgamal.elgamal_base import (
    ElGamalPublicKey as ElGamalPublicKey,
)
from tno.mpc.encryption_schemes.elgamal.elgamal_base import (
    ElGamalSecretKey as ElGamalSecretKey,
)

__version__ = "1.1.5"
