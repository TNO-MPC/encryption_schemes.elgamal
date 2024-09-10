"""
Testing module of the tno.mpc.encryption_schemes.elgamal package.
"""

from contextlib import contextmanager
from typing import Iterator

import pytest

from tno.mpc.encryption_schemes.templates import EncryptionSchemeWarning


@contextmanager
def conditional_pywarn(truthy: bool, match: str) -> Iterator[None]:
    """
    Conditionally wraps statement in pytest.warns(EncryptionSchemeWarning) contextmanager.

    :param truthy: If True, activate pytest.warns contextmanager. Otherwise, do not activate a
        contextmanager.
    :param match: Match parameter for pytest.warns.
    :return: Context where EncyrptionSchemeWarning is expected if truthy holds.
    """
    if truthy:
        with pytest.warns(EncryptionSchemeWarning) as record:
            yield
            assert (
                len(record) >= 1  # Duplicate warnings possible
            ), f"Expected to catch one EncryptionSchemeWarning, caught {len(record)}."
            warn_messages = [str(rec.message) for rec in record]
            joined_messages = "\n".join(
                '"' + message + '"' for message in warn_messages
            )
            assert any(
                match == message for message in warn_messages
            ), f'Expected message "{match}", received messages:\n{joined_messages}.'
    else:
        yield
