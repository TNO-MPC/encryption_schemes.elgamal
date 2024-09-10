# TNO PET Lab - secure Multi-Party Computation (MPC) - Encryption Schemes - ElGamal

This package provides implementations of the multiplicative and additive versions of the ElGamal encryption scheme.

Supports:

- Positive and negative numbers.
- Multiplicative homomorphic multiplication of ciphertexts, negation of ciphertexts, exponentiation of ciphertexts with integral powers, check for zero underlying plaintext.
- Additive ElGamal: homomorphic addition of ciphertexts, negation of ciphertexts, multiplication of ciphertext with integral scalars.

### PET Lab

The TNO PET Lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of PET solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed PET functionalities to boost the development of new protocols and solutions.

The package `tno.mpc.encryption_schemes.elgamal` is part of the [TNO Python Toolbox](https://github.com/TNO-PET).

_Limitations in (end-)use: the content of this software package may solely be used for applications that comply with international export control laws._  
_This implementation of cryptographic software has not been audited. Use at your own risk._

## Documentation

Documentation of the `tno.mpc.encryption_schemes.elgamal` package can be found
[here](https://docs.pet.tno.nl/mpc/encryption_schemes/elgamal/1.1.5).

## Install

Easily install the `tno.mpc.encryption_schemes.elgamal` package using `pip`:

```console
$ python -m pip install tno.mpc.encryption_schemes.elgamal
```

_Note:_ If you are cloning the repository and wish to edit the source code, be
sure to install the package in editable mode:

```console
$ python -m pip install -e 'tno.mpc.encryption_schemes.elgamal'
```

If you wish to run the tests you can use:

```console
$ python -m pip install 'tno.mpc.encryption_schemes.elgamal[tests]'
```
_Note:_ A significant performance improvement can be achieved by installing the GMPY2 library.

```console
$ python -m pip install 'tno.mpc.encryption_schemes.elgamal[gmpy]'
```

## Basic usage

Basic usage of the multiplicative variant of ElGamal is as follows.
Note that only the multiplicative variant of ElGamal allows for checking whether the plaintext is equal to zero without decrypting.
This is explained in the [background](#background-of-the-elgamal-scheme) section.

```python
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal

if __name__ == "__main__":
    # initialize ElGamal with key length of 1024 bits
    elgamal_scheme = ElGamal.from_security_parameter(bits=1024)
    # encrypt the number 8
    ciphertext1 = elgamal_scheme.encrypt(8)
    # multiply the original plaintext by 5
    ciphertext1 *= 5
    # take the original plaintext to the power 2
    ciphertext1 **= 2
    # check whether the ciphertext is equal to zero
    assert not ciphertext1.is_zero()
    # encrypt the number 10
    ciphertext2 = elgamal_scheme.encrypt(10)
    # multiply the encrypted numbers with each other
    encrypted_multiplication = ciphertext1 * ciphertext2
    # ...communication...
    # decrypt the encrypted sum to 16000
    decrypted_multiplication = elgamal_scheme.decrypt(encrypted_multiplication)
    assert decrypted_multiplication == 16000
```

Basic usage of the additive variant of ElGamal is as follows.

```python
from tno.mpc.encryption_schemes.elgamal.elgamal_additive import ElGamalAdditive

if __name__ == "__main__":
    # initialize ElGamalAdditive with key length of 1024 bits
    elgamal_additive_scheme = ElGamalAdditive.from_security_parameter(bits=1024)
    # encrypt the number 8
    ciphertext1 = elgamal_additive_scheme.encrypt(8)
    # add 5 to the original plaintext
    ciphertext1 += 5
    # multiply the original plaintext by 10
    ciphertext1 *= 10
    # encrypt the number 10
    ciphertext2 = elgamal_additive_scheme.encrypt(10)
    # add both encrypted numbers together
    encrypted_sum = ciphertext1 + ciphertext2
    # ...communication...
    # decrypt the encrypted sum to 140
    decrypted_sum = elgamal_additive_scheme.decrypt(encrypted_sum)
    assert decrypted_sum == 140
```

Running this example will show several warnings. The remainder of this documentation explains why the warnings are issued and how to get rid of them depending on the users' preferences.

## Fresh and unfresh ciphertexts

An encrypted message is called a ciphertext. A ciphertext in the current package has a property `is_fresh` that indicates whether this ciphertext has fresh randomness, in which case it can be communicated to another player securely. More specifically, a ciphertext `c` is fresh if another user, knowledgeable of all prior communication and all current ciphertexts marked as fresh, cannot deduce any more private information from learning `c`.

The package understands that the freshness of the result of a homomorphic operation depends on the freshness of the inputs, and that the homomorphic operation renders the inputs unfresh. For example, if `c1` and `c2` are fresh ciphertexts, then `c12 = c1 + c2` is marked as a fresh encryption (no rerandomization needed) of the sum of the two underlying plaintexts. After the operation, ciphertexts `c1` and `c2` are no longer fresh.

The fact that `c1` and `c2` were both fresh implies that, at some point, we randomized them. After the operation `c12 = c1 + c2`, only `c12` is fresh. This implies that one randomization was lost in the process. In particular, we wasted resources. An alternative approach was to have unfresh `c1` and `c2` then compute the unfresh result `c12` and only randomize that ciphertext. This time, no resources were wasted. The package issues a warning to inform the user this and similar efficiency opportunities.

The package integrates naturally with `tno.mpc.communication` and if that is used for communication, its serialization logic will ensure that all sent ciphertexts are fresh. A warning is issued if a ciphertext was randomized in the proces. A ciphertext is always marked as unfresh after it is serialized. Similarly, all received ciphertexts are considered unfresh.

## Tailor behavior to your needs

The crypto-neutral developer is facilitated by the package as follows: the package takes care of all bookkeeping, and the serialization used by `tno.mpc.communication` takes care of all randomization. The warnings can be [disabled](#warnings) for a smoother experience.

The eager crypto-youngster can improve their understanding and hone their skills by learning from the warnings that the package provides in a safe environment. The package is safe to use when combined with `tno.mpc.communication`. It remains to be safe while you transform your code from 'randomize-early' (fresh encryptions) to 'randomize-late' (unfresh encryptions, randomize before exposure). At that point you have optimized the efficiency of the library while ensuring that all exposed ciphertexts are fresh before they are serialized. In particular, you no longer rely on our serialization for (re)randomizing your ciphertexts.

Finally, the experienced cryptographer can turn off warnings / turn them into exceptions, or benefit from the `is_fresh` flag for own purposes (e.g. different serializer or communication).

### Warnings

By default, the `warnings` package prints only the first occurence of a warning for each location (module + line number) where the warning is issued. The user may easily [change this behaviour](https://docs.python.org/3/library/warnings.html#the-warnings-filter) to never see warnings:

```py
from tno.mpc.encryption_schemes.elgamal_base import EncryptionSchemeWarning

warnings.simplefilter("ignore", EncryptionSchemeWarning)
```

Alternatively, the user may pass `"once"`, `"always"` or even `"error"`.

Finally, note that some operations issue two warnings, e.g. `c1-c2` issues a warning for computing `-c2` and a warning for computing `c1 + (-c2)`.

## Advanced usage

The [basic usage](#basic-usage) can be improved upon by explicitly randomizing at late as possible.

We demonstrate here for multiplicative ElGamal, but it works the analogous for additive ElGamal: instead of `encrypt()` one should use `unsafe_encrypt` and explicitly use `randomize()` after the local calculations are done.

```python
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal

if __name__ == "__main__":
    elgamal_scheme = ElGamal.from_security_parameter(bits=1024)
    # unsafe_encrypt does NOT randomize the generated ciphertext; it is deterministic still
    ciphertext1 = elgamal_scheme.unsafe_encrypt(8)
    ciphertext1 *= 5
    ciphertext1 **= 2
    ciphertext2 = elgamal_scheme.unsafe_encrypt(10)
    # no randomness can be wasted by multiplying the two unfresh encryptions
    encrypted_multiplication = ciphertext1 * ciphertext2
    # randomize the result, which is now fresh
    encrypted_multiplication.randomize()
    # ...communication...
    decrypted_multiplication = elgamal_scheme.decrypt(encrypted_multiplication)
    assert decrypted_multiplication == 16000
```

As explained [above](#fresh-and-unfresh-ciphertexts), this implementation avoids wasted randomization for `encrypted_multiplication` or `encrypted_sum` and therefore is more efficient.

## Speed-up encrypting and randomizing

Encrypting messages and randomizing ciphertexts is an involved operation that requires randomly generating large values and processing them in some way. This process can be sped up which will boost the performance of your script or package. The base package `tno.mpc.encryption_schemes.templates` provides several ways to more quickly generate randomness and we will show two of them below.

### Generate randomness with multiple processes on the background

The simplest improvement gain is to generate the required amount of randomness as soon as the scheme is initialized (so prior to any call to `randomize` or `encrypt`):

```py
from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal
# For the additive version, the above line should be replaced by
# from tno.mpc.encryption_schemes.elgamal.elgamal_additive import ElGamalAdditive

if __name__ == "__main__":
   # For the additive version, the ElGamal in the line below should be replaced by ElGamalAdditive.
    elgamal_scheme = ElGamal.from_security_parameter(bits=1024)
    elgamal_scheme.boot_randomness_generation(amount=5)
    # Possibly do some stuff here
    for msg in range(5):
        # The required randomness for encryption is already prepared, so this operation is faster.
        elgamal_scheme.encrypt(msg)
    elgamal_scheme.shut_down()
```

Calling `ElGamal.boot_randomness_generation` will generate a number of processes that is each tasked with generating some of the requested randomness. By default, the number of processes equals the number of CPUs on your device.

### Share ElGamal scheme and generate randomness a priori

A more advanced approach is to generate the randomness a priori and store it. Then, if you run your main protocol, all randomness is readily available. This looks as follows. First, the key-generating party generates a public-private keypair and shares the public key with the other participants. Now, every player pregenerates the amount of randomness needed for her part of the protocol and stores it in a file. For example, this can be done overnight or during the weekend. When the main protocol is executed, every player uses the same scheme (public key) as communicated before, configures the scheme to use the pregenerated randomness from file, and runs the main protocol without the need to generate randomness for encryption at that time. A minimal example is provided below.

```py
from pathlib import Path
from typing import List

from tno.mpc.communication import Serialization
from tno.mpc.encryption_schemes.templates.random_sources import FileSource

from tno.mpc.encryption_schemes.elgamal.elgamal import ElGamal, ElGamalCipherText


def deserializer(x: str) -> tuple[int, int]:
    """Deserialize a string representing a tuple of integers."""
    x = x.removeprefix("(").removesuffix(")")
    a, b = x.split(",")
    return int(a), int(b)


def initialize_and_store_scheme() -> None:
    # Generate scheme
    scheme = ElGamal.from_security_parameter(bits=1024)

    # Store without secret key for others
    with open(Path("scheme_without_secret_key"), "wb") as file:
        file.write(Serialization.pack(scheme, msg_id="", use_pickle=False))

    # Store with secret key for own use
    scheme.share_secret_key = True
    with open(Path("scheme_with_secret_key"), "wb") as file:
        file.write(Serialization.pack(scheme, msg_id="", use_pickle=False))

    # Tidy up to simulate real environment (program terminates)
    scheme.clear_instances()


def load_scheme(path: Path) -> ElGamal:
    # Load scheme from disk
    with open(path, "rb") as file:
        scheme_raw = file.read()
    return Serialization.unpack(scheme_raw)[1]


def pregenerate_randomness_in_weekend(scheme: ElGamal, amount: int, path: Path) -> None:
    # Generate randomness
    scheme.boot_randomness_generation(amount)
    # Save randomness to comma-separated csv
    with open(path, "w") as file:
        for _ in range(amount):
            file.write(f"{scheme.get_randomness()};")
    # Shut down processes gracefully
    scheme.shut_down()


def show_pregenerated_randomness(scheme: ElGamal, amount: int, path: Path) -> None:
    # Configure file as randomness source
    scheme.register_randomness_source(
        FileSource(path, delimiter=";", deserializer=deserializer)
    )
    # Consume randomness from file
    for i in range(amount):
        print(f"Random element {i}: {scheme.get_randomness()}")


def use_pregenerated_randomness_in_encryption(
    scheme: ElGamal, amount: int, path: Path
) -> List[ElGamalCipherText]:
    # Configure file as randomness source
    scheme.register_randomness_source(
        FileSource(path, delimiter=";", deserializer=deserializer)
    )
    # Consume randomness from file
    ciphertexts = [scheme.encrypt(_) for _ in range(amount)]
    return ciphertexts


def decrypt_result(scheme: ElGamal, ciphertexts: List[ElGamalCipherText]) -> None:
    # Show result
    for i, ciphertext in enumerate(ciphertexts):
        print(f"Decryption of ciphertext {i}: {scheme.decrypt(ciphertext)}")


if __name__ == "__main__":
    AMOUNT = 5
    RANDOMNESS_PATH = Path("randomness.csv")

    # Alice initializes, stores and distributes the ElGamal scheme
    initialize_and_store_scheme()

    # Tidy up to simulate real environment (second party doesn't yet have the ElGamal instance)
    ElGamal.clear_instances()

    # Bob loads the ElGamal scheme, pregenerates randomness and encrypts the values 0,...,AMOUNT-1
    scheme_without_secret_key = load_scheme("scheme_without_secret_key")
    assert (
        scheme_without_secret_key.secret_key is None
    ), "Loaded ElGamal scheme contains secret key! This is not supposed to happen."
    pregenerate_randomness_in_weekend(
        scheme_without_secret_key, AMOUNT, RANDOMNESS_PATH
    )
    show_pregenerated_randomness(scheme_without_secret_key, AMOUNT, RANDOMNESS_PATH)
    # Prints the following to screen (numbers will be different):
    # Random element 0: 663667452419034735381232312860937013...
    # Random element 1: ...
    # ...
    ciphertexts = use_pregenerated_randomness_in_encryption(
        scheme_without_secret_key, AMOUNT, RANDOMNESS_PATH
    )

    # Tidy up to simulate real environment (first party should use own ElGamal instance)
    ElGamal.clear_instances()

    # Alice receives the ciphertexts from Bob and decrypts them
    scheme_with_secret_key = load_scheme("scheme_with_secret_key")
    decrypt_result(scheme_with_secret_key, ciphertexts)
    # Prints the following to screen:
    # Decryption of ciphertext 0: 0.000
    # Decryption of ciphertext 1: 1.000
    # ...
```

# Background of the ElGamal scheme

The ElGamal encryption scheme is an asymmetric encryption scheme based on the discrete logarithm problem.
Although a seemingly simple scheme, here some of the design choices of the implementation are highlighted.

There are two versions of the scheme, allowing for multiplicative or additive homomorphic operations.
The multiplicative scheme is more widespread, therefore it is implemented in the `ElGamal` class.
The additive scheme is implemented in the `ElGamalAdditive` class.
Common functionality between the two versions are implemented in the `ElGamalBase` class.

Key material is created by generating a safe prime $p$ such that the multiplicative subgroup $\mathbb{Z}_p^*$ of $\mathbb{Z}_p$ is a cyclic group of order $p-1$, as well as a generator $g$ of this group and a random value $x \in \{1, ..., p - 2\}$, used to calculate $h = g^x$.
The secret key is then given by $(p, g, x)$ and the public key by $(p, g, h)$.

The current implementation generates the safe prime $p$ itself, but this takes a long time for large primes.
Therefore, key generation may take very long.
As a quicker alternative, one may want to consider using standardized safe primes, like can be found in the specification of [More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)](https://datatracker.ietf.org/doc/html/rfc3526) and [Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)](https://datatracker.ietf.org/doc/html/rfc7919).

The generator $g$ is chosen such that it generates $\mathbb{Z}_p^*$. This means $g$ should have order $p-1$, and thus $g$ not being equal to 1 and checking that it does not have order $2$ or $q$ is sufficient.

More on the considerations when implementing ElGamal can be found in this [paper](https://eprint.iacr.org/2021/923.pdf).

For the multiplicative scheme, a message $m$ is encrypted by taking some random value $r \in \{1, ..., p - 2\}$ (the same interval as the secret key is taken from) and calculating the ciphertext $(c_1, c_2) = (g^r, m \cdot h^r)$.
For the additive scheme, the ciphertext is calculated as $(c_1, c_2) = (g^r, g^m \cdot h^r)$.

Decryption of both versions is done by calculating $c_2 \cdot c_1^{-x}$. For the additive scheme, this results in $g^m$, so the discrete log must be taken in order to retrieve $m$. This cannot be done efficiently due to the hardness of the discrete log problem, so this additive scheme can only be used when the values to be decrypted are expected to be small. Currently, this discrete log is implemented as a brute force search, but depending on the application it could be speeded up with look up tables or the use of Pollard's kangaroo algorithm.
