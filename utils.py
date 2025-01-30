# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0

"""
Utility Functions for Chat Application

This module provides a collection of utility functions, primarily focused on cryptographic
operations, that are used throughout the chat application. The functions include key
generation, encryption, decryption, signing, verification, and other supporting utilities
such as configuration reading and date manipulation.

The module includes the following functions:

    * read_config - Reads and returns the user configuration from a given config file.
    * generate_keypair_ECDH - Generates a key pair for Elliptic-Curve Diffie-Hellman (ECDH).
    * generate_keypair_Ed25519 - Generates a key pair for Ed25519 signature scheme.
    * public_key_to_der - Converts a public key to DER format.
    * der_to_public_key - Loads a public key from DER format.
    * private_key_to_der - Converts a private key to DER format.
    * der_to_private_key - Loads a private key from DER format.
    * perform_x25519_ecdh - Performs the X25519 ECDH key exchange by computing the shared secret.
    * derive_shared_AES_key - Derives a shared AES key using HKDF based on the shared secret.
    * encrypt_message - Encrypts a plaintext message using AES-GCM.
    * decrypt_message - Decrypts a message encrypted with AES-GCM.
    * sign_with_Ed25519 - Signs data using the Ed25519 private key.
    * verify_Ed25519_signature - Verifies a signature using the Ed25519 public key.
    * compute_sha256_hash - Computes the SHA-256 hash of the given data.
    * compute_hash_chain - Computes a chain of SHA-256 hashes from a seed value.
    * get_current_date - Returns the current system date and time.
    * set_fake_date - Overrides the current date and time with a fake date for testing.
    * reset_date - Resets the date and time to the actual system date.
"""


import os
import socket
import configparser
import base64
import datetime

from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_der_public_key,
    load_der_private_key
)
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes
)
from cryptography.exceptions import (
    InvalidTag,
    UnsupportedAlgorithm,
    InvalidSignature
)


def read_config(config_file):
    """Reads the user configuration from a config file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        configparser.SectionProxy: The 'user' section of the configuration.
    """

    config = configparser.ConfigParser()
    config.read(config_file)

    return config['user']


def generate_keypair_ECDH():
    """Generates an Elliptic-Curve Diffie-Hellman (ECDH) key pair.

    Returns:
        tuple: A tuple containing the private and public keys.
    """

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def generate_keypair_Ed25519():
    """Generates an Ed25519 key pair for digital signatures.

    Returns:
        tuple: A tuple containing the private and public keys.
    """

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def public_key_to_der(public_key):
    """Converts a public key to DER format.

    Args:
        public_key (bytes): The public key to be converted.

    Returns:
        bytes: The public key in DER format.
    """

    public_key_der = public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_der


def der_to_public_key(public_key_der):
    """Loads a public key from its DER format.

    Args:
        public_key_der (bytes): The public key in DER format.

    Returns:
        bytes: The loaded public key.
    """

    public_key = load_der_public_key(public_key_der)

    return public_key


def private_key_to_der(private_key):
    """Converts a private key to DER format.

    Args:
        private_key (bytes): The private key to be converted.

    Returns:
        bytes: The private key in DER format.
    """

    private_key_der = private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    return private_key_der


def der_to_private_key(private_key_der):
    """Loads a private key from its DER format.

    Args:
        private_key_der (bytes): The private key in DER format.

    Returns:
        bytes: The loaded private key.
    """

    private_key = load_der_private_key(private_key_der, password=None)

    return private_key


def perform_x25519_ecdh(own_private_key, partner_public_key):
    """Performs the X25519 Elliptic-Curve Diffie-Hellman (ECDH) key exchange by computing the shared secret.

    Args:
        own_private_key (bytes): The user's private key.
        partner_public_key (bytes): The partner's public key.

    Returns:
        bytes: The shared secret derived from the ECDH exchange.
    """

    shared_secret = own_private_key.exchange(partner_public_key)

    return shared_secret


def derive_shared_AES_key(shared_secret_ECDH):
    """Derives a shared AES key using HKDF based on the ECDH shared secret.

    Args:
        shared_secret_ECDH (bytes): The shared secret from the ECDH exchange.

    Returns:
        bytes: The derived AES key.
    """

    hkdf = HKDF(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = None,
        info = b'DTNChatApplication|AESkey',
    )

    key_AES = hkdf.derive(shared_secret_ECDH)

    return key_AES


def encrypt_message(key_AES, plaintext):
    """Encrypts a plaintext message using AES-GCM.

    Args:
        key_AES (bytes): The AES key used for encryption.
        plaintext (str): The message to be encrypted.

    Returns:
        str: The encrypted message, base64-encoded.
    """

    nonce = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key_AES),
        modes.GCM(nonce),
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

    return base64.b64encode(encryptor.tag + nonce + ciphertext).decode('utf-8')


def decrypt_message(key_AES, received_concatenation):
    """Decrypts a message encrypted with AES-GCM.

    Args:
        key_AES (bytes): The AES key used for decryption.
        received_concatenation (str): The base64-encoded concatenated tag, nonce, and ciphertext.

    Returns:
        str: The decrypted plaintext message.

    Raises:
        InvalidTag: If the decryption fails due to an invalid tag.
    """

    received_message = base64.b64decode(received_concatenation.encode('utf-8'))
    tag = received_message[:16] # tag is 16 bytes long
    nonce = received_message[16:28] # nonce is 12 bytes long
    ciphertext = received_message[28:] # length of ciphertext unknown

    decryptor = Cipher(
        algorithms.AES(key_AES),
        modes.GCM(nonce, tag),
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode('utf-8')


def sign_with_Ed25519(data, private_key):
    """Signs data using the Ed25519 private key.

    Args:
        data (bytes): The data to be signed.
        private_key (bytes): The Ed25519 private key used for signing.

    Returns:
        bytes: The generated signature.
    """

    signature = private_key.sign(data)

    return signature


def verify_Ed25519_signature(signature, data, public_key):
    """Verifies a signature using the Ed25519 public key.

    Args:
        signature (bytes): The signature to be verified.
        data (bytes): The original data that was signed.
        public_key (bytes): The Ed25519 public key used for verification.

    Raises:
        InvalidSignature: If the signature verification fails.
    """

    public_key.verify(signature, data)


def compute_sha256_hash(data):
    """Computes the SHA-256 hash of the given data.

    Args:
        data (bytes): The data to be hashed.

    Returns:
        bytes: The computed SHA-256 hash.
    """

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()

    return hash_value


def compute_hash_chain(seed, length, enable_print=True):
    """Computes a chain of SHA-256 hashes from a seed value.

    Args:
        seed (bytes): The initial seed value.
        length (int): The number of hashes in the chain.
        enable_print (bool, optional): Flag to enable printing the chain length.

    Returns:
        bytes: The final hash value in the chain.
    """

    if enable_print:
        print(f"\nCOMPUTING HASH CHAIN OF LENGTH {length}\n")
    hash_value = seed
    for i in range(length):
        hash_value = compute_sha256_hash(hash_value)

    return hash_value


def get_current_date():
    """Returns the current system date and time.

    Returns:
        datetime.datetime: The current date and time.
    """

    return datetime.datetime.now()


def set_fake_date(fake_date):
    """Overrides the current date and time with a fake date for testing purposes.

    Args:
        fake_date (datetime.datetime): The fake date to be used.

    Returns:
        unittest.mock._patch: The patcher object for managing the fake date.
    """

    class PatchedDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return fake_date

    patcher = patch('datetime.datetime', PatchedDateTime)
    patcher.start()

    return patcher


def reset_date(patcher):
    """Resets the date and time to the actual system date.

    Args:
        patcher (unittest.mock._patch): The patcher object to be stopped.

    Returns:
        None
    """

    if patcher:
        patcher.stop()
