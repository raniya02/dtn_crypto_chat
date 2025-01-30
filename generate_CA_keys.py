# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0

"""
Certificate Authority Key Generator

This script generates a pair of Ed25519 keys (private and public) for use as the
Certificate Authority (CA) keys. The keys are output in DER format and printed
as hexadecimal strings. This script is typically used as part of the setup process
in "test_setup.py".

The script imports the following utility functions:
    * generate_keypair_Ed25519 - generates an Ed25519 key pair (private and public).
    * public_key_to_der - converts a public key to DER format.
    * private_key_to_der - converts a private key to DER format.

When run directly, this script will generate a new CA key pair and output the keys in DER
format as hexadecimal strings to the console.

"""

from utils import (
    generate_keypair_Ed25519,
    public_key_to_der,
    private_key_to_der
)


if __name__ == "__main__":
    ca_private_key, ca_public_key = generate_keypair_Ed25519()
    ca_private_key_der = private_key_to_der(ca_private_key)
    ca_public_key_der = public_key_to_der(ca_public_key)

    print(f"{ca_private_key_der.hex()},{ca_public_key_der.hex()}")
