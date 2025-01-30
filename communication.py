# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0

"""Chat Communication Handler

This script handles chat conversations between two users, such as Alice and Bob.
Users can send and receive messages to and from each other, and the script also
manages the integration of revocation status updates. These updates are piped
into the script to ensure that the latest revocation status is always sent along
with each message.

"""

import sys
import json
import threading
import datetime
import os

from utils import (
    encrypt_message,
    decrypt_message
)

import logging
import cbor2

from abc import ABC, abstractmethod

from ud3tn_utils.aap2 import (
    AAP2TCPClient,
    AAP2UnixClient,
    AuthType,
    BundleADU,
    BundleADUFlags,
    ResponseStatus,
)
from pyd3tn.bundle7 import (
    BibeProtocolDataUnit,
    Bundle,
    PayloadBlock,
    PrimaryBlock,
)
from ud3tn_utils.aap2.bin.helpers import initialize_logger

from utils import (
    compute_hash_chain,
    get_current_date,
    set_fake_date
)


logger = logging.getLogger(__name__)

newest_revocation_status = None


# SENDING MESSAGES: -----------------------------------------------------------


def send_message(
        payload, dest_eid, agentid, socket,
        secret,
        tcp=None,
        verbosity=0,
        bdm_auth=False,
):
    """Sends a message via the µd3TN AAP2 protocol.

    Args:
        payload (str): The message payload to be sent.
        dest_eid (str): The destination endpoint identifier (EID).
        agentid (str): The agent ID of the sending node.
        socket (str): The socket address used for communication.
        secret (str): The secret for authentication of the sending node.
        tcp (str, optional): The TCP address if using TCP instead of Unix sockets.
        verbosity (int, optional): The verbosity level for logging.
        bdm_auth (bool, optional): Flag to enable Bundle Dispatch Authentication.

    Raises:
        ValueError: If the payload is not provided.

    Returns:
        None
    """

    global logger
    logger = initialize_logger(verbosity)

    if payload is not None:
        payload = payload.encode("utf-8")
    else:
        raise ValueError("Payload must be provided!")

    if tcp:
        aap2_client = AAP2TCPClient(address=tcp)
    else:
        aap2_client = AAP2UnixClient(address=socket)
    with aap2_client:
        secret_value = aap2_client.configure(
            agentid,
            subscribe=False,
            secret=secret,
            auth_type=(
                AuthType.AUTH_TYPE_DEFAULT if not bdm_auth
                else AuthType.AUTH_TYPE_BUNDLE_DISPATCH
            ),
        )
        logger.info("Assigned agent secret: '%s'", secret_value)

        flags = [BundleADUFlags.BUNDLE_ADU_NORMAL]
        if bdm_auth:
            flags += [BundleADUFlags.BUNDLE_ADU_WITH_BDM_AUTH]
        aap2_client.send_adu(
            BundleADU(
                dst_eid=dest_eid,
                payload_length=len(payload),
                adu_flags=flags,
            ),
            payload,
        )
        assert (
                aap2_client.receive_response().response_status ==
                ResponseStatus.RESPONSE_STATUS_SUCCESS
        )


def send(user_name, user_socket, secret, destination_name, key):
    """Handles sending messages from the user to the destination within the DTN chat application.

    Args:
        user_name (str): The name of the user sending the message.
        user_socket (str): The socket address for communication.
        secret (str): The secret for authentication of the sending user.
        destination_name (str): The name of the destination user.
        key (bytes): The encryption key used for encrypting the message with AES-GCM.

    Returns:
        None
    """

    global newest_revocation_status

    destination_eid = f"dtn://{destination_name.replace(' ', '-').lower()}.dtn/"
    destination_agentid = f"{destination_name.replace(' ', '').lower()}{user_name.replace(' ', '').lower()}"

    while True:
        message = input(f"{user_name}: ")
        message_enc = encrypt_message(key, message)

        payload = {
            "message": message_enc,
            "status": newest_revocation_status
        }
        payload_str = json.dumps(payload)

        send_message(
            payload=payload_str,
            dest_eid=destination_eid + destination_agentid,
            agentid=f"{user_name.replace(' ', '').lower()}{destination_name.replace(' ', '').lower()}",
            socket=user_socket,
            secret=secret
        )


# RECEIVING MESSAGES: -----------------------------------------------------------


def run_aap_recv(aap2_client, max_count, output, verify_pl, newline, user_name, destination_name, key, destination_cert_issuance_date, destination_validity_hash):
    """Receives messages using the AAP2 client and processes them.

    Args:
        aap2_client (AAP2TCPClient or AAP2UnixClient): The AAP2 client for communication.
        max_count (int): The maximum number of messages to receive before terminating.
        output (IO): The output stream where received messages are written.
        verify_pl (str, optional): Expected payload for verification.
        newline (bool): Whether to add a newline after each received message.
        user_name (str): The name of the sending user.
        destination_name (str): The name of the receiving user.
        key (bytes): The encryption key used for decrypting the message.
        destination_cert_issuance_date (str): The certificate issuance date of the destination user.
        destination_validity_hash (str): The validity hash of the destination user's certificate.

    Returns:
        None
    """

    logging.basicConfig(level=logging.DEBUG)
    logger.info("Waiting for bundles...")
    counter = 0

    while True:
        msg = aap2_client.receive_msg()
        if not msg:
            logger.debug("No message received. Exiting receive loop.")
            return
        msg_type = msg.WhichOneof("msg")

        if msg_type == "keepalive":
            logger.debug("Received keepalive message, acknowledging.")
            aap2_client.send_response_status(
                ResponseStatus.RESPONSE_STATUS_ACK
            )
            continue

        elif msg_type != "adu":
            logger.info("Received message with field '%s' set, discarding.", msg_type)
            continue

        adu_msg, bundle_data = aap2_client.receive_adu(msg.adu)
        aap2_client.send_response_status(
            ResponseStatus.RESPONSE_STATUS_SUCCESS
        )

        enc = False
        err = False

        if BundleADUFlags.BUNDLE_ADU_BPDU in adu_msg.adu_flags:
            payload = cbor2.loads(bundle_data)
            bundle = Bundle.parse(payload[2])
            payload = bundle.payload_block.data
            enc = True
        else:
            payload = bundle_data

        if not err:
            enc = " encapsulated" if enc else ""
            logger.info(
                "Received%s bundle from '%s', payload len = %d",
                enc,
                msg.adu.src_eid,
                len(payload),
            )

            if verify_pl is not None and verify_pl.encode("utf-8") != payload:
                logger.fatal("Unexpected payload != '%s'", verify_pl)
                sys.exit(1)

            try:
                message = json.loads(payload)
                logger.info("Received message: %s", message)

                days_passed = (get_current_date().date() - datetime.datetime.fromisoformat(destination_cert_issuance_date).date()).days

                try:
                    assert bytes.fromhex(destination_validity_hash) == compute_hash_chain(bytes.fromhex(message.get("status")), days_passed) or bytes.fromhex(destination_validity_hash) == compute_hash_chain(bytes.fromhex(message.get("status")), days_passed + 1) or bytes.fromhex(destination_validity_hash) == compute_hash_chain(bytes.fromhex(message.get("status")), days_passed - 1)
                    # +1 if the revocation for tommorrow has already arrived and self.revocation_status has already been updated accordingly
                    # -1 if the revocation status for today has not arrived yet (grace_period = 1)
                except AssertionError:
                    print("ERROR: Invalid hash value - must have been modified!")
                    raise

                output.write(b"\r")
                line_to_write = f"{destination_name}: {decrypt_message(key, message.get('message'))}"
                if len(line_to_write) < len(user_name) + 2:
                    line_to_write += " " * (len(user_name) + 2 - len(line_to_write))
                output.write(line_to_write.encode("utf-8"))

                if newline:
                    output.write(b"\n")
                    output.write(f"{user_name}: ".encode("utf-8"))

                output.flush()

            except json.JSONDecodeError as e:
                logger.error("Failed to decode message payload: %s", e)

        else:
            logger.warning(
                "Received administrative record of unknown type from '%s'!",
                msg.adu.src_eid
            )

        counter += 1
        if max_count and counter >= max_count:
            logger.info("Expected amount of bundles received, terminating.")

            return


def receive_message(
        agentid,
        user_name,
        user_socket,
        secret,
        destination_name,
        key,
        destination_cert_issuance_date,
        destination_validity_hash,
        tcp=None,
        verbosity=0,
        count=None,
        output=sys.stdout.buffer,
        verify_pl=None,
        newline=True,
        keepalive_seconds=None
):
    """Configures the AAP2 client to receive and process incoming messages.

    Args:
        agentid (str): The agent ID of the receiving node.
        user_name (str): The name of the user receiving the message.
        user_socket (str): The socket address for communication.
        secret (str): The secret for authentication of the receiving node.
        destination_name (str): The name of the destination user.
        key (bytes): The encryption key used for decrypting the message.
        destination_cert_issuance_date (str): The certificate issuance date of the destination user.
        destination_validity_hash (str): The validity hash of the destination user's certificate.
        tcp (str, optional): The TCP address if using TCP instead of Unix sockets.
        verbosity (int, optional): The verbosity level for logging.
        count (int, optional): The maximum number of messages to receive.
        output (IO, optional): The output stream where received messages are written.
        verify_pl (str, optional): Expected payload for verification.
        newline (bool, optional): Whether to add a newline after each received message.
        keepalive_seconds (int, optional): The interval in seconds for sending keepalive messages.

    Returns:
        None
    """

    global logger
    logger = initialize_logger(verbosity)

    try:
        if tcp:
            aap2_client = AAP2TCPClient(address=tcp)
        else:
            aap2_client = AAP2UnixClient(address=user_socket)

        with aap2_client:
            secret_value = aap2_client.configure(
                agentid,
                subscribe=True,
                secret=secret,
                keepalive_seconds=keepalive_seconds,
            )
            logger.info("Assigned agent secret: '%s'", secret_value)
            run_aap_recv(
                aap2_client,
                count,
                output,
                verify_pl,
                newline,
                user_name,
                destination_name,
                key,
                destination_cert_issuance_date,
                destination_validity_hash
            )
    finally:
        if output != sys.stdout.buffer:
            print("Closing output stream")
            output.close()


def listen_for_updates(pipe_name):
    """Listens for updates on a named pipe for revocation status changes.

    Args:
        pipe_name (str): The name of the pipe to listen on.

    Returns:
        None
    """

    global newest_revocation_status

    with open(pipe_name, 'r') as pipe:
        while True:
            data = pipe.read()
            if data:
                components = data.split('|', 1)
                mocked_date_str = components[0]
                newest_revocation_status = components[1] if len(components) > 1 else None
                print(f"INFO: Received new revocation status!")
                if mocked_date_str:
                    mocked_date = datetime.datetime.fromisoformat(mocked_date_str)
                    set_fake_date(mocked_date)
                    print("INFO: The current date is: ", get_current_date().date())


if __name__ == "__main__":
    """Main execution block for the communication script.

    This block initializes the communication environment, including setting
    up threads for sending and receiving messages and listening for revocation
    status updates.
    """

    user_name = sys.argv[1]
    user_socket = sys.argv[2]
    newest_revocation_status = sys.argv[3] # in hex() format
    secret = sys.argv[4]
    destination_name = sys.argv[5]
    key = bytes.fromhex(sys.argv[6])
    destination_cert_issuance_date = sys.argv[7] # in date().isoformat()
    destination_validity_hash = sys.argv[8] # in hex() format
    manipulated_date_str = sys.argv[9]
    pipe_name = sys.argv[10]

    if manipulated_date_str:
        manipulated_date = datetime.datetime.fromisoformat(manipulated_date_str)
        set_fake_date(manipulated_date)
    print("The current date is: ", get_current_date().date())

    print(f"TERMINAL OF {user_name.upper()}")
    print(f"Welcome to the conversation with {destination_name}!")

    agentid = f"{user_name.replace(' ', '').lower()}{destination_name.replace(' ', '').lower()}"

    update_thread = threading.Thread(target=listen_for_updates, args=(pipe_name,))
    update_thread.daemon = True
    update_thread.start()

    receive_thread = threading.Thread(target=receive_message, args=(agentid, user_name, user_socket, secret, destination_name, key, destination_cert_issuance_date, destination_validity_hash,))
    send_thread = threading.Thread(target=send, args=(user_name, user_socket, secret, destination_name, key,))

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()
