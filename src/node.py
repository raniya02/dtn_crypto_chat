# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0

import logging
import cbor2
import json
import sys
import datetime

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

logger = logging.getLogger(__name__)


class Node:
    """Abstract base class for a communication node using the AAP2 protocol.

    This class provides the foundational functionality for nodes that need to send and
    receive messages over a network using the AAP2 protocol. It includes methods for
    configuring sender and receiver clients, sending messages, and processing received messages.

    Attributes:
        eid (str): The endpoint identifier for the node.
        agentid (str): The agent ID associated with the node.
        socket (str): The socket path for communication.
        secret (str): The secret used for authentication.
        aap2_sender_client (AAP2UnixClient): The AAP2 client for sending messages.
        aap2_receiver_client (AAP2UnixClient): The AAP2 client for receiving messages.
        certificate_validity_period (int): The validity period for certificates (in days).
        certificate_time_granularity (int): The granularity for certificate status checks (in days).
        manipulated_date (datetime.datetime): A date used for mocking different dates in testing.
        mock_date_is_triggered (bool): Flag indicating whether the date manipulation is active.
    """

    def __init__(self, eid, agentid, socket, secret):
        self.eid = eid
        self.agentid = agentid
        self.socket = socket
        self.secret = secret
        self.aap2_sender_client = self.configure_sender_client()
        self.aap2_receiver_client = self.configure_receiver_client()
        self.certificate_validity_period = 365 # valid for 1 year
        self.certificate_time_granularity = 1 # status is checked every day
        self.manipulated_date = datetime.datetime(2025, 8, 9) # used for mocking different date
        #self.manipulated_date = None
        self.mock_date_is_triggered = False


    def configure_sender_client(self, bdm_auth=False):
        """Configures the AAP2 client for sending messages.

        Args:
            bdm_auth (bool, optional): Whether to use Bundle Dispatch Authentication. Defaults to False.

        Returns:
            AAP2UnixClient: The configured AAP2 client for sending messages.
        """

        aap2_client = AAP2UnixClient(address=self.socket)

        aap2_client.connect()

        secret_value = aap2_client.configure(
            self.agentid,
            subscribe=False,
            secret=self.secret,
            auth_type=(
                AuthType.AUTH_TYPE_DEFAULT if not bdm_auth
                else AuthType.AUTH_TYPE_BUNDLE_DISPATCH
            ),
        )
        logger.info("Assigned agent secret: '%s'", secret_value)

        return aap2_client


    def configure_receiver_client(self, keepalive_seconds=None):
        """Configures the AAP2 client for receiving messages.

        Args:
            keepalive_seconds (int, optional): Interval for sending keepalive messages in seconds. Defaults to None.

        Returns:
            AAP2UnixClient: The configured AAP2 client for receiving messages.
        """

        aap2_client = AAP2UnixClient(address=self.socket)

        aap2_client.connect()

        secret_value = aap2_client.configure(
            self.agentid,
            subscribe=True,
            secret=self.secret,
            keepalive_seconds=keepalive_seconds,
        )
        logger.info("Assigned agent secret: '%s'", secret_value)

        return aap2_client


    def disconnect(self):
        """Disconnects the AAP2 sender and receiver clients.

        This method is used to cleanly disconnect the sender and receiver clients when the node is done communicating.
        """

        self.aap2_sender_client.disconnect()
        self.aap2_receiver_client.disconnect()


    # SENDING MESSAGES: -------------------------------------------------------------


    def send_message(
        self,
        payload, dest_eid,
        aap2_client,
        verbosity=0,
        bdm_auth=False,
    ):
        """Sends a message to a specified destination using the AAP2 protocol.

        Args:
            payload (str): The message payload to be sent.
            dest_eid (str): The destination endpoint identifier (EID).
            aap2_client (AAP2UnixClient): The AAP2 client used for sending the message.
            verbosity (int, optional): The verbosity level for logging. Defaults to 0.
            bdm_auth (bool, optional): Whether to use Bundle Dispatch Authentication. Defaults to False.

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


    # RECEIVING MESSAGES: -----------------------------------------------------------


    def run_aap_recv(self, aap2_client, max_count, output, verify_pl, newline):
        """Receives and processes incoming messages using the AAP2 client.

        Args:
            aap2_client (AAP2UnixClient): The AAP2 client used for receiving messages.
            max_count (int): The maximum number of messages to receive before terminating.
            output (IO): The output stream where received messages are written.
            verify_pl (str, optional): Expected payload for verification.
            newline (bool): Whether to add a newline after each received message.

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

                    self.handle_incoming_messages(message)

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
        self,
        aap2_client,
        verbosity=0,
        count=None,
        output=sys.stdout.buffer,
        verify_pl=None,
        newline=True,
    ):
        """Configures and starts the process for receiving messages.

        Args:
            aap2_client (AAP2UnixClient): The AAP2 client used for receiving messages.
            verbosity (int, optional): The verbosity level for logging. Defaults to 0.
            count (int, optional): The maximum number of messages to receive before terminating. Defaults to None.
            output (IO, optional): The output stream where received messages are written. Defaults to sys.stdout.buffer.
            verify_pl (str, optional): Expected payload for verification. Defaults to None.
            newline (bool, optional): Whether to add a newline after each received message. Defaults to True.

        Returns:
            None
        """

        global logger
        logger = initialize_logger(verbosity)

        self.run_aap_recv(
            aap2_client,
            count,
            output,
            verify_pl,
            newline,
        )


    @abstractmethod
    def handle_incoming_messages(self, message):
        """Abstract method to handle incoming messages.

        This method must be implemented by subclasses to define specific behavior
        upon receiving messages.

        Args:
            message (dict): The message received by the node.

        Returns:
            None
        """

        pass
