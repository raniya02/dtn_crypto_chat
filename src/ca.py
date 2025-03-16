# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0

import os
import sys
import time
import json
import datetime
import subprocess
import signal
import argparse
import psutil
import pickle

from base64 import b64encode
from unittest.mock import patch

from node import Node
from utils import (
    sign_with_Ed25519,
    der_to_public_key,
    der_to_private_key,
    public_key_to_der,
    compute_sha256_hash,
    compute_hash_chain,
    get_current_date,
    set_fake_date,
    reset_date
)

from ud3tn_utils.aap2.aap2_client import AAP2CommunicationError


def signal_handler(sig, frame):
    """Handles termination signals (SIGTERM, SIGINT) and exits the program gracefully.

    Args:
        sig (int): The signal number received.
        frame (FrameType): The current stack frame.
    """

    print("Signal received, exiting...")
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler) # Handle termination signal from the operating system.
signal.signal(signal.SIGINT, signal_handler) # Handle interrupt signal (e.g., Ctrl+C) from the user.


class CA(Node):
    """A class used to represent a Certificate Authority (CA) node in a secure communication system.

    The CA class extends the Node class and manages certificate issuance, revocation, and
    revocation status distribution to users.

    Attributes:
        eid (str): The endpoint identifier of the CA, inherited from Node.
        agentid (str): The agent ID of the CA, inherited from Node.
        socket (str): The socket for communication, inherited from Node.
        secret (str): The secret of the CA, used to prevent strangers from gaining access to messages by using the same agent ID as the CA, inherited from Node.
        __private_key (bytes): The private key of the CA used for signing certificates.
        public_key (bytes): The public key of the CA used by others to verify the CA's signatures.
        __revocation_database (dict): A database of the users' certificates and their revocation statuses.
        generated_certificates_counter (int): Counter to keep track of the number of issued certificates, used as certificate serial numbers.
        revocation_entries_to_be_deleted (list): List of revocation database entries pending deletion.
        eval_mode_scalability_reqcert (bool): Flag for evaluating scalability during certificate requests.
        eval_mode_scalability_revstatus (bool): Flag for evaluating scalability during revocation status updates.
        eval_mode_scalability_ecdh (bool): Flag for evaluating scalability during ECDH key exchanges.
    """


    def __init__(self, eid, agentid, socket, secret, private_key_der, public_key_der, eval_mode_scalability_reqcert, eval_mode_scalability_revstatus, eval_revocation_database, eval_mode_scalability_ecdh):
        """Initializes a CA object.

        Args:
            eid (str): The endpoint identifier for the CA.
            agentid (str): The agent ID for the CA.
            socket (str): The socket path for communication.
            secret (str): The secret key for the CA.
            private_key_der (str): The private key of the CA in DER format (hex string).
            public_key_der (str): The public key of the CA in DER format (hex string).
            eval_mode_scalability_reqcert (bool): Flag to enable scalability evaluation during certificate requests.
            eval_mode_scalability_revstatus (bool): Flag to enable scalability evaluation during revocation status updates.
            eval_revocation_database (dict): The revocation database used during scalability evaluation of revocation status updates.
            eval_mode_scalability_ecdh (bool): Flag to enable scalability evaluation during ECDH key exchanges.
        """

        super().__init__(eid, agentid, socket, secret)
        self.__private_key = der_to_private_key(bytes.fromhex(private_key_der))
        self.public_key = der_to_public_key(bytes.fromhex(public_key_der))
        self.__revocation_database = {} # {"user_name": [status, date_of_iss, date_of_exp, [X0, Y0, ...]]}
        self.generated_certificates_counter = 0
        self.revocation_entries_to_be_deleted = []
        self.eval_mode_scalability_reqcert = eval_mode_scalability_reqcert
        self.eval_mode_scalability_revstatus = eval_mode_scalability_revstatus
        self.eval_mode_scalability_ecdh = eval_mode_scalability_ecdh

        if self.eval_mode_scalability_revstatus:
            self.__revocation_database = eval_revocation_database
            self.send_revocation_status()


    def log_request_reception(self, user_name):
        """Logs the reception of a request from a user (used for evaluation purposes).

        Args:
            user_name (str): The name of the user who sent the request.
        """

        log_file = 'request_reception.log'
        with open(log_file, 'a') as f:
            f.write(f"{user_name}: Received request from this user\n")


    def handle_incoming_messages(self, message):
        """Handles incoming messages based on their type and processes them accordingly.

        Args:
            message (dict): The incoming message to be processed.
        """

        if message.get("type") == "REQ_CERT":
            node_name = message.get("name")
            print(f"INFO: Issuing a certificate for {node_name} ..")

            if self.eval_mode_scalability_reqcert:
                self.log_request_reception(node_name)

            node_public_key_bytes = bytes.fromhex(message.get("public_key"))
            node_public_key = der_to_public_key(node_public_key_bytes)
            self.generate_certificate(node_name, node_public_key)

        elif message.get("type") == "SEND_STATUS":
            print("INFO: Beginning revocation status sending procedure ...")

            if self.manipulated_date is not None:
                self.mock_date_is_triggered = True
                set_fake_date(self.manipulated_date)
                print("The current date is: ", get_current_date().date())

            self.send_revocation_status()

        elif message.get("type") == "REQ_CERT_REVOC":
            node_name = message.get("certificate")["ID"]
            print(f"INFO: Received request for certificate revocation from {node_name} ...")

            del self.__revocation_database[node_name]
            print("INFO: Certificate has been revoked. Entry deleted.")

        elif message.get("type") == "REVOKE_CERT":
            node_name = message.get("ID")
            print(f"INFO: Revoking certificate of {node_name} ...")
            self.revoke_certificate(node_name)

        elif message.get("type") == "REQ_TEST":
            node_name = message.get("name")
            print(f"INFO: Received test message from {node_name} ...")
            self.log_request_reception(node_name)

            message = {"type": "ACK_TEST"}
            super().send_message(
                payload=json.dumps(message),
                dest_eid=f"dtn://user.dtn/{node_name.lower()}",
                aap2_client=self.aap2_sender_client
            )
            print(f"INFO: Sending test message back to {node_name} ...")


    def generate_certificate(self, node_user_name, node_public_key):
        """Generates a certificate and related information for a user and sends it to them.

        A signature for the certificate is created and sent along with the certificate to the respective user.
        Relevant certificate information of the user is stored in the CA's revocation database.

        The revocation status upon certificate issuance is set to "0" (= valid) per default.

        Args:
            node_user_name (str): The name of the user for whom the certificate is generated.
            node_public_key (bytes): The public key of the user.
        """

        self.generated_certificates_counter += 1

        date_of_certificate_issuance = datetime.datetime.now().date()
        date_of_certificate_expiration = date_of_certificate_issuance + datetime.timedelta(days=self.certificate_validity_period)

        validity_target = os.urandom(20) # X0
        revocation_target = os.urandom(20) # Y0
        validity_hash = compute_hash_chain(validity_target, self.certificate_validity_period)
        revocation_hash = compute_sha256_hash(revocation_target)
        node_public_key_bytes = public_key_to_der(node_public_key)

        certificate = {
            "SN": self.generated_certificates_counter,
            "ID": node_user_name,
            "PK": node_public_key_bytes.hex(),
            "D1": date_of_certificate_issuance.isoformat(),
            "D2": date_of_certificate_expiration.isoformat(),
            f"X{self.certificate_validity_period}": validity_hash.hex(),
            "Y1": revocation_hash.hex()
        }

        self.__revocation_database[node_user_name] = [0, date_of_certificate_issuance, date_of_certificate_expiration, [validity_target, revocation_target]]

        certificate_signature = sign_with_Ed25519(json.dumps(certificate).encode('utf-8'), self.__private_key)
        print(f"INFO: Sending generated certificate to {node_user_name} ...")

        destination_eid = f"dtn://{''.join([i for i in node_user_name.replace(' ', '-').lower() if not i.isdigit()])}.dtn/{node_user_name.replace(' ', '').lower()}"
        # structure is designed such, in order to also accomodate users of the form user1, user2, ..., with hardcoded node ID "dtn://user.dtn/" (used for the evaluation)

        message = {
            "type": "ACK_CERT",
            "certificate": certificate,
            "certificate_signature": certificate_signature.hex()
        }
        super().send_message(
            payload=json.dumps(message),
            dest_eid=destination_eid,
            aap2_client=self.aap2_sender_client
        )


    def check_if_revoked(self, user_name, date_tomorrow):
        """Checks if a user's certificate is revoked and sends the appropriate revocation status.

        In either case (status is valid or revoked), the status is sent to the respective user.
        However, if the status is revoked, the entry is deleted from the revocation database after sending the status.

        Args:
            user_name (str): The name of the user whose certificate status is being checked.
            date_tomorrow (datetime.date): The date of the day after the current day.
        """

        if self.__revocation_database[user_name][0] == 0: # is still valid
            days_passed = (date_tomorrow - self.__revocation_database[user_name][1]).days
            hash_number = self.certificate_validity_period - days_passed
            validity_hash = compute_hash_chain(self.__revocation_database[user_name][3][0], hash_number)

            message = {
                "type": "REV_STATUS",
                "hash": validity_hash.hex()
            }

        else: # is revoked
            revocation_hash = self.__revocation_database[user_name][3][1]

            message = {
                "type": "REV_STATUS",
                "hash": revocation_hash.hex()
            }
            self.revocation_entries_to_be_deleted.append(user_name)

        print(f"INFO: Sending revocation status to {user_name} ...")

        destination_eid = f"dtn://{''.join([i for i in user_name.replace(' ', '-').lower() if not i.isdigit()])}.dtn/{user_name.replace(' ', '').lower()}"
        # structure is designed such, in order to also accomodate users of the form user1, user2, ..., with hardcoded node ID "dtn://user.dtn/" (used for the evaluation)

        super().send_message(
            payload=json.dumps(message),
            dest_eid=destination_eid,
            aap2_client=self.aap2_sender_client
        )


    def send_revocation_status(self):
        """Sends the revocation status for all users in the revocation database.

        If the date of certificate expiration is tommorrow (or today, or has already passed => these cases are only of relevance if the service somehow failed to perform on any date, since this is normally a daily procedure), the entry is deleted from the revocation database.
        """

        if self.eval_mode_scalability_revstatus:
            time.sleep(3)

        current_date = get_current_date().date()
        tomorrow = (get_current_date() + datetime.timedelta(days=1)).date()

        for key in self.__revocation_database:
            if (self.__revocation_database[key][2] - current_date).days <= 1:
                self.revocation_entries_to_be_deleted.append(key)
                return
            else:
                self.check_if_revoked(key, tomorrow)

        while self.revocation_entries_to_be_deleted:
            entry = self.revocation_entries_to_be_deleted.pop(0)
            del self.__revocation_database[entry]


    def revoke_certificate(self, node_user_name):
        """Revokes a user's certificate.

        Args:
            node_user_name (str): The name of the user whose certificate is being revoked.
        """

        self.__revocation_database[node_user_name][0] = 1


    def save_revocation_database(self, file_path):
        """Saves the revocation database to a file. Used for evaluation purposes.

        Args:
            file_path (str): The path to the file where the revocation database will be saved.
        """

        with open(file_path, 'wb') as pickle_file:
            pickle.dump(self.__revocation_database, pickle_file)


def main():
    """The main function to set up and run the Certificate Authority (CA) node."""

    def pickle_file(value):
        """Helper function to load a pickle file.

        Args:
            value (str): The file path to the pickle file.

        Returns:
            object: The object loaded from the pickle file.
        """
        with open(value, 'rb') as pickle_file:
            return pickle.load(pickle_file)


    parser = argparse.ArgumentParser(description='Register the CA to start the chat application.')

    # Positional arguments:
    parser.add_argument(
        'ca_eid',
        type=str,
        help='The EID of the CA to receive messages'
    )
    parser.add_argument(
        'ca_agentid',
        type=str,
        help='The agentid of the CA to receive messages'
    )
    parser.add_argument(
        'ca_socket',
        type=str,
        help='The socket path of the CA to send messages'
    )
    parser.add_argument(
        'ca_private_key',
        type=str,
        help='The private key of the CA'
    )
    parser.add_argument(
        'ca_public_key',
        type=str,
        help='The public key of the CA'
    )

    # Optional arguments:
    parser.add_argument(
        '--eval-scalability-reqcert',
        action='store_true',
        help='Enable evaluation mode: scalability, requesting certificates from the CA',
    )
    parser.add_argument(
        '--eval-scalability-revstatus',
        action='store_true',
        help='Enable evaluation mode: scalability, sending revocation status to users',
    )
    parser.add_argument(
        '-rb', '--revocation-database',
        type=pickle_file,
        help='Path to the pickle file containing the revocation database',
    )
    parser.add_argument(
        '--eval-scalability-ecdh',
        action='store_true',
        help='Enable evaluation mode: scalability, sending ECDH requests to users',
        # only used to assist another evaluation test
    )

    args = parser.parse_args()

    arg_eid = sys.argv[1]
    arg_agentid = sys.argv[2]
    arg_socket = sys.argv[3]
    arg_private_key_der = sys.argv[4]
    arg_public_key_der = sys.argv[5]

    arg_secret = b64encode(os.urandom(5)).decode('utf-8')

    ca = CA(args.ca_eid, args.ca_agentid, args.ca_socket, arg_secret, args.ca_private_key, args.ca_public_key, args.eval_scalability_reqcert, args.eval_scalability_revstatus, args.revocation_database, args.eval_scalability_ecdh)

    try:
        ca.receive_message(ca.aap2_receiver_client)

    except KeyboardInterrupt:
        print("Exiting...")

    finally:

        if ca.eval_mode_scalability_reqcert:
            pickle_file_path = 'revocation_database.pkl'
            ca.save_revocation_database(pickle_file_path)

        ca.disconnect()

if __name__ == "__main__":
    main()
