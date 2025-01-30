# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0

import json
import sys
import time
import subprocess
import os
import threading
import shlex
import argparse
import datetime

from base64 import b64encode

from node import Node
from utils import (
    read_config,
    generate_keypair_ECDH,
    public_key_to_der,
    der_to_public_key,
    verify_Ed25519_signature,
    compute_sha256_hash,
    compute_hash_chain,
    perform_x25519_ecdh,
    derive_shared_AES_key,
    get_current_date,
    set_fake_date,
    reset_date,
    encrypt_message,
    decrypt_message
)

from ud3tn_utils.aap2.aap2_client import AAP2CommunicationError

# Used for evaluating temporal overhead
start_req_cert_timer = None
start_req_ecdh_timer = None
start_communication_timer = None

end_req_cert_timer = None
end_req_ecdh_timer = None
end_communication_timer = None


class User(Node):
    """A class used to represent an user in a secure communication system.

    The User class extends the Node class and manages secure communication through certificate requests and ECDH key exchanges.

    Attributes:
        eid (str): The endpoint identifier for the user, inherited from Node.
        agentid (str): The agent ID for the user, inherited from Node.
        socket (str): The socket for communication, inherited from Node.
        secret (str): The secret of the user, used to prevent strangers from gaining access to messages by using the agent ID from another user, inherited from Node.
        user_name (str): The name of the user.
        ca_eid (str): The endpoint identifier of the certificate authority (CA).
        ca_agentid (str): The agent ID of the CA.
        ca_public_key (bytes): The public key of the CA in bytes.
        __private_key (bytes): The user's private key, used for ECDH.
        public_key (bytes): The user's public key, used for ECDH.
        __user_database (dict): A database containing relevant information from communication partners.
        certificate (dict): The user's certificate.
        certificate_signature (str): The signature of the certificate, issued by the CA.
        revocation_status (str): The revocation status of the certificate.
        grace_period (int): The grace period for revocation status validity.
        pipe_name (str): The name of the pipe for inter-process communication.
        print_mode (bool): Flag to enable print mode.
        eval_mode_scalability_reqcert (bool): Flag for evaluating scalability during certificate requests.
        eval_mode_scalability_revstatus (bool): Flag for evaluating scalability during revocation status updates.
        eval_mode_scalability_ecdh (bool): Flag for evaluating scalability during ECDH key exchanges.
        eval_mode_time (bool): Flag for evaluating temporal overhead, in comparison to sending messages without any key management.
        evaluation_time_mode (int): Indicator for which kind of scenario (worst-case, medium, best-case) shall be simulated during temporal overhead evalation.
    """

    def __init__(self, eid, agentid, socket, secret, user_name, ca_eid, ca_agentid, ca_public_key_der, print_mode, eval_mode_scalability_reqcert, eval_mode_scalability_revstatus, eval_mode_scalability_ecdh, eval_mode_time, evaluation_time_mode):
        """Initializes a User object.

        Args:
            eid (str): The endpoint identifier for the user.
            agentid (str): The agent ID for the user.
            socket (str): The socket for communication.
            secret (str): The secret of the user.
            user_name (str): The name of the user.
            ca_eid (str): The endpoint identifier of the CA.
            ca_agentid (str): The agent ID of the CA.
            ca_public_key_der (str): The CA's public key in bytes.
            print_mode (bool): Flag to enable print mode.
            eval_mode_scalability_reqcert (bool): Flag to enable scalability evaluation during certificate requests.
            eval_mode_scalability_revstatus (bool): Flag to enable scalability evaluation during revocation status updates.
            eval_mode_scalability_ecdh (bool): Flag to enable scalability evaluation during ECDH key exchanges.
            eval_mode_time (bool): Flag to enable temporal overhead evaluation.
            evaluation_time_mode (int): Indicator for which kind of scenario (worst-case, medium, best-case) shall be simulated during temporal overhead evalation.
        """


        super().__init__(eid, agentid, socket, secret)
        self.user_name = user_name
        self.ca_eid = ca_eid
        self.ca_agentid = ca_agentid
        self.ca_public_key = der_to_public_key(bytes.fromhex(ca_public_key_der))
        self.__private_key, self.public_key = generate_keypair_ECDH()
        self.__user_database = {} # {"user_name": [D1, D2, X365, Y1, k_AES]}; k_AES stored in hex() format
        self.certificate = {} # stored in hex() format
        self.certificate_signature = None
        self.revocation_status = None # stored in hex() format
        self.grace_period = 1 # status of yesterday is also OK
        self.pipe_name = f"/tmp/{user_name.replace(' ', '').lower()}_pipe"

        # Optional arguments:
        self.print_mode = print_mode
        self.eval_mode_scalability_reqcert = eval_mode_scalability_reqcert
        self.eval_mode_scalability_revstatus = eval_mode_scalability_revstatus
        self.eval_mode_scalability_ecdh = eval_mode_scalability_ecdh
        self.eval_mode_time = eval_mode_time
        self.evaluation_time_mode = evaluation_time_mode

        if not all([
            self.eval_mode_scalability_reqcert,
            self.eval_mode_scalability_revstatus,
            self.eval_mode_scalability_ecdh,
            self.eval_mode_time
        ]):
            if os.path.exists(self.pipe_name):
                os.remove(self.pipe_name)
            with open(self.pipe_name, 'w') as pipe:
                pass

        if not self.eval_mode_scalability_revstatus:
            self.request_certificate()


    def log_message_reception(self):
        """Logs the reception of a message depending on the evaluation mode."""

        if self.eval_mode_scalability_reqcert:
            log_file = 'certificate_reception.log'
            with open(log_file, 'a') as f:
                f.write(f"{self.user_name}: Received certificate\n")

        elif self.eval_mode_scalability_revstatus:
            log_file = 'status_reception.log'
            with open(log_file, 'a') as f:
                f.write(f"{self.user_name}: Received status\n")

        elif self.eval_mode_scalability_ecdh:
            log_file = 'ecdh_reception.log'
            with open(log_file, 'a') as f:
                f.write(f"{self.user_name}: Received ECDH response\n")


    def log_request_reception(self, user_name):
        """Logs the reception of an ECDH request from a user.

        Args:
            user_name (str): The name of the user sending the ECDH request.
        """

        log_file = 'ecdh_request_reception.log'
        with open(log_file, 'a') as f:
            f.write(f"{user_name}: Received ECDH request from this user\n")


    def handle_incoming_messages(self, message):
        """Handles incoming messages based on their message type.

        Args:
            message (dict): The incoming message to be processed.
        """

        if message.get("type") == "ACK_CERT":
            self.receive_certificate(message)

        elif message.get("type") == "REV_STATUS":
            self.receive_revocation_status(message)

        elif message.get("type") == "REQ_ECDH":
            self.receive_ecdh_request(message)

        elif message.get("type") == "ACK_ECDH":
            self.receive_ecdh_acknowledgement(message)

        elif message.get("type") == "RES_COMM":
            if self.print_mode:
                print(f"INFO: {message.get('name')} asked to resume communication with you.")
            self.start_conversation(message.get("name"))

        else:
            self.time_evaluation(message)


    # CERTIFICATE: -------------------------------------------------------------

    def request_certificate(self):
        """Requests a certificate from the CA."""

        if self.print_mode:
            print(f"INFO: Requesting a certificate from the CA for {self.user_name} ...")
        if self.eval_mode_time and self.user_name == "Alice Armstrong":
            global start_req_cert_timer
            start_req_cert_timer = time.time()

        message = {
            "type": "REQ_CERT",
            "name": self.user_name,
            "public_key": public_key_to_der(self.public_key).hex()
        }
        super().send_message(
            dest_eid=self.ca_eid + self.ca_agentid,
            payload=json.dumps(message),
            aap2_client=self.aap2_sender_client
        )


    def receive_certificate(self, message):
        """Processes the received certificate from the CA.

        Args:
            message (dict): The message containing the certificate information.
        """

        if self.print_mode:
            print(f"INFO: Received certificate for {self.user_name} ...")

        verify_Ed25519_signature(
            signature=bytes.fromhex(message.get("certificate_signature")),
            data=json.dumps(message.get("certificate")).encode('utf-8'),
            public_key=self.ca_public_key
        )

        if self.eval_mode_scalability_reqcert:
            self.log_message_reception()
            sys.exit(0)

        self.certificate = message.get("certificate")
        self.certificate_signature = message.get("certificate_signature")
        self.revocation_status = self.certificate[f"X{self.certificate_validity_period}"]

        if self.eval_mode_time and self.user_name == "Alice Armstrong":
            global end_req_cert_timer
            end_req_cert_timer = time.time()

            self.initiate_ecdh("dtn://bob-brown.dtn/bobbrown")


    # REVOCATION: ----------------------------------------------------------------

    def receive_revocation_status(self, message):
        """Processes the received revocation status update from the CA.

        In case the status is valid ("0"), this status is stored, and piped into the communication with other users (if there is one ongoing).

        In case the status is revoked ("1"), a new key pair is automatically generated, and a new certificate is requested from the CA.

        If self.manipulated_date and self.mock_date_is_triggered in class Node are set, this also sets the current date to another date, in order to test if sending revocation status updates works properly (i.e. if the correct number of hash calculation are made).

        Args:
            message (dict): The message containing the revocation status information.
        """

        if self.print_mode:
            print(f"INFO: Received revocation status for {self.user_name} ...")
            hash_print = True
        else:
            hash_print = False

        if self.eval_mode_scalability_revstatus:
            self.log_message_reception()
            sys.exit(0)

        if self.manipulated_date is not None:
            self.mock_date_is_triggered = True
            set_fake_date(self.manipulated_date)
            if self.print_mode:
                print("The current date is: ", get_current_date().date())

        days_passed = (get_current_date().date() - datetime.datetime.fromisoformat(self.certificate["D1"]).date()).days
        status_hash = bytes.fromhex(message.get("hash"))
        validity_hash = bytes.fromhex(self.certificate[f"X{self.certificate_validity_period}"])
        revocation_hash = bytes.fromhex(self.certificate["Y1"])

        if revocation_hash == compute_sha256_hash(status_hash):
            status = 1 # revoked
        elif validity_hash == compute_hash_chain(status_hash, days_passed + 1, hash_print) or \
             validity_hash == compute_hash_chain(status_hash, days_passed, hash_print):
            # +1: if status arrived on the intended day
            # +0: if the status arrived one day later
            status = 0 # still valid
        else:
            raise AssertionError("ERROR: Invalid hash value - must have been modified!")

        if status == 0: # still valid
            self.revocation_status = message.get("hash") # stored in hex()

            with open(self.pipe_name, 'w') as pipe:
                if self.manipulated_date is None:
                    mocked_date_str = ""
                else:
                    mocked_date_str = self.manipulated_date.isoformat()
                revocation_update = f"{mocked_date_str}|{self.revocation_status}"
                pipe.write(revocation_update)

            if self.print_mode:
                print("Your certificate is still valid :)")

        else: # is revoked
            if self.print_mode:
                print("Your certificate has been revoked :(")

            self.__private_key, self.public_key = generate_keypair_ECDH()
            self.request_certificate()

        if self.eval_mode_scalability_ecdh and not self.user_name == "Alice Armstrong":
            self.initiate_ecdh("dtn://alice-armstrong.dtn/alicearmstrong")


    def request_certificate_revocation(self):
        """Requests the revocation of the user's certificate, and automatically requests a new certificate after generating a new key pair."""

        if self.print_mode:
            print(f"Requesting certificate revocation for {self.user_name} ...")

        message = {
            "type": "REQ_CERT_REVOC",
            "certificate": self.certificate
        }
        super().send_message(
            dest_eid=self.ca_eid + self.ca_agentid,
            payload=json.dumps(message),
            aap2_client=self.aap2_sender_client
        )
        self.__private_key, self.public_key = generate_keypair_ECDH()
        self.request_certificate()


    # ECDH: ------------------------------------------------------------------------

    def initiate_ecdh(self, dest_eid):
        """Initiates an Elliptic-Curve Diffie-Hellman (ECDH) key exchange with another user.

        Args:
            dest_eid (str): The endpoint identifier of the user to exchange keys with.
        """

        if self.print_mode:
            print(f"INFO: Requesting communication ...")

        if self.eval_mode_time:
            global start_req_ecdh_timer
            start_req_ecdh_timer = time.time()

        message = {
            "type": "REQ_ECDH",
            "certificate": self.certificate,
            "certificate_signature": self.certificate_signature,
            "status": self.revocation_status
        }
        super().send_message(
            dest_eid=dest_eid,
            payload=json.dumps(message),
            aap2_client=self.aap2_sender_client
        )
        print("message sent")


    def receive_ecdh_request(self, message):
        """Processes an incoming ECDH key exchange request.

        Args:
            message (dict): The message containing the ECDH request.
        """

        sender_name = message.get("certificate")["ID"]

        if self.eval_mode_scalability_ecdh:
            self.log_request_reception(sender_name)

        if self.print_mode:
            print(f"INFO: Received request from {sender_name} to talk to you!")
            hash_print = True
        else:
            hash_print = False

        self.verify_ecdh(message, hash_print)

        if self.print_mode:
            print(f"INFO: Accepting communication request from {sender_name} ...")

        destination_eid = f"dtn://{''.join([i for i in sender_name.replace(' ', '-').lower() if not i.isdigit()])}.dtn/{sender_name.replace(' ', '').lower()}"
        # structure is designed such, in order to also accomodate users of the form user1, user2, ..., with hardcoded node ID "dtn://user.dtn/" (used for the evaluation)

        response = {
            "type": "ACK_ECDH",
            "certificate": self.certificate,
            "certificate_signature": self.certificate_signature,
            "status": self.revocation_status,
        }
        super().send_message(
            dest_eid=destination_eid,
            payload=json.dumps(response),
            aap2_client=self.aap2_sender_client
        )

        if not self.eval_mode_scalability_ecdh:
            self.execute_ecdh(message)


    def receive_ecdh_acknowledgement(self, message):
        """Processes an ECDH key exchange acknowledgement.

        Args:
            message (dict): The message containing the ECDH acknowledgement.
        """

        sender_name = message.get("certificate")["ID"]

        if self.print_mode:
            print(f"INFO: Request for communication with {sender_name} has been accepted.")
            hash_print = True
        else:
            hash_print = False

        if self.eval_mode_scalability_ecdh:
            self.log_message_reception()
            sys.exit(0)

        self.verify_ecdh(message, hash_print)
        self.execute_ecdh(message)

        if self.eval_mode_time:
            global end_req_ecdh_timer, start_communication_timer
            end_req_ecdh_timer = time.time()
            start_communication_timer = time.time()

            # Simulate normal message exchange like in communication.py:
            key_aes = bytes.fromhex(self.__user_database[message.get("certificate")["ID"]][-1])
            message_enc = encrypt_message(key_aes, "Hello, here is Alice!")

            payload = {
                "message": message_enc,
                "status": self.revocation_status
            }
            super().send_message(
                dest_eid="dtn://bob-brown.dtn/bobbrown",
                payload=json.dumps(payload),
                aap2_client=self.aap2_sender_client
            )


    def verify_ecdh(self, message, hash_print):
        """Verifies the integrity and authenticity of an ECDH message, by verifying the validity of the partner's certificate and revocation status.

        Args:
            message (dict): The message containing the ECDH request or acknowledgement.
            hash_print (bool): Flag indicating whether to print hash information (how many hash calculations are conducted).
        """

        verify_Ed25519_signature(
                signature=bytes.fromhex(message.get("certificate_signature")),
                data=json.dumps(message.get("certificate")).encode('utf-8'),
                public_key=self.ca_public_key
        )
        certificate = message.get("certificate")
        days_passed = (get_current_date().date() - datetime.datetime.fromisoformat(certificate["D1"]).date()).days
        status_hash = bytes.fromhex(message.get("status"))
        validity_hash = bytes.fromhex(certificate[f"X{self.certificate_validity_period}"])

        try:
            assert any(
                validity_hash == compute_hash_chain(status_hash, days_passed + offset, hash_print)
                for offset in (0, 1, -1)
            )
            # 0: regular case
            # +1: status for tommorrow has already arrived & self.revocation_status has been updated
            # -1: status for today has not arrived yet (grace_period = 1)
        except AssertionError:
            print("ERROR: Invalid hash value - must have been modified!")
            raise

        if self.eval_mode_time:
            if self.evaluation_time_mode == 100:
                # simulate worst case revocation status checking:
                for i in [362, 363, 364]:
                    random_hash = compute_hash_chain(os.urandom(32), i)
            elif self.evaluation_time_mode == 50:
                # simulate average case revocation checking:
                for i in [182]:
                    random_hash = compute_hash_chain(os.urandom(32), i)
            elif self.evaluation_time_mode == 0:
                # simulate best case scenario:
                pass
            else:
                raise ValueError("ERROR: Your provided mode is not supported! Valid modes are 0, 50, and 100.")


    def execute_ecdh(self, message):
        """Executes the ECDH key exchange process, and stores relevant certificate information from the communication partner into the user database.

        Args:
            message (dict): The message containing the ECDH request or acknowledgement.
        """

        partner_public_key_ecdh = der_to_public_key(bytes.fromhex(message.get("certificate")["PK"]))
        partner_name = message.get("certificate")["ID"]

        shared_secret = perform_x25519_ecdh(self.__private_key, partner_public_key_ecdh)
        key_aes = derive_shared_AES_key(shared_secret)

        self.__user_database[partner_name] = [
            message.get("certificate")["D1"],
            message.get("certificate")["D2"],
            message.get("certificate")[f"X{self.certificate_validity_period}"], message.get("certificate")["Y1"],
            key_aes.hex()
        ]

        if not self.eval_mode_time:
            self.start_conversation(partner_name)


    # COMMUNICATION: ---------------------------------------------------------------------

    def start_conversation(self, communication_partner_name):
        """Starts a conversation with another user, by starting a new subprocess and opening a new terminal.

        If self.mock_date_is_triggered and self.manipulated_date in class Node are set, this also passes the mocked date into the subprocess, to ensure proper revocation status checking within this subprocess.

        Args:
            communication_partner_name (str): The name of the communication partner.
        """

        key = self.__user_database[communication_partner_name][4] # key stored in hex()
        partner_certificate_issuance_date = self.__user_database[communication_partner_name][0]
        partner_validity_hash = self.__user_database[communication_partner_name][2]

        if self.mock_date_is_triggered and self.manipulated_date is not None:
            manipulated_date_str = self.manipulated_date.isoformat()
        else:
            manipulated_date_str = ""

        # Open a new terminal:
        command = [
            'gnome-terminal', '--', 'bash', '-c',
            f'source .venv/bin/activate && python test/dtn_crypto_chat/communication.py '
            f'{shlex.quote(self.user_name)} '
            f'{shlex.quote(self.socket)} '
            f'{shlex.quote(self.revocation_status)} '
            f'{shlex.quote(self.secret)} '
            f'{shlex.quote(communication_partner_name)} '
            f'{shlex.quote(key)} '
            f'{shlex.quote(partner_certificate_issuance_date)} '
            f'{shlex.quote(partner_validity_hash)} '
            f'{shlex.quote(manipulated_date_str)} '
            f'{shlex.quote(self.pipe_name)}; exec bash'
        ]
        subprocess.Popen(command)


    def initiate_communication(self, entered_username):
        """Initiates communication with a user.

        If the user is already present in the user database, this means a key has already been agreed on, and communication can be resumed.

        If the user is not present in the user database yet, this means no prior communication with this communication partner has been conducted, and a new ECDH key exchange must first be made.

        Args:
            entered_username (str): The username of the intended communication partner.
        """

        destination_eid = f"dtn://{entered_username.replace(' ', '-').lower()}.dtn/{entered_username.replace(' ', '').lower()}"

        if entered_username in self.__user_database:
            if self.print_mode:
                print(f"Resuming conversation with user {entered_username} ...")

            message = {
            "type": "RES_COMM",
            "name": self.user_name,
            }
            super().send_message(
                dest_eid=destination_eid,
                payload=json.dumps(message),
                aap2_client=self.aap2_sender_client
            )
            self.start_conversation(entered_username)

        else:
            self.initiate_ecdh(destination_eid)


    # EVALUATION: ---------------------------------------------------------------------

    def time_evaluation(self, message):
        """Assists the evaluation of the time taken for sending a message from one user to another user, with key management employed.

        Simulates the message exchange between Alice and Bob, which would normally take place in communication.py.
        Stores the defined time stamps into a separate file for later evaluation.

        Args:
            message (dict): The message to process for time evaluation.
        """

        # Bob receives Alice's message and replies
        if self.eval_mode_time and self.user_name == "Bob Brown":
            if self.evaluation_time_mode == 100:
                # simulate worst case revocation status checking:
                for i in [362, 363, 364]:
                    random_hash = compute_hash_chain(os.urandom(32), i)
            elif self.evaluation_time_mode == 50:
                # simulate average case revocation checking:
                for i in [182]:
                    random_hash = compute_hash_chain(os.urandom(32), i)
            elif self.evaluation_time_mode == 0:
                # simulate best case scenario:
                pass
            else:
                raise ValueError("ERROR: Your provided mode is not supported! Valid modes are 0, 50, and 100.")

            k_aes = bytes.fromhex(self.__user_database["Alice Armstrong"][-1])

            message_dec = decrypt_message(k_aes, message.get("message"))
            print(f"Bob Brown received message: {message_dec}")

            message_enc = encrypt_message(k_aes, "Hello, here is Bob!")

            payload = {
                "message": message_enc,
                "status": self.revocation_status
            }
            super().send_message(
                dest_eid="dtn://alice-armstrong.dtn/alicearmstrong",
                payload=json.dumps(payload),
                aap2_client=self.aap2_sender_client
            )

        # Alice receives Bob's reply
        elif self.eval_mode_time and self.user_name == "Alice Armstrong":
            if self.evaluation_time_mode == 100:
                # simulate worst case revocation status checking:
                for i in [362, 363, 364]:
                    random_hash = compute_hash_chain(os.urandom(32), i)
            elif self.evaluation_time_mode == 50:
                # simulate average case revocation checking:
                for i in [182]:
                    random_hash = compute_hash_chain(os.urandom(32), i)
            elif self.evaluation_time_mode == 0:
                # simulate best case scenario:
                pass
            else:
                raise ValueError("ERROR: Your provided mode is not supported! Valid modes are 0, 50, and 100.")

            k_aes = bytes.fromhex(self.__user_database["Bob Brown"][-1])

            message_dec = decrypt_message(k_aes, message.get("message"))
            print(f"Alice Armstrong received message back: {message_dec}")

            global end_communication_timer, end_overall_timer
            end_communication_timer = time.time()

            global start_req_cert_timer, end_req_cert_timer, start_req_ecdh_timer, end_req_ecdh_timer, start_communication_timer

            metrics = {
                    "request_certificate": {
                        "start_time": start_req_cert_timer,
                        "end_time": end_req_cert_timer,
                        "total_time": end_req_cert_timer - start_req_cert_timer,
                    },
                    "initiate_ecdh": {
                        "start_time": start_req_ecdh_timer,
                        "end_time": end_req_ecdh_timer,
                        "total_time": end_req_ecdh_timer - start_req_ecdh_timer,
                    },
                    "communication": {
                        "start_time": start_communication_timer,
                        "end_time": end_communication_timer,
                        "total_time": end_communication_timer - start_communication_timer,
                    },
                    "overall": {
                        "calculation": (end_req_cert_timer - start_req_cert_timer) + (end_req_ecdh_timer - start_req_ecdh_timer) + (end_communication_timer - start_communication_timer)
                    }
                }
            with open("measurements_key_management.txt", 'w') as f:
                json.dump(metrics, f, indent=4)


def main():
    """The main function to set up a user and handle communication based on command-line arguments."""

    parser = argparse.ArgumentParser(description='Register an user to start chatting.')

    # Positional arguments:
    parser.add_argument(
        'config_file',
        type=str,
        help='Path to the configuration file used to set up the user'
    )

    # Optional arguments
    parser.add_argument(
        '-p', '--print-mode',
        action='store_true',
        help='Enable print mode',
    )
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
        '--eval-scalability-ecdh',
        action='store_true',
        help='Enable evaluation mode: scalability, sending multiple ECDH requests to one user',
    )
    parser.add_argument(
        '--eval-time',
        action='store_true',
        help='Enable evaluation mode: time consumption',
    )
    parser.add_argument(
        '--eval-time-mode',
        type=int,
        help='Determines the date that is simulated, and therefore the length of the hash chain (0/50/100 percent)',
    )
    args = parser.parse_args()

    config = read_config(args.config_file)

    arg_eid = config['eid']
    arg_agentid = config['agentid']
    arg_socket = config['socket']
    arg_user_name = config['user_name']
    arg_ca_eid = config['ca_eid']
    arg_ca_agentid = config['ca_agentid']
    arg_ca_public_key_der = config['ca_public_key']

    arg_secret = b64encode(os.urandom(5)).decode('utf-8')

    user = User(arg_eid, arg_agentid, arg_socket, arg_secret, arg_user_name, arg_ca_eid, arg_ca_agentid, arg_ca_public_key_der, args.print_mode, args.eval_scalability_reqcert, args.eval_scalability_revstatus, args.eval_scalability_ecdh, args.eval_time, args.eval_time_mode)

    if any([
        args.eval_scalability_reqcert,
        args.eval_scalability_revstatus,
        args.eval_scalability_ecdh,
        args.eval_time
    ]):
        try:
            if args.eval_scalability_revstatus:
                print("Attaching receiver to :", user.user_name)
            user.receive_message(user.aap2_receiver_client)

        except KeyboardInterrupt:
            print("Exiting...")

        finally:
            user.disconnect()

    else:
        receive_thread = threading.Thread(target=user.receive_message, args=(user.aap2_receiver_client,))
        receive_thread.daemon = True
        receive_thread.start()

        try:
            while True:
                if not user.certificate:
                    time.sleep(1)
                    continue

                input_information = input("Who do you want to write a message to? (or enter 'rr' for a revocation request): ")

                if input_information == "rr":
                    user.request_certificate_revocation()
                else:
                    communication_partner = input_information
                    user.initiate_communication(communication_partner)

        except KeyboardInterrupt:
            print("Exiting ...")

        finally:
            user.disconnect()


if __name__ == "__main__":
    main()
