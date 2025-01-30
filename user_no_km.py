# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0

"""
Chat Application Simulation Without Key Management

This script is used for evaluation purposes to simulate the chat application
without employing any key management mechanisms. The script enables sending and
receiving messages between users, such as Alice Armstrong and Bob Brown, without
any encryption or key management. It also records the time taken for the communication
between Alice and Bob.

This script requires the configuration file to set up the user details and connection parameters.

Classes:
    Ud3tn_user - Represents a user in the chat application without key management.

Functions:
    main - The main function of the script, responsible for setting up the user and handling communication.

Usage:
    Run this script with a path to the configuration file as an argument. The configuration file is typically automatically generated when invoking 'test_setup.sh' prior.

Example:
    $ python user_no_km.py alice_config
"""


import json
import os
import sys
import argparse
import time

from base64 import b64encode

from node import Node
from utils import read_config


start_communication_timer = None
end_communication_timer = None


class Ud3tn_user(Node):
    """Represents a user in the chat application without key management.

    This class inherits from the Node class and is used to simulate a user
    (e.g., Alice Armstrong or Bob Brown) in a chat application without
    employing any key management mechanisms.

    Attributes:
        user_name (str): The name of the user (e.g., Alice Armstrong, Bob Brown).
    """


    def __init__(self, eid, agentid, socket, secret, user_name):
        """Initializes the Ud3tn_user with user details and requests a test message if the user is Alice.

        Args:
            eid (str): The endpoint identifier for the user, inherited from Node.
            agentid (str): The agent ID for the user, inherited from Node.
            socket (str): The socket path for communication, inherited from Node.
            secret (str): The secret of the user, used to prevent strangers from gaining access to messages by using the agent ID from another user, inherited from Node.
            user_name (str): The name of the user.
        """

        super().__init__(eid, agentid, socket, secret)
        self.user_name = user_name

        if self.user_name == "Alice Armstrong":
            self.request_test_msg()


    def handle_incoming_messages(self, message):
        """Handles incoming messages and responds accordingly.

        If the user is Bob Brown, the message is received, and Bob responds to Alice.
        If the user is Alice Armstrong, the message is received, and the communication time is recorded.

        Args:
            message (dict): The incoming message to be processed.
        """

        if self.user_name == "Bob Brown":
            print(f"Bob Brown received message: {message.get('message')}")

            message = {
                "message": "Hello, here is Bob!",
            }
            super().send_message(
                dest_eid="dtn://alice-armstrong.dtn/alicearmstrong",
                payload=json.dumps(message),
                aap2_client=self.aap2_sender_client
            )

        elif self.user_name == "Alice Armstrong":
            print(f"Alice Armstrong received message back: {message.get('message')}")

            global end_communication_timer, start_communication_timer
            end_communication_timer = time.time()

            metrics = {
                "start_time": start_communication_timer,
                "end_time": end_communication_timer,
                "total_time": end_communication_timer - start_communication_timer
            }
            with open("measurements_no_km.txt", 'w') as f:
                json.dump(metrics, f, indent=4)



    def request_test_msg(self):
        """Requests a test message to be sent to Bob Brown.

        This method is called during initialization if the user is Alice Armstrong.
        It sends an initial message to Bob and starts the communication timer.
        """

        print(f"INFO: Writing a test message to Bob ...")

        global start_communication_timer
        start_communication_timer = time.time()

        message = {
            "message": "Hello, here is Alice!",
        }
        super().send_message(
            dest_eid="dtn://bob-brown.dtn/bobbrown",
            payload=json.dumps(message),
            aap2_client=self.aap2_sender_client
        )


def main():
    """The main function to set up the user and handle communication.

    This function reads the configuration file to set up the user, initializes
    the user object, and starts the message receiving process.
    """

    parser = argparse.ArgumentParser(description='Send and receive messages without any key management.')

     # Positional arguments:
    parser.add_argument(
        'config_file',
        type=str,
        help='Path to the configuration file used to set up the user'
    )

    args = parser.parse_args()

    config = read_config(args.config_file)

    arg_eid = config['eid']
    arg_agentid = config['agentid']
    arg_socket = config['socket']
    arg_user_name = config['user_name']

    arg_secret = b64encode(os.urandom(5)).decode('utf-8')

    ud3tn_user = Ud3tn_user(arg_eid, arg_agentid, arg_socket, arg_secret, arg_user_name)

    try:
        ud3tn_user.receive_message(ud3tn_user.aap2_receiver_client)
    except KeyboardInterrupt:
        print("Exiting...")


if __name__ == "__main__":
    main()
