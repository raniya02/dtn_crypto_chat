#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0


# -------------------------------------------------------------------------------
# Scalability Evaluation - User Setup Script
#
# This script sets up a specified number of user instances to evaluate the scalability
# of the chat application. Depending on the evaluation mode, the script can simulate
# the load of multiple users interacting with the Certificate Authority (CA) and
# optionally with Alice in the network.
#
# In the case of "reqcert" or "revstatus", this script is expected to be run along
# with "scal_ca.sh".
# If the mode is "sendecdh", this script is expected to be run along with both
# "scal_ca.sh" and "scal_receiver.sh".
#
# The script performs the following tasks:
# 1. Parses command-line options to determine the evaluation mode and other parameters.
# 2. Configures and starts user instances.
# 3. Establishes contacts between the CA and users, and optionally between Alice and users.
# 4. Monitors and counts the number of messages received to assess the system's scalability.
#
# Usage:
#   $ ./scal_user.sh -t <TEST_MODE> -u <AMOUNT_USERS> -r <AMOUNT_RUNS> -c <CA_IP_ADDRESS> [-a <ALICE_IP_ADDRESS>]
#
# Options:
#   -t  TEST_MODE (mandatory, reqcert/revstatus/sendecdh)
#   -u  AMOUNT_USERS (mandatory, per second)
#   -r  AMOUNT_RUNS (mandatory, TOTAL_USERS = AMOUNT_USERS (per second) * AMOUNT_RUNS)
#   -c  CA_IP_ADDRESS (mandatory)
#   -a  ALICE_IP_ADDRESS (required if TEST_MODE is 'sendecdh')
#
# Examples:
#   $ ./scal_user.sh -t reqcert -u 10 -r 5 -c 192.168.1.10
#   $ ./scal_user.sh -t sendecdh -u 5 -r 4 -c 192.168.1.10 -a 192.168.1.20
#
# The script will handle cleanup and termination of processes upon exit.
# -------------------------------------------------------------------------------


set -euo pipefail

TEST_MODE=""
AMOUNT_USERS="" # amount users per second
AMOUNT_RUNS=""
CA_IP_ADDRESS=""
ALICE_IP_ADDRESS=""


# Function to display usage instructions
usage() {
    echo "Usage: $0 -t <TEST_MODE> -u <AMOUNT_USERS> -r <AMOUNT_RUNS> -c <CA_IP_ADDRESS> [-a <ALICE_IP_ADDRESS>]"
    echo "  -t  TEST_MODE (mandatory, reqcert/revstatus/sendecdh)"
    echo "  -u  AMOUNT_USERS (mandatory, per second)"
    echo "  -r  AMOUNT_RUNS (mandatory, TOTAL_USERS = AMOUNT_USERS (per second) * AMOUNT_RUNS)"
    echo "  -c  CA_IP_ADDRESS (mandatory)"
    echo "  -a  ALICE_IP_ADDRESS (required if TEST_MODE is 'sendecdh')"
    exit 1
}

# Parse command-line options
while getopts "t:u:r:c:a:" opt; do
  case ${opt} in
    t)
      TEST_MODE=${OPTARG}
      ;;
    u)
      AMOUNT_USERS=${OPTARG}
      ;;
    r)
      AMOUNT_RUNS=${OPTARG}
      ;;
    c)
      CA_IP_ADDRESS=${OPTARG}
      ;;
    a)
      ALICE_IP_ADDRESS=${OPTARG}
      ;;
    *)
      usage
      ;;
  esac
done

shift $((OPTIND -1))


# Check if the mandatory arguments are provided
if [ -z "$CA_IP_ADDRESS" ] || [ -z "$AMOUNT_USERS" ] || [ -z "$AMOUNT_RUNS" ] || [ -z "$TEST_MODE" ]; then
    echo "Error: CA_IP_ADDRESS, AMOUNT_USERS, AMOUNT_RUNS, and TEST_MODE are all mandatory."
    usage
fi

# Check if ALICE_IP_ADDRESS is required and provided
if [ "$TEST_MODE" == "sendecdh" ] && [ -z "$ALICE_IP_ADDRESS" ]; then
    echo "Error: ALICE_IP_ADDRESS is required when TEST_MODE is 'sendecdh'."
    usage
fi


# Determine arguments and log files based on the test mode
if [ "$TEST_MODE" = "reqcert" ]; then
    ARGUMENT="--eval-scalability-reqcert"
    LOGFILE_KM="certificate_reception.log"
    MSG_CONTENT="Received certificate"
    WAIT_TIME=6
elif [ "$TEST_MODE" = "revstatus" ]; then
    ARGUMENT="--eval-scalability-revstatus"
    LOGFILE_KM="status_reception.log"
    MSG_CONTENT="Received status"
    WAIT_TIME=15
elif [ "$TEST_MODE" = "sendecdh" ]; then
    ARGUMENT="--eval-scalability-ecdh"
    LOGFILE_KM="ecdh_reception.log"
    MSG_CONTENT="Received ECDH response"
    WAIT_TIME=20
else
    echo "Error: Your provided argument is not a supported mode."
    exit 1
fi


# -------------------------------------------------------------------------------
# Configuration Variables
# These variables define the details for the users, CA, and optionally Alice.
# -------------------------------------------------------------------------------


# User Configuration
EID="dtn://user.dtn/"
SOCKET="ud3tn2.aap2.socket"
AAP_PORT=4243
MTCP_PORT=4225

# CA Configuration
CA_MTCP_PORT=4224
CA_EID="dtn://ca.dtn/"
CA_AGENTID="ca"
CA_PUBLIC_KEY="302a300506032b657003210027d11f1cbbb79f1104b443537572ea7dbceb9272b0916260333331fbd1c9cb9d"

# Alice Configuration
ALICE_EID="dtn://alice-armstrong.dtn/"
ALICE_SOCKET="ud3tn3.aap2.socket"
ALICE_AAP_PORT=4244
ALICE_MTCP_PORT=4226

# Set the working directory to the current directory (assumed to be "ud3tn").
UD3TN_DIR="$(pwd)"

# Process ID of the User instance
USER_PID=0

USER_NAMES=()


# -------------------------------------------------------------------------------
# Cleanup Function
# This function handles cleanup of all processes upon script exit.
# -------------------------------------------------------------------------------


cleanup() {
    echo "Cleaning up..."

    killall python > /dev/null 2>&1
    killall ud3tn > /dev/null 2>&1
    fuser -k $MTCP_PORT/tcp > /dev/null 2>&1

    wait
    echo "All processes terminated."
}

# Remove old log files
rm -f certificate_reception.log status_reception.log ecdh_reception.log /tmp/user.log

# Trap to ensure cleanup is called on script exit
trap cleanup EXIT


# -------------------------------------------------------------------------------
# Start User Instance
# Initializes and starts the user instance.
# -------------------------------------------------------------------------------


"$UD3TN_DIR/build/posix/ud3tn" --eid "$EID" --aap-port "$AAP_PORT" --aap2-socket "$UD3TN_DIR/$SOCKET" --cla "mtcp:*,$MTCP_PORT" -L 4 > /tmp/user.log 2>&1 &
USER_PID=$!

echo "If you are ready to configure the contact, press ENTER:"
read WAIT_PLACEHOLDER


# -------------------------------------------------------------------------------
# Configure Contacts
# Establishes contact between CA and the user, and optionally with Alice.
# -------------------------------------------------------------------------------


# Establish contact between CA and the user
echo "Configuring contact between \"CA\" and \"User\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$SOCKET" --schedule 1 3600000 100000 "$CA_EID" "mtcp:$CA_IP_ADDRESS:$CA_MTCP_PORT"

if [ "$TEST_MODE" = "sendecdh" ]; then
    # Establish contact between Alice and the user
    echo "Configuring contact between \"Alice\" and \"User\" ..."

    python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$SOCKET" --schedule 1 3600000 100000 "$ALICE_EID" "mtcp:$ALICE_IP_ADDRESS:$ALICE_MTCP_PORT"
fi


# -------------------------------------------------------------------------------
# User Simulation Loop
# Creates the specified number of user instances and starts their Python processes.
# -------------------------------------------------------------------------------


SLEEP_TIME=$(echo "scale=10; 1 / $AMOUNT_USERS" | bc)
TOTAL_AMOUNT=$((AMOUNT_USERS * AMOUNT_RUNS))

# Create Python instances of User and start their instances

for i in $(seq 1 $TOTAL_AMOUNT); do
    USER_NAME="User$i"
    AGENTID="user$i"
    USER_NAMES+=("$USER_NAME")

    # Write user's configuration to a file
    cat <<EOL > user${i}_config
[user]
eid=$EID
agentid=$AGENTID
socket=$SOCKET
user_name=$USER_NAME
ca_eid=$CA_EID
ca_agentid=$CA_AGENTID
ca_public_key=$CA_PUBLIC_KEY
EOL

    USER_CONFIG="user${i}_config"
    python "$UD3TN_DIR/test/dtn_crypto_chat/user.py" "$USER_CONFIG" "$ARGUMENT" --print-mode &

    sleep $SLEEP_TIME

done


# -------------------------------------------------------------------------------
# Wait for Test Completion and Analyze Results
# Waits for the specified time and then counts the received messages.
# -------------------------------------------------------------------------------


sleep $WAIT_TIME


# Count how many messages were received:
RECEIVED_COUNT=$(grep -c "$MSG_CONTENT" "$LOGFILE_KM")
echo "Number of messages received: $RECEIVED_COUNT"

if [ "$RECEIVED_COUNT" -eq "$TOTAL_AMOUNT" ]; then
    echo "All messages received successfully."
else
    echo "Some messages are missing. Expected: $TOTAL_AMOUNT, but got: $RECEIVED_COUNT."
    echo "Users who did not receive their reply:"

    # Print which users did not get their reply:
    for user in "${USER_NAMES[@]}"; do
        if ! grep -q "$user: $MSG_CONTENT" "$LOGFILE_KM"; then
            echo "$user did not receive a reply."
        fi
    done
fi

# Clean up generated configuration files and pipes
rm -f /tmp/user*_pipe user*_config

cleanup
