#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0


# -------------------------------------------------------------------------------
# Scalability Evaluation - Receiver Setup Script (Alice)
#
# This script sets up a scalability test environment where Alice (a user in the
# chat application) is subjected to multiple simultaneous ECDH key exchange
# requests. The script is intended to be run alongside "scal_ca.sh" and "scal_user.sh".
#
# The script performs the following tasks:
# 1. Parses command-line options to get the IP addresses of the Certificate
#    Authority (CA) and the sender (the user initiating the ECDH requests).
# 2. Configures and starts Alice's instance.
# 3. Establishes communication contacts between Alice, the CA, and the sender instance.
# 4. Monitors Alice's CPU and memory usage during the test.
# 5. Counts and logs the number of ECDH requests Alice successfully handles.
#
# Usage:
#   $ ./scal_receiver.sh -c <CA_IP_ADDRESS> -s <SENDER_IP_ADDRESS>
#
# Options:
#   -c  CA_IP_ADDRESS (mandatory)
#   -s  SENDER_IP_ADDRESS (mandatory)
#
# Examples:
#   $ ./scal_receiver.sh -c 192.168.1.10 -s 192.168.1.20
#
# The script will handle cleanup and termination of processes upon exit.
# -------------------------------------------------------------------------------


set -euo pipefail

CA_IP_ADDRESS=""
SENDER_IP_ADDRESS=""

# Function to display usage instructions
usage() {
    echo "Usage: $0 -c <CA_IP_ADDRESS> -s <SENDER_IP_ADDRESS>"
    echo "  -c  CA_IP_ADDRESS (mandatory)"
    echo "  -s  SENDER_IP_ADDRESS (mandatory)"
    exit 1
}

# Parse command-line options
while getopts "c:s:" opt; do
  case ${opt} in
    c)
      CA_IP_ADDRESS=${OPTARG}
      ;;
    s)
      SENDER_IP_ADDRESS=${OPTARG}
      ;;
    *)
      usage
      ;;
  esac
done

shift $((OPTIND -1))

# Check if mandatory arguments are provided
if [ -z "$CA_IP_ADDRESS" ] || [ -z "$SENDER_IP_ADDRESS" ]; then
    echo "Error: CA_IP_ADDRESS and SENDER_IP_ADDRESS are both mandatory."
    usage
fi


# -------------------------------------------------------------------------------
# Configuration Variables
# These variables define the details for Alice, the CA, and the sender.
# -------------------------------------------------------------------------------


# Alice's Configuration
EID="dtn://alice-armstrong.dtn/"
AGENTID="alicearmstrong"
SOCKET="ud3tn3.aap2.socket"
AAP_PORT=4244
MTCP_PORT=4226
USER_NAME="Alice Armstrong"

# CA Configuration
CA_EID="dtn://ca.dtn/"
CA_AGENTID="ca"
CA_SOCKET="ud3tn1.aap2.socket"
CA_AAP_PORT=4242
CA_MTCP_PORT=4224
CA_PUBLIC_KEY="302a300506032b657003210027d11f1cbbb79f1104b443537572ea7dbceb9272b0916260333331fbd1c9cb9d"

# Sender Configuration
SENDER_MTCP_PORT=4225
SENDER_EID="dtn://user.dtn/"


# Set the working directory to the current directory (assumed to be "ud3tn").
UD3TN_DIR="$(pwd)"

# Process ID of Alice
ALICE_PID=0


# -------------------------------------------------------------------------------
# Cleanup Function
# This function handles cleanup of all processes upon script exit.
# -------------------------------------------------------------------------------


cleanup() {
    echo "Cleaning up..."

    killall python ud3tn top > /dev/null 2>&1
    fuser -k $MTCP_PORT/tcp > /dev/null 2>&1

#     if [ $CA_PID -ne 0 ]; then
#         kill $CA_PID > /dev/null 2>&1
#     fi
#     if [ $USER_PID -ne 0 ]; then
#         kill $USER_PID > /dev/null 2>&1
#     fi

    wait
    echo "All processes terminated."
}

# Remove old log files
rm -f ecdh_request_reception.log /tmp/alice.log

# Trap to ensure cleanup is called on script exit
trap cleanup EXIT


# Function to monitor CPU usage
monitor_cpu_usage() {
    local PID="$1"
    local LOG_FILE="$2"
    local INTERVAL="$3"

    # This code snippet is taken from: https://www.baeldung.com/linux/process-periodic-cpu-usage
    top -b -d "$INTERVAL" -p $PID | awk \
        -v cpuLog="$LOG_FILE" -v pid="$PID" '
        /^top -/{time = $3}
        $1+0>0 {printf "%s %s :: PID[%s] CPU Usage: %d%%\n", \
                strftime("%Y-%m-%d"), time, pid, $9 > cpuLog
                fflush(cpuLog)}'
    # End of taken code snippet
}

# Function to monitor memory usage
monitor_memory_usage() {
    local PID="$1"
    local LOG_FILE="$2"
    local INTERVAL="$3"

    # Inspired by the taken code snippet from above:
    top -b -d "$INTERVAL" -p $PID | awk \
        -v memLog="$LOG_FILE" -v pid="$PID" '
        /^top -/{time = $3}
        $1+0>0 {printf "%s %s :: PID[%s] Memory Usage: %s%% (%s KB)\n", \
                strftime("%Y-%m-%d"), time, pid, $10, $6 > memLog
                fflush(memLog)}'
    # End of inspired code
}


# -------------------------------------------------------------------------------
# Start Alice's Instance
# Initializes and starts Alice's instance.
# -------------------------------------------------------------------------------


echo "Setting up \"Alice\" ..."

"$UD3TN_DIR/build/posix/ud3tn" --eid "$EID" --aap-port "$AAP_PORT" --aap2-socket "$UD3TN_DIR/$SOCKET" --cla "mtcp:*,$MTCP_PORT" -L 4 > /tmp/alice.log 2>&1 &
ALICE_PID=$!

echo "If you are ready to configure the contact, press ENTER:"
read WAIT_PLACEHOLDER


# -------------------------------------------------------------------------------
# Configure Contacts
# Establishes contacts between Alice, the CA, and the sender.
# -------------------------------------------------------------------------------


# Establish contact between CA and Alice
echo "Configuring contact between \"CA\" and \"Alice\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$SOCKET" --schedule 1 3600000 100000 "$CA_EID" "mtcp:$CA_IP_ADDRESS:$CA_MTCP_PORT"

# Establish contact between the sender and Alice
echo "Configuring contact between \"Sender\" and \"Alice\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$SOCKET" --schedule 1 3600000 100000 "$SENDER_EID" "mtcp:$SENDER_IP_ADDRESS:$SENDER_MTCP_PORT"


# -------------------------------------------------------------------------------
# Start Python Process for Alice
# Begins monitoring Alice's CPU and memory usage while handling ECDH requests.
# -------------------------------------------------------------------------------


TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Log files for CPU and memory usage
CPU_LOG_FILE="/tmp/alice_cpu_usage_${TIMESTAMP}.log"
CPU_MONITOR_INTERVAL=0.5
MEMORY_LOG_FILE="/tmp/alice_memory_usage_${TIMESTAMP}.log"
MEMORY_MONITOR_INTERVAL=0.5

# Configuration file for Alice
cat <<EOL > alice_config
[user]
eid=$EID
agentid=$AGENTID
socket=$SOCKET
user_name=$USER_NAME
ca_eid=$CA_EID
ca_agentid=$CA_AGENTID
ca_public_key=$CA_PUBLIC_KEY
EOL

# Start the Python process for Alice to handle ECDH requests
python "$UD3TN_DIR/test/dtn_crypto_chat/user.py" "alice_config" --eval-scalability-ecdh --print-mode &
ALICE_PY_PID=$!
echo "ALICE Python PID: $ALICE_PY_PID"


# Monitor CPU and memory usage
monitor_cpu_usage $ALICE_PY_PID $CPU_LOG_FILE $CPU_MONITOR_INTERVAL &
CPU_MONITOR_PID=$!
echo "CPU Monitor PID: $CPU_MONITOR_PID"

monitor_memory_usage $ALICE_PY_PID $MEMORY_LOG_FILE $MEMORY_MONITOR_INTERVAL &
MEMORY_MONITOR_PID=$!
echo "Memory Monitor PID: $MEMORY_MONITOR_PID"

# Allow the test to run for a while
sleep 30


# -------------------------------------------------------------------------------
# Wait for Process Completion and Cleanup
# Waits for Alice's Python process to complete, then stops monitoring.
# -------------------------------------------------------------------------------

wait $ALICE_PY_PID
kill $CPU_MONITOR_PID
kill $MEMORY_MONITOR_PID


# -------------------------------------------------------------------------------
# Analyze Results
# Counts and displays the number of received ECDH requests.
# -------------------------------------------------------------------------------


# Count how many messages were received:
RECEIVED_COUNT=$(grep -c "Received ECDH request" "ecdh_request_reception.log")
echo "Number of messages received: $RECEIVED_COUNT"

sleep 1
