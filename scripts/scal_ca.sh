#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0


# -------------------------------------------------------------------------------
# Scalability Evaluation - Certificate Authority Setup Script
#
# This script sets up the Certificate Authority (CA) for scalability evaluation tests.
# Depending on the evaluation mode, it will configure the CA to handle different
# scalability scenarios:
# 1. "reqcert": Evaluate the CA's ability to handle multiple certificate requests.
# 2. "revstatus": Evaluate the CA's ability to send revocation status updates.
# 3. "sendecdh": Assists in evaluating an user's (e.g. Alice's) ability to handle multiple ECDH (Elliptic Curve
#    Diffie-Hellman) requests from different users.
#
# In the case of "reqcert" or "revstatus", this script is expected to be run along
# with "scal_user.sh".
# If the mode is "sendecdh", this script is expected to be run along with both
# "scal_user.sh" and "scal_receiver.sh".
#
# The script performs the following tasks:
# 1. Parses command-line options to determine the evaluation mode and IP addresses.
# 2. Configures and starts the CA instance.
# 3. Establishes contact between the CA and the user, and optionally between the
#    CA and Alice (in case of mode "sendecdh").
# 4. Monitors and logs CPU and memory usage during the evaluation.
#
# Usage:
#   $ ./scal_ca.sh -t <TEST_MODE> -u <USER_IP_ADDRESS> [-a <ALICE_IP_ADDRESS>]
#
# Options:
#   -t  TEST_MODE (mandatory, reqcert/revstatus/sendecdh)
#   -u  USER_IP_ADDRESS (mandatory)
#   -a  ALICE_IP_ADDRESS (required if TEST_MODE is 'sendecdh')
#
# Examples:
#   $ ./scal_ca.sh -t reqcert -u 192.168.1.10
#   $ ./scal_ca.sh -t sendecdh -u 192.168.1.10 -a 192.168.1.20
#
# The script will handle cleanup and termination of processes upon exit.
# -------------------------------------------------------------------------------


set -euo pipefail


ALICE_IP_ADDRESS=""
USER_IP_ADDRESS=""
TEST_MODE=""

# Function to display usage instructions
usage() {
    echo "Usage: $0 -t <TEST_MODE> -u <USER_IP_ADDRESS> [-a <ALICE_IP_ADDRESS>]"
    echo "  -t  TEST_MODE (mandatory, reqcert/revstatus/sendecdh)"
    echo "  -u  USER_IP_ADDRESS (mandatory)"
    echo "  -a  ALICE_IP_ADDRESS (required if TEST_MODE is 'sendecdh')"
    exit 1
}

# Parse command-line options
while getopts "t:u:a:" opt; do
  case ${opt} in
    t)
      TEST_MODE=${OPTARG}
      ;;
    u)
      USER_IP_ADDRESS=${OPTARG}
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

# Check if TEST_MODE and USER_IP_ADDRESS are provided
if [ -z "$TEST_MODE" ] || [ -z "$USER_IP_ADDRESS" ]; then
    echo "Error: TEST_MODE and USER_IP_ADDRESS are both mandatory."
    usage
fi

# Check if ALICE_IP_ADDRESS is required and provided
if [ "$TEST_MODE" == "sendecdh" ] && [ -z "$ALICE_IP_ADDRESS" ]; then
    echo "Error: ALICE_IP_ADDRESS is required when TEST_MODE is 'sendecdh'."
    usage
fi

# Set up timestamp for log files
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")


# Determine arguments and log file names based on the test mode
if [ "$TEST_MODE" = "reqcert" ]; then
    ARGUMENT="--eval-scalability-reqcert"
    CPU_MONITOR_INTERVAL=1
    CPU_LOG_FILE="/tmp/ca_cpu_reqcert_${TIMESTAMP}.log"
    MEMORY_LOG_FILE="/tmp/ca_memory_reqcert_${TIMESTAMP}.log"
    MEMORY_MONITOR_INTERVAL=1

elif [ "$TEST_MODE" = "revstatus" ]; then
    ARGUMENT="--eval-scalability-revstatus --revocation-database revocation_database.pkl"
    CPU_MONITOR_INTERVAL=0.5
    CPU_LOG_FILE="/tmp/ca_cpu_revstatus_${TIMESTAMP}.log"
    MEMORY_LOG_FILE="/tmp/ca_memory_revstatus_${TIMESTAMP}.log"
    MEMORY_MONITOR_INTERVAL=0.5

elif [ "$TEST_MODE" = "sendecdh" ]; then
    ARGUMENT="--eval-scalability-ecdh"
    CPU_MONITOR_INTERVAL=0.5
    CPU_LOG_FILE="/tmp/ca_cpu_sendecdh_${TIMESTAMP}.log"
    MEMORY_LOG_FILE="/tmp/ca_memory_sendecdh_${TIMESTAMP}.log"
    MEMORY_MONITOR_INTERVAL=0.5

else
    echo "Error: Your provided argument is not a supported mode."
    exit 1

fi


# -------------------------------------------------------------------------------
# Configuration Variables
# These variables define the details for the CA, User, and Alice.
# -------------------------------------------------------------------------------


# Config variables - Certificate Authority (CA):
CA_EID="dtn://ca.dtn/"
CA_AGENTID="ca"
CA_SOCKET="ud3tn1.aap2.socket"
CA_AAP_PORT=4242
CA_MTCP_PORT=4224

CA_PRIVATE_KEY="302e020100300506032b657004220420f859981507b4ad7a66f2a8236788b20ff2824ec246115a7a943e7af94f202172"
CA_PUBLIC_KEY="302a300506032b657003210027d11f1cbbb79f1104b443537572ea7dbceb9272b0916260333331fbd1c9cb9d"

USER_MTCP_PORT=4225
USER_EID="dtn://user.dtn/"

ALICE_MTCP_PORT=4226
ALICE_EID="dtn://alice-armstrong.dtn/"


# Set the working directory.
UD3TN_DIR="$(pwd)/ud3tn"

# Process ID for the CA instance.
CA_PID=0


# -------------------------------------------------------------------------------
# Cleanup Function
# This function handles cleanup of all processes upon script exit.
# -------------------------------------------------------------------------------


cleanup() {
    echo "Cleaning up..."

    killall python ud3tn top > /dev/null 2>&1
    fuser -k $CA_MTCP_PORT/tcp > /dev/null 2>&1

    wait
    echo "All processes terminated."
}

# Remove old log files
rm -f request_reception.log /tmp/ca.log

# Trap to ensure cleanup is called on script exit
trap cleanup EXIT


# -------------------------------------------------------------------------------
# Monitoring Functions
# These functions monitor CPU and memory usage of the CA during the evaluation.
# -------------------------------------------------------------------------------


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
# Start Certificate Authority (CA) Instance
# Initializes and starts the CA instance.
# -------------------------------------------------------------------------------


echo "Setting up Certificate Authority \"CA\" ..."

"$UD3TN_DIR/build/posix/ud3tn" --eid "$CA_EID" --aap-port "$CA_AAP_PORT" --aap2-socket "$UD3TN_DIR/$CA_SOCKET" --cla "mtcp:*,$CA_MTCP_PORT" -L 4 > /tmp/ca.log 2>&1 &
CA_PID=$!

echo "If you are ready to configure the contact, press ENTER:"
read WAIT_PLACEHOLDER


# -------------------------------------------------------------------------------
# Configure Contacts
# Establishes contact between CA and the user, and optionally with Alice.
# -------------------------------------------------------------------------------


# Establish contact between CA and the user
echo "Configuring contact between \"CA\" and \"User\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$CA_SOCKET" --schedule 1 3600000 100000 "$USER_EID" "mtcp:$USER_IP_ADDRESS:$USER_MTCP_PORT"

if [ "$TEST_MODE" = "sendecdh" ]; then
    # Establish contact between CA and Alice
    echo "Configuring contact between \"CA\" and \"Alice\" ..."

    python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$CA_SOCKET" --schedule 1 3600000 100000 "$ALICE_EID" "mtcp:$ALICE_IP_ADDRESS:$ALICE_MTCP_PORT"
fi


# -------------------------------------------------------------------------------
# Start Python CA Instance
# Starts the CA instance and begins monitoring CPU and memory usage.
# -------------------------------------------------------------------------------


python "src/ca.py" "$CA_EID" "$CA_AGENTID" "$UD3TN_DIR/$CA_SOCKET" "$CA_PRIVATE_KEY" "$CA_PUBLIC_KEY" $ARGUMENT &
CA_PY_PID=$!
echo "CA Python PID: $CA_PY_PID"

monitor_cpu_usage $CA_PY_PID $CPU_LOG_FILE $CPU_MONITOR_INTERVAL &
CPU_MONITOR_PID=$!
echo "CPU Monitor PID: $CPU_MONITOR_PID"

monitor_memory_usage $CA_PY_PID $MEMORY_LOG_FILE $MEMORY_MONITOR_INTERVAL &
MEMORY_MONITOR_PID=$!
echo "Memory Monitor PID: $CPU_MONITOR_PID"
MEMORY_MONITOR_PID=$!


# -------------------------------------------------------------------------------
# Wait for CA Process Completion
# Waits for the CA Python process to complete, then stops monitoring.
# -------------------------------------------------------------------------------


wait $CA_PY_PID
kill $CPU_MONITOR_PID
kill $MEMORY_MONITOR_PID


# -------------------------------------------------------------------------------
# Final Output (for reqcert mode)
# Counts and displays the number of received messages in reqcert mode.
# -------------------------------------------------------------------------------


if [ "$TEST_MODE" = "reqcert" ]; then
    # Count how many messages were received:
    RECEIVED_COUNT=$(grep -c "Received request" "request_reception.log")
    echo "Number of messages received: $RECEIVED_COUNT"
fi
