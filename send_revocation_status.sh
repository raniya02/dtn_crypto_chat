#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0


# -------------------------------------------------------------------------------
# Send Revocation Status Script
#
# This script triggers the Certificate Authority (CA) to send revocation status
# updates to all users in the system. The script operates in two modes:
# 1. "chat": Regular functionality where revocation status updates are sent.
# 2. "evaluation": Used for scalability testing by sending revocation status updates
#    to evaluate the system's performance.
#
# The script performs the following tasks:
# 1. Parses command-line options to determine the mode and CA IP address.
# 2. Configures and starts a service instance for communication.
# 3. Establishes contact between the service instance and the CA.
# 4. Sends a message to the CA to trigger the sending of revocation status updates.
#
# Usage:
#   $ ./send_revocation_status.sh -m <MODE> [-c <CA_IP_ADDRESS>]
#
# Options:
#   -m  MODE (mandatory, 'chat' for regular functionality or 'evaluation' for scalability testing)
#   -c  CA_IP_ADDRESS (required if MODE is 'evaluation')
#
# Examples:
#   $ ./send_revocation_status.sh -m chat
#   $ ./send_revocation_status.sh -m evaluation -c 192.168.1.10
#
# -------------------------------------------------------------------------------


set -euo pipefail

MODE=""
CA_IP_ADDRESS=""

usage() {
    echo "Usage: $0 -m <MODE> [-c <CA_IP_ADDRESS>]"
    echo "  -m  MODE (mandatory, 'chat' for regular functionality / 'evaluation' for testing scalability)"
    echo "  -c  CA_IP_ADDRESS (required if MODE is 'evaluation')"
    exit 1
}

# Parse command-line options
while getopts "m:c:" opt; do
  case ${opt} in
    m)
      MODE=${OPTARG}
      ;;
    c)
      CA_IP_ADDRESS=${OPTARG}
      ;;
    *)
      usage
      ;;
  esac
done

shift $((OPTIND -1))

# Check if MODE is provided
if [ -z "$MODE" ]; then
    echo "Error: MODE is mandatory."
    usage
fi

# Check if CA_IP_ADDRESS is required and provided
if [ "$MODE" == "evaluation" ] && [ -z "$CA_IP_ADDRESS" ]; then
    echo "Error: CA_IP_ADDRESS is required when MODE is 'evaluation'."
    usage
fi


# -------------------------------------------------------------------------------
# Configuration Variables
# These variables define the details for the service instance.
# -------------------------------------------------------------------------------


# Config variables - service instance
SERVICE_EID="dtn://service.dtn/"
SERVICE_AGENTID="service"
SERVICE_SOCKET="ud3tn5.aap2.socket"
SERVICE_AAP_PORT=4246
SERVICE_MTCP_PORT=4228

# # Set the working directory to the current directory (assumed to be "ud3tn").
UD3TN_DIR="$(pwd)"

# Process ID for the Service Instance
SERVICE_PID=0

# JSON string to trigger revocation status updates
JSON_STRING='{"type": "SEND_STATUS"}'


# -------------------------------------------------------------------------------
# Mode Setup
# Configure based on the selected mode ('chat' or 'evaluation').
# -------------------------------------------------------------------------------


if [ "$MODE" = "chat" ]; then
    source ./ca_config.sh
    IP_CA="localhost"

    cat <<EOL > ca_config.sh
export CA_EID=$CA_EID
export CA_AGENTID=$CA_AGENTID
export CA_MTCP_PORT=$CA_MTCP_PORT
EOL

elif [ "$MODE" = "evaluation" ]; then
    CA_EID="dtn://ca.dtn/"
    CA_AGENTID="ca"
    CA_MTCP_PORT=4224
    IP_CA=$CA_IP_ADDRESS

else
    echo "Error: Your provided argument is not a supported mode."
    exit 1
fi


# -------------------------------------------------------------------------------
# Cleanup Function
# This function handles cleanup of the service instance upon script exit.
# -------------------------------------------------------------------------------


trap "fuser -k $SERVICE_MTCP_PORT/tcp > /dev/null 2>&1" EXIT


# -------------------------------------------------------------------------------
# Start Service Instance
# Initializes and starts the service instance.
# -------------------------------------------------------------------------------


echo "Starting Service instance ..."

"$UD3TN_DIR/build/posix/ud3tn" --eid "$SERVICE_EID" --aap-port "$SERVICE_AAP_PORT" --aap2-socket "$UD3TN_DIR/$SERVICE_SOCKET" --cla "mtcp:127.0.0.1,$SERVICE_MTCP_PORT" > /tmp/service.log 2>&1 &
SERVICE_PID=$!

echo "Successfully started Service instance."


# -------------------------------------------------------------------------------
# Configure Contact from Service to CA
# Establishes communication from the service instance to the CA.
# -------------------------------------------------------------------------------


echo "Configuring contact from \"Service\" to \"CA\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$SERVICE_SOCKET" --schedule 1 3600000 100000 "$CA_EID" "mtcp:$IP_CA:$CA_MTCP_PORT"

echo "Finished establishing contact from \"Service\" to \"CA\"."


# -------------------------------------------------------------------------------
# Send Revocation Status Update Trigger
# Sends a message to the CA to trigger the sending of revocation status updates.
# -------------------------------------------------------------------------------


# Send message from Service to CA (triggers send_revocation_status function in ca.py):
python "$UD3TN_DIR/tools/aap2/aap2_send.py" --socket "$UD3TN_DIR/$SERVICE_SOCKET" "$CA_EID$CA_AGENTID" "$JSON_STRING"

# Brief sleep to allow processes to complete
sleep 2
