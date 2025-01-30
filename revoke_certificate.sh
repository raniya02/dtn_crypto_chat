#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0


# -------------------------------------------------------------------------------
# Revoke Certificate Script
#
# This script is used by the Certificate Authority (CA) to revoke certificates
# for selected users based on their names. It initializes a Revocation Authority
# (RA) instance, configures communication with the CA, and allows to
# input the name of the certificate owner whose certificate should be revoked.
#
# The script performs the following tasks:
# 1. Sets up and starts the Revocation Authority (RA) instance.
# 2. Establishes communication between the RA and the CA.
# 3. Prompts to input the name of the certificate owner for revocation.
# 4. Sends a revocation request from the RA to the CA to revoke the specified certificate.
#
# Usage:
# Run this script from within the "ud3tn" directory:
#   $ test/dtn_crypto_chat/revoke_certificate.sh
#
# The script will handle cleanup and termination of processes upon exit.
# -------------------------------------------------------------------------------


set -euo pipefail

BP_VERSION=7 # Bundle Protocol version to be used (BPv7)


# -------------------------------------------------------------------------------
# Configuration Variables
# These variables define the details for the Revocation Authority (RA).
# -------------------------------------------------------------------------------


# Config variables - Revocation Authority (RA)
RA_EID="dtn://ra.dtn/"
RA_AGENTID="ra"
RA_SOCKET="ud3tn6.aap2.socket"
RA_AAP_PORT=4247
RA_MTCP_PORT=4229

# Set the working directory to the current directory (assumed to be "ud3tn").
UD3TN_DIR="$(pwd)"

# Process ID for the RA instance
RA_PID=0


# -------------------------------------------------------------------------------
# Cleanup Function
# This function handles cleanup of the RA instance upon script exit.
# -------------------------------------------------------------------------------


cleanup() {
    echo "Cleaning up..."
    if [[ $RA_PID -ne 0 ]]; then
        echo "Stopping RA instance..."
        kill "$RA_PID" || true
        wait "$RA_PID" || true
    fi
    echo "Exiting."
    exit 0
}

# Trap to ensure cleanup is called on script exit or termination signals
trap cleanup SIGINT SIGTERM

# Source the CA configuration
source ./ca_config.sh

cat <<EOL > ca_config.sh
export CA_EID=$CA_EID
export CA_AGENTID=$CA_AGENTID
export CA_MTCP_PORT=$CA_MTCP_PORT
EOL


# -------------------------------------------------------------------------------
# Start Revocation Authority (RA) Instance
# Initializes and starts the RA instance.
# -------------------------------------------------------------------------------


# Start instance Revocation Authority:
echo "Starting RA instance ..."

"$UD3TN_DIR/build/posix/ud3tn" --eid "$RA_EID" --bp-version "$BP_VERSION" --aap-port "$RA_AAP_PORT" -S "$UD3TN_DIR/$RA_SOCKET" --cla "mtcp:127.0.0.1,$RA_MTCP_PORT" > /tmp/ra.log 2>&1 &
RA_PID=$!

echo "Successfully started RA instance."


# -------------------------------------------------------------------------------
# Configure Contact from RA to CA
# Establishes communication from the RA to the CA.
# -------------------------------------------------------------------------------


echo "Configuring contact from \"RA\" to \"CA\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$RA_SOCKET" --schedule 1 3600000 100000 "$CA_EID" "mtcp:localhost:$CA_MTCP_PORT"

echo "Finished establishing contact from \"RA\" to \"CA\"."


# -------------------------------------------------------------------------------
# Main Loop: Revoke Certificates
# Continuously prompts to enter the owner of the certificate to be revoked.
# -------------------------------------------------------------------------------


while true; do

    read -p "Please enter the name of the owner whose certificate should be revoked: " USER_INPUT

    JSON_STRING="{\"type\": \"REVOKE_CERT\", \"ID\": \"$USER_INPUT\"}"

    # Send message from RA to CA (triggers revoke_certificate function in ca.py):
    (python "$UD3TN_DIR/tools/aap2/aap2_send.py" --socket "$UD3TN_DIR/$RA_SOCKET" "$CA_EID$CA_AGENTID" "$JSON_STRING") &

done


# -------------------------------------------------------------------------------
# Cleanup
# Ensure cleanup is called when the script exits.
# -------------------------------------------------------------------------------


cleanup
