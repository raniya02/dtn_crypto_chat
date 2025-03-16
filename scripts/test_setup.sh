#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause OR Apache-2.0


# -------------------------------------------------------------------------------
# Setup Script for µD3TN Instances
#
# This script sets up the details for each user and the Certificate Authority (CA).
# It initializes µD3TN instances for each entity and configures the contacts using
# the AAP2 protocol. The script also generates a key pair for the CA and writes the
# configuration details for each user to a file for further use in the chat application.
#
# Requirements:
# - The script assumes it is being run from within the "ud3tn" directory.
# - Python and the necessary Python scripts/tools are available in the specified paths.
#
# The script performs the following tasks:
# 1. Initializes µD3TN instances for CA, Alice, Bob, and Carol.
# 2. Configures communication contacts between these entities.
# 3. Generates a public/private key pair for the CA.
# 4. Writes configuration files for Alice, Bob, Carol, and the CA.
#
# Usage:
# Run the script from within the "ud3tn" directory:
#   $ test/dtn_crypto_chat/test_setup.sh
#
# The script will automatically handle process cleanup upon exit.
# -------------------------------------------------------------------------------


set -euo pipefail


# -------------------------------------------------------------------------------
# Configuration Variables
# These variables define the details for the CA and the users: Alice, Bob, and Carol.
# -------------------------------------------------------------------------------


# Config variables - Certificate Authority (CA):
CA_EID="dtn://ca.dtn/"
CA_AGENTID="ca"
CA_SOCKET="ud3tn-ca.aap2.socket"
CA_AAP_PORT=5242
CA_MTCP_PORT=5224
CA_IP_ADDRESS="localhost"

# Config variables - first instance: Alice Armstrong
A_NAME="Alice Armstrong"
A_EID="dtn://alice-armstrong.dtn/"
A_AGENTID="alicearmstrong"
A_SOCKET="ud3tn-alice.aap2.socket"
A_AAP_PORT=5243
A_MTCP_PORT=5225
A_IP_ADDRESS="localhost"

# Config variables - second instance: Bob Brown
B_NAME="Bob Brown"
B_EID="dtn://bob-brown.dtn/"
B_AGENTID="bobbrown"
B_SOCKET="ud3tn-bob.aap2.socket"
B_AAP_PORT=5244
B_MTCP_PORT=5226
B_IP_ADDRESS="localhost"

# Config variables - third instance: Carol Clark
C_NAME="Carol Clark"
C_EID="dtn://carol-clark.dtn/"
C_AGENTID="carolclark"
C_SOCKET="ud3tn-carol.aap2.socket"
C_AAP_PORT=5245
C_MTCP_PORT=5227
C_IP_ADDRESS="localhost"


# -------------------------------------------------------------------------------
# Environment Setup
# Defines paths and handles process termination upon script exit.
# -------------------------------------------------------------------------------


# Set the working directory.
UD3TN_DIR="$(pwd)/ud3tn"

# Process IDs for each entity
CA_PID=0
A_PID=0
B_PID=0
C_PID=0

# Function to handle script exit and cleanup
exit_handler() {
    echo "Terminating all processes..."
    [ $CA_PID -ne 0 ] && kill -TERM $CA_PID || true
    [ $A_PID -ne 0 ] && kill -TERM $A_PID || true
    [ $B_PID -ne 0 ] && kill -TERM $B_PID || true
    [ $C_PID -ne 0 ] && kill -TERM $C_PID || true

    wait $CA_PID $A_PID $B_PID $C_PID || true

#     echo
#     echo ">>> CA LOGFILE"
#     cat "/tmp/ca.log" || true
#     echo
#     echo ">>> A LOGFILE"
#     cat "/tmp/a.log" || true
#     echo
#     echo ">>> B LOGFILE"
#     cat "/tmp/b.log" || true
#     echo
#     echo ">>> C LOGFILE"
#     cat "/tmp/c.log" || true
#     echo
}

# Trap to ensure the exit handler is called on script exit
trap exit_handler EXIT

# Clean up any existing log files
rm -f /tmp/a.log /tmp/b.log /tmp/c.log /tmp/ca.log


# -------------------------------------------------------------------------------
# Setup µD3TN Instances
# Start the µD3TN instances for the CA and the three users.
# -------------------------------------------------------------------------------


# Start instance Certificate Authority:
echo "Setting up Certificate Authority \"CA\" ..."

"$UD3TN_DIR/build/posix/ud3tn" --eid "$CA_EID" --aap-port "$CA_AAP_PORT" --aap2-socket "$UD3TN_DIR/$CA_SOCKET" --cla "mtcp:*,$CA_MTCP_PORT" > /tmp/ca.log 2>&1 &
CA_PID=$!


# Start user Alice Armstrong:
echo "Setting up uD3TN user \"Alice\" ..."

"$UD3TN_DIR/build/posix/ud3tn" --eid "$A_EID" --aap-port "$A_AAP_PORT" --aap2-socket "$UD3TN_DIR/$A_SOCKET" --cla "mtcp:*,$A_MTCP_PORT" > /tmp/a.log 2>&1 &
A_PID=$!


# Start user Bob Brown:
echo "Starting second uD3TN user \"Bob\" ..."

"$UD3TN_DIR/build/posix/ud3tn" --eid "$B_EID" --aap-port "$B_AAP_PORT" --aap2-socket "$UD3TN_DIR/$B_SOCKET" --cla "mtcp:*,$B_MTCP_PORT" > /tmp/b.log 2>&1 &
B_PID=$!


# Start user Carol Clark:
echo "Setting up uD3TN user \"Carol\" ..."

"$UD3TN_DIR/build/posix/ud3tn" --eid "$C_EID" --aap-port "$C_AAP_PORT" --aap2-socket "$UD3TN_DIR/$C_SOCKET" --cla "mtcp:*,$C_MTCP_PORT" > /tmp/c.log 2>&1 &
C_PID=$!


# -------------------------------------------------------------------------------
# Configure Contacts
# Establishes the communication links between the CA and users, and between users.
# -------------------------------------------------------------------------------


# CA <=> Alice Armstrong:
echo "Configuring contact between \"CA\" and \"Alice\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$CA_SOCKET" --schedule 1 3600000 100000 "$A_EID" "mtcp:$A_IP_ADDRESS:$A_MTCP_PORT"

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$A_SOCKET" --schedule 1 3600000 100000 "$CA_EID" "mtcp:$CA_IP_ADDRESS:$CA_MTCP_PORT"


# CA <=> Bob Brown:
echo "Configuring contact between \"CA\" and \"Bob\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$CA_SOCKET" --schedule 1 3600000 100000 "$B_EID" "mtcp:$B_IP_ADDRESS:$B_MTCP_PORT"

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$B_SOCKET" --schedule 1 3600000 100000 "$CA_EID" "mtcp:$CA_IP_ADDRESS:$CA_MTCP_PORT"


# CA <=> Carol Clark:
echo "Configuring contact between \"CA\" and \"Carol\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$CA_SOCKET" --schedule 1 3600000 100000 "$C_EID" "mtcp:$C_IP_ADDRESS:$C_MTCP_PORT"

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$C_SOCKET" --schedule 1 3600000 100000 "$CA_EID" "mtcp:$CA_IP_ADDRESS:$CA_MTCP_PORT"


# Alice Armstrong <=> Bob Brown:
echo "Configuring contact between \"Alice\" and \"Bob\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$A_SOCKET" --schedule 1 3600000 100000 "$B_EID" "mtcp:$B_IP_ADDRESS:$B_MTCP_PORT"

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$B_SOCKET" --schedule 1 3600000 100000 "$A_EID" "mtcp:$A_IP_ADDRESS:$A_MTCP_PORT"


# Alice Armstrong <=> Carol Clark:
echo "Configuring contact between \"Alice\" and \"Carol\" ..."

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$A_SOCKET" --schedule 1 3600000 100000 "$C_EID" "mtcp:$C_IP_ADDRESS:$C_MTCP_PORT"

python "$UD3TN_DIR/tools/aap2/aap2_config.py" --socket "$UD3TN_DIR/$C_SOCKET" --schedule 1 3600000 100000 "$A_EID" "mtcp:$A_IP_ADDRESS:$A_MTCP_PORT"


# -------------------------------------------------------------------------------
# Generate and Write Configuration Files
# Generates the CA's private and public key pair and writes user configurations.
# -------------------------------------------------------------------------------


# Generate private public key pair of CA:
KEYS=$(python "$(pwd)/src/generate_CA_keys.py")
# Split the output into two variables:
IFS=',' read -r CA_PRIVATE_KEY CA_PUBLIC_KEY <<< "$KEYS"

# Write CA's configuration to a file (used for mocking revocation):
cat <<EOL > ca_config.sh
export CA_EID=$CA_EID
export CA_AGENTID=$CA_AGENTID
export CA_MTCP_PORT=$CA_MTCP_PORT
EOL

# Write Alice's configuration to a file:
cat <<EOL > alice_config
[user]
eid=$A_EID
agentid=$A_AGENTID
socket=${UD3TN_DIR}/${A_SOCKET}
user_name=$A_NAME
ca_eid=$CA_EID
ca_agentid=$CA_AGENTID
ca_public_key=$CA_PUBLIC_KEY
EOL

# Write Bob's configuration to a file:
cat <<EOL > bob_config
[user]
eid=$B_EID
agentid=$B_AGENTID
socket=${UD3TN_DIR}/${B_SOCKET}
user_name=$B_NAME
ca_eid=$CA_EID
ca_agentid=$CA_AGENTID
ca_public_key=$CA_PUBLIC_KEY
EOL

# Write Carol's configuration to a file:
cat <<EOL > carol_config
[user]
eid=$C_EID
agentid=$C_AGENTID
socket=${UD3TN_DIR}/${C_SOCKET}
user_name=$C_NAME
ca_eid=$CA_EID
ca_agentid=$CA_AGENTID
ca_public_key=$CA_PUBLIC_KEY
EOL


# -------------------------------------------------------------------------------
# Start CA Python Instance
# Finally, starts the Python instance for the CA using the generated keys.
# -------------------------------------------------------------------------------


# Start Python instance CA:
python "$(pwd)/src/ca.py" "$CA_EID" "$CA_AGENTID" "$UD3TN_DIR/$CA_SOCKET" "$CA_PRIVATE_KEY" "$CA_PUBLIC_KEY" &

wait $CA_PID $A_PID $B_PID $C_PID

echo "All processes terminated."
