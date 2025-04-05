#!/bin/bash

# Directory and key file paths
SSH_DIR="$HOME/.ssh"
PRIVATE_KEY="$SSH_DIR/id_rsa"
PUBLIC_KEY="$SSH_DIR/id_rsa.pub"

# Create ~/.ssh directory if it doesn't exist
if [ ! -d "$SSH_DIR" ]; then
    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    echo "Created SSH directory: $SSH_DIR"
fi

# Generate SSH key pair if it doesn't exist
if [ ! -f "$PRIVATE_KEY" ]; then
    echo "Generating new SSH key pair..."
    ssh-keygen -t rsa -b 4096 -f "$PRIVATE_KEY" -N "" -q
    chmod 600 "$PRIVATE_KEY"
    chmod 644 "$PUBLIC_KEY"
    echo "SSH key pair generated:"
    echo "Private key: $PRIVATE_KEY"
    echo "Public key:  $PUBLIC_KEY"
    echo ""
    echo "Public key content:"
    cat "$PUBLIC_KEY"
else
    echo "SSH key pair already exists:"
    echo "Private key: $PRIVATE_KEY"
    echo "Public key:  $PUBLIC_KEY"
    echo ""
    echo "Public key content:"
    cat "$PUBLIC_KEY"
fi
