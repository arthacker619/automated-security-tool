#!/bin/bash

# Update package lists
sudo apt update

# Install required tools
sudo apt install -y subfinder httpx naabu katana nuclei gf dalfox waybackurls openredirex jq curl

# Install Python libraries
pip3 install tqdm

echo "All required tools are installed."
