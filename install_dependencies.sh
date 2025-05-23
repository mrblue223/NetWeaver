#!/bin/bash

# This script helps install Python packages required by your application.

echo "Checking for Python and pip..."

# Check if Python is installed
if ! command -v python3 &> /dev/null
then
    echo "Python 3 is not found. Please install Python 3 first."
    echo "You can usually download it from https://www.python.org/downloads/"
    exit 1
fi

# Check if pip is installed for Python 3
if ! command -v pip3 &> /dev/null
then
    echo "pip (Python package installer) for Python 3 is not found."
    echo "Attempting to install pip for Python 3..."
    python3 -m ensurepip --default-pip
    if [ $? -ne 0 ]; then
        echo "Failed to install pip. Please install it manually, e.g., 'sudo apt install python3-pip' on Debian/Ubuntu."
        exit 1
    fi
    echo "pip installed successfully."
fi

echo "All standard library modules (tkinter, socket, threading, time, sys, os, mimetypes, ipaddress, signal, ssl) are included with Python."
echo "No separate download is needed for them."
echo ""
echo "Installing third-party packages..."

# Install Pillow, which provides PIL.Image and PIL.ImageTk
echo "Installing Pillow..."
pip3 install Pillow

if [ $? -eq 0 ]; then
    echo "Pillow installed successfully."
    echo "All necessary Python dependencies should now be available."
else
    echo "Failed to install Pillow. Please check the error messages above."
    echo "You might need to run this script with 'sudo' if you encounter permission errors (e.g., 'sudo ./install_dependencies.sh')."
fi
