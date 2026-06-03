#!/bin/bash
# Installs C++ build dependencies for the server network module.
# Called by server/setup.sh — can also be run directly.
set -e

echo "[network] Installing C++ dependencies..."

if [[ "$(uname)" == "Darwin" ]]; then
    if ! command -v brew &>/dev/null; then
        echo "Homebrew not found — install it from https://brew.sh then re-run this script."
        exit 1
    fi
    brew install cmake openssl pkg-config

elif [ -f /etc/os-release ]; then
    . /etc/os-release

    if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
        sudo apt-get update -qq
        sudo apt-get install -y build-essential cmake libssl-dev pkg-config

    elif [[ "$ID" == "fedora" || "$ID" == "rhel" || "$ID" == "centos" ]]; then
        sudo dnf install -y gcc-c++ cmake openssl-devel pkgconfig

    elif [[ "$ID" == "arch" ]]; then
        sudo pacman -Sy --noconfirm base-devel cmake openssl

    else
        echo "Unsupported OS: $ID — install cmake, openssl-dev, and a C++17 compiler manually."
        exit 1
    fi

else
    echo "Cannot detect OS — install cmake, openssl-dev, and a C++17 compiler manually."
    exit 1
fi

echo "[network] C++ dependencies installed."
