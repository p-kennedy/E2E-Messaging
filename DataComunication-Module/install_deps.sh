#!/bin/bash
# install_deps.sh
# Installs all system dependencies needed to build the C++ secure messaging client.
# Run once after cloning the repo: ./install_deps.sh

set -e  # exit immediately if any command fails

echo "=== Installing dependencies for Secure Messaging Client ==="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS — please install dependencies manually."
    exit 1
fi

if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    echo "[apt] Updating package lists..."
    sudo apt-get update -qq

    echo "[apt] Installing build tools and OpenSSL..."
    sudo apt-get install -y \
        build-essential \
        cmake \
        libssl-dev \
        pkg-config

    echo "[apt] Done."

elif [[ "$OS" == "fedora" || "$OS" == "rhel" || "$OS" == "centos" ]]; then
    sudo dnf install -y \
        gcc-c++ \
        cmake \
        openssl-devel \
        pkgconfig

elif [[ "$OS" == "arch" ]]; then
    sudo pacman -Sy --noconfirm \
        base-devel \
        cmake \
        openssl

else
    echo "Unsupported OS: $OS"
    echo "Please install: cmake, openssl-dev, and a C++17 compiler manually."
    exit 1
fi

echo ""
echo "=== All dependencies installed ==="
echo ""
echo "To build the project, run:"
echo "  cmake -B build -S ."
echo "  cmake --build build"
echo ""
echo "To run the connection test:"
echo "  ./build/test_connection"
