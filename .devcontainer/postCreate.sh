#!/bin/bash

set -e

mise install

sudo apt update -y
sudo apt-get install -y gcc-mingw-w64-x86-64 build-essential
