#!/usr/bin/env sh
set -e

# Install root dev dependencies
python -m pip install -r requirements-dev.txt

# Install liboqs-python dev extras
python -m pip install -e ./liboqs-python[dev]

echo "Dev dependencies installed."