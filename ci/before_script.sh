#!/bin/bash

set -e

if [[ -z $(which pip) ]]; then
    curl -sSLO https://bootstrap.pypa.io/get-pip.py
	python get-pip.py --user
fi

# load travis-cargo
pip install 'travis-cargo<0.2' --user

if test "$TRAVIS_RUST_VERSION" = "nightly"; then
    if ! cargo install --list | grep -q clippy; then
        cargo install clippy
    fi
fi
