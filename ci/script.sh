#!/bin/bash

# the main build
set -e

run_cargo() {
    pushd "$1"
    travis-cargo test
    travis-cargo --only stable doc
    if test "$TRAVIS_RUST_VERSION" = "nightly"; then
        cargo clippy --features=$TRAVIS_CARGO_NIGHTLY_FEATURE -- -Wclippy_pedantic
    fi
    popd
}

run_cargo commoncrypto-sys
