#!/bin/bash

# the main build
set -e

travis-cargo build
travis-cargo test
travis-cargo --only stable doc

if test "$TRAVIS_RUST_VERSION" = "nightly"; then
    cargo clippy --features=$TRAVIS_CARGO_NIGHTLY_FEATURE -- -Wclippy_pedantic
fi
