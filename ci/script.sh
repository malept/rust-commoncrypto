#!/bin/bash

# the main build
set -e

run_cargo() {
    pushd "$1"
    if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
        cargo fmt -- --write-mode=diff $(git diff --name-only "$TRAVIS_COMMIT" "$TRAVIS_BRANCH" | grep \.rs$)
    else
        cargo fmt -- --write-mode=diff $(git show --format= --name-only "$TRAVIS_COMMIT_RANGE" | sort -u | grep \.rs$)
    fi
    travis-cargo test
    travis-cargo --only stable doc
    if test "$TRAVIS_RUST_VERSION" = "nightly"; then
        cargo clippy --features=$TRAVIS_CARGO_NIGHTLY_FEATURE -- -Wclippy_pedantic
    fi
    popd
}

run_cargo commoncrypto-sys
run_cargo commoncrypto
