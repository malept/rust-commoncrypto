#!/bin/bash

# the main build
set -xe

run_cargo() {
    dir="$1"
    pushd "$dir" > /dev/null

    run_rustfmt
    travis-cargo test
    travis-cargo --only stable doc
    if test "$TRAVIS_RUST_VERSION" = "nightly"; then
        cargo clippy --features=$TRAVIS_CARGO_NIGHTLY_FEATURE -- -Wclippy_pedantic
    fi
    popd
    echo "Completed $dir"
}

run_rustfmt() {
    if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
        files="$(git diff --name-only "$TRAVIS_COMMIT" "$TRAVIS_BRANCH" . | grep \.rs$)"
    else
        files="$(git show --format= --name-only "$TRAVIS_COMMIT_RANGE" . | sort -u | grep \.rs$)"
    fi

    if [[ -n "$files" ]]; then
        cargo fmt -- --write-mode=diff $files
    fi
    echo "Completed rustfmt"
}

run_cargo commoncrypto-sys
run_cargo commoncrypto
