#!/bin/bash

# the main build
set -e

run_cargo() {
    dir="$1"
    pushd "$dir" > /dev/null

    run_rustfmt
    travis-cargo test
    travis-cargo --only stable doc
    if test "$TRAVIS_RUST_VERSION" = "nightly"; then
        cargo clippy --features=$TRAVIS_CARGO_NIGHTLY_FEATURE -- -Wclippy_pedantic
    fi
    popd > /dev/null
    echo "Completed $dir"
}

#
# Based on comments in https://www.reddit.com/r/rust/comments/5f3oov/
#
run_rustfmt() {
    if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
        files="$(git diff --name-only "$TRAVIS_COMMIT" "$TRAVIS_BRANCH" . | (grep \.rs$; true))"
    else
        files="$(git show --format= --name-only "$TRAVIS_COMMIT_RANGE" . | sort -u | (grep \.rs$; true))"
    fi

    if [[ -n "$files" ]]; then
        cargo fmt -- --write-mode=diff $files
    fi
    echo "Completed rustfmt"
}

run_cargo commoncrypto-sys
run_cargo commoncrypto
