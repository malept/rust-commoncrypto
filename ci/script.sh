#!/bin/bash -xe

run_clippy() {
    dir="$1"
    pushd "$dir" > /dev/null

    # https://github.com/Manishearth/rust-clippy/issues/1707
    if test "$TRAVIS_RUST_VERSION" = "nightly"; then
        cargo +nightly clippy -- --allow clippy_pedantic
        echo "Completed clippy in $dir"
    fi
    popd > /dev/null
}

#
# Based on comments in https://www.reddit.com/r/rust/comments/5f3oov/
#
run_rustfmt() {
    local changed_rust_files
    if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
        changed_rust_files="$(git diff --name-only "$TRAVIS_COMMIT" "$TRAVIS_BRANCH" . | (grep \.rs$; true))"
    else
        changed_rust_files="$(git show --format= --name-only "$TRAVIS_COMMIT_RANGE" . | sort -u | (grep \.rs$; true))"
    fi

    if [[ -n "$changed_rust_files" ]]; then
        cargo fmt --all -- --write-mode=diff $changed_rust_files
    fi
    echo "Completed rustfmt"
}

cargo test --all
if test "$TRAVIS_RUST_VERSION" = "stable"; then
    cargo doc --all
fi

run_rustfmt

run_clippy commoncrypto-sys
run_clippy commoncrypto
