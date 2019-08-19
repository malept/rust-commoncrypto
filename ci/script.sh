#!/bin/bash -xe

#
# Based on comments in https://www.reddit.com/r/rust/comments/5f3oov/
#
run_rustfmt() {
    local changed_rust_files
    if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
        changed_rust_files="$(git diff --name-only "$TRAVIS_COMMIT_RANGE" . | grep \.rs$)"
    else
        changed_rust_files="$(git show --format= --name-only "$TRAVIS_COMMIT_RANGE" . | sort -u | grep \.rs$)"
    fi

    if [[ -n "$changed_rust_files" ]]; then
        cargo fmt --all -- --check  $changed_rust_files
    fi
    echo "Completed rustfmt"
}

cargo test --all
if test "$TRAVIS_RUST_VERSION" = "stable" -a "$TRAVIS_OSX_IMAGE" = "xcode11"; then
    cargo doc --all

    run_rustfmt
    cargo clippy --all -- --allow clippy::pedantic
fi
