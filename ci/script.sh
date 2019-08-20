#!/bin/bash -xe

#
# Based on comments in https://www.reddit.com/r/rust/comments/5f3oov/
#
run_rustfmt() {
    local changed_rust_files
    if [ "$TRAVIS_PULL_REQUEST" != "false" ]; then
        changed_rust_files="$(git diff --name-only "$TRAVIS_COMMIT_RANGE" . | grep \.rs$; true)"
    else
        changed_rust_files="$(git show --format= --name-only "$TRAVIS_COMMIT_RANGE" . | gsort -u | grep \.rs$; true)"
    fi

    if [[ -n "$changed_rust_files" ]]; then
        cargo fmt --all -- --check  $changed_rust_files
    fi
    echo "Completed rustfmt"
}

if test "$TARGET" = "all-style-docs"; then
    cargo doc --all

    run_rustfmt
    cargo clippy --all -- --allow clippy::pedantic
else
    cross build --target $TARGET
    cross build --target $TARGET --release

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cross test --target $TARGET
    cross test --target $TARGET --release
fi
