#!/bin/bash -e

cargo_install() {
    local binary="$1"
    local crate="$2"

    test -x $HOME/.cargo/bin/$binary || cargo install $crate
}

cargo_install_update() {
    local binary="$1"
    local crate="$2"

    cargo_install "$binary" "$crate"
    cargo install-update $crate
}

cargo_install cargo-install-update cargo-update
cargo_install_update rustfmt rustfmt

if test "$TRAVIS_RUST_VERSION" = "stable"; then
    cargo_install_update cargo-coverage cargo-travis
elif test "$TRAVIS_RUST_VERSION" = "nightly"; then
    cargo_install_update cargo-clippy clippy
fi
