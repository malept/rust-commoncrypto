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

if test "$TRAVIS_RUST_VERSION" = "stable" -a "$TRAVIS_OSX_IMAGE" = "xcode11"; then
    cargo_install_update cargo-coverage cargo-travis
    rustup component add rustfmt --toolchain $TRAVIS_RUST_VERSION
    rustup component add clippy --toolchain $TRAVIS_RUST_VERSION
fi
