#!/bin/bash -e

install_target_and_cross() {
    # Builds for iOS are done on OSX, but require the specific target to be
    # installed.
    case $TARGET in
        *-apple-ios)
            rustup target install $TARGET
            ;;
    esac

    # This fetches latest stable release
    local tag=$(git ls-remote --tags --refs --exit-code https://github.com/rust-embedded/cross \
                       | cut -d/ -f3 \
                       | grep -E '^v[0.1.0-9.]+$' \
                       | gsort --version-sort \
                       | tail -n1)
    curl -LSfs https://japaric.github.io/trust/install.sh | \
        sh -s -- \
           --force \
           --git japaric/cross \
           --tag $tag \
            --target x86_64-apple-darwin
}

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

if test "$TARGET" = "all-style-docs"; then
    cargo_install cargo-install-update cargo-update
    cargo_install_update cargo-coverage cargo-travis
    rustup component add rustfmt --toolchain $TRAVIS_RUST_VERSION
    rustup component add clippy --toolchain $TRAVIS_RUST_VERSION
else
    install_target_and_cross
fi
