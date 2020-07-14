# Contributing to rust-commoncrypto

rust-commoncrypto is a part of the Rust ecosystem. As such, all contributions to this project follow
the [Rust language's code of conduct](https://www.rust-lang.org/conduct.html) where appropriate.

This project is hosted at [GitHub](https://github.com/malept/rust-commoncrypto). Both pull requests
and issues of many different kinds are accepted.

## Filing Issues

Issues include bugs, questions, feedback, and feature requests. Before you file a new issue, please
make sure that your issue has not already been filed by someone else.

### Filing Bugs

When filing a bug, please include the following information:

* Rust version that compiled the `commoncrypto` crate.
* The version (and/or git revision) of the `commoncrypto` crate.
* A detailed list of steps to reproduce the bug. A minimal testcase would be very helpful,
  if possible.
* If there any any error messages in the console, copying them in the bug summary will be
  very helpful.

## Filing Pull Requests

Here are some things to keep in mind as you file a pull request to fix a bug, add a new feature,
etc.:

* Travis CI is used to make sure that the project builds as expected on the supported platforms,
* using the current stable and beta versions of Rust.
  Make sure the testsuite passes locally by running `cargo test`.
* Unless it's impractical, please write tests for your changes. This will help spot regressions
  much easier.
* If your PR changes the behavior of an existing feature, or adds a new feature, please add/edit
  the `rustdoc` inline documentation.
* Please ensure that your changes follow the [rustfmt](https://github.com/rust-lang-nursery/rustfmt)
  coding standard, and do not produce any warnings when running the
  [clippy](https://github.com/Manishearth/rust-clippy) linter.
* If you are contributing a nontrivial change, please add an entry to `NEWS.md`. The format is
  similar to the one described at [Keep a Changelog](http://keepachangelog.com/).
* Please **do not** bump the version number in your pull requests, the maintainers will do that.
  Feel free to indicate whether the changes require a major, minor, or patch version bump, as
  prescribed by the [semantic versioning specification](http://semver.org/).
* Please make sure your commits are rebased onto the latest commit in the main branch, and that
  you limit/squash the number of commits created to a "feature"-level. For instance:

bad:

```
commit 1: add foo
commit 2: run rustfmt
commit 3: add test
commit 4: add docs
commit 5: add bar
commit 6: add test + docs
```

good:

```
commit 1: add foo
commit 2: add bar
```

If you are continuing the work of another person's PR and need to rebase/squash, please retain the
attribution of the original author(s) and continue the work in subsequent commits.
