# Contributing to ksight

ksight welcomes contributions from everyone. Contributing is an opportunity
to improve your technical skills, develop professionally, and participate in
open source Linux tooling.

## Before you start

Review the [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

ksight is dual-licensed under MIT and Apache-2.0. By contributing, you agree
that your changes will be distributed under the same terms.

## Reporting issues

If you find a bug or have a feature request, search the
[GitHub issues](https://github.com/WaiHlyanMinThein17/ksight/issues) first.
If no existing issue covers your case, open a new one with a clear description
and steps to reproduce.

## Setting up for development

ksight uses a forking, feature-based workflow.

Start by creating a personal fork of the repository on GitHub, then clone
your fork:

```bash
git clone git@github.com:<your-username>/ksight.git
cd ksight
git remote add upstream git@github.com:WaiHlyanMinThein17/ksight.git
git fetch upstream
```

ksight is an eBPF project, so building it requires the eBPF cross-compilation
toolchain in addition to a standard Rust install:

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Verify everything is working:

```bash
cargo build
cargo test --workspace --exclude ksight-ebpf
cargo clippy --workspace --exclude ksight-ebpf -- -D warnings
```

Running ksight loads eBPF programs and attaches to kernel tracepoints, which
requires a BTF-enabled kernel and elevated privilege (see the
[README](README.md#requirements)).

## Making a change

Create a branch for your work:

```bash
git checkout -b feat/your-feature-name
```

Branch names should be brief and follow the format
`<type>/<short-description>`. For example, `feat/add-tcp-tracing`
or `fix/histogram-bucket-overflow`.

## Commit style

Format commit messages using
[Conventional Commits](https://www.conventionalcommits.org):

```
feat(ebpf): add TCP connection tracepoints
fix(agent): handle ring buffer wakeup race
docs(readme): document the system-trace interface
```

## Testing

All non-trivial changes to userspace logic should include tests. Run the
test suite with:

```bash
cargo test --workspace --exclude ksight-ebpf
```

The `ksight-ebpf` crate is excluded because it is `no_std` and only builds for
the BPF target; it cannot be run as a host test. eBPF changes are validated by
the kernel verifier at load time and by running ksight on real hardware.

Run formatting and linting before opening a pull request:

```bash
cargo fmt --all
cargo clippy --workspace --exclude ksight-ebpf -- -D warnings
```

All pull requests must pass CI before merging.

## Opening a pull request

Push your branch and open a pull request on GitHub. Title the PR after the
most significant change. Describe what the change does and why. Reference
any related issues.

Maintainers aim to review pull requests within a week.