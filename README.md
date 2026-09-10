# xfw

**A fast IP blocker for Linux, powered by eBPF/XDP.**

`xfw` drops traffic from blocked IPs or IP ranges at the earliest possible point in the network stack, the [XDP](https://www.datadoghq.com/blog/xdp-intro/) (eXpress Data Path) hook, giving packet filtering with minimal CPU overhead, before packets even reach the kernel's networking stack.

## Features

- **XDP-powered**: filtering happens at the driver level for most network interfaces.
- **IPv4 & IPv6** support
- **CIDR ranges**: block entire subnets, not just single IPs

## Installation

### Prerequisites

- Stable Rust toolchain: `rustup toolchain install stable`
- Nightly Rust toolchain (for building the eBPF program): `rustup toolchain install nightly --component rust-src`
- [`bpf-linker`](https://github.com/aya-rs/bpf-linker): `cargo binstall bpf-linker`
- A Linux kernel with XDP support (most modern kernels)

### Build from source

```bash
git clone https://github.com/kakeetopius/xfw.git
cd xfw
cargo install --path xfw
```

The binary will be installed in the directory `~/.cargo/bin/`. `xfw` needs to run as root (or with [`CAP_BPF`/`CAP_NET_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)) since it loads eBPF programs and attaches them to network interfaces.

## Usage

### Start the blocker

Attach the XDP program to one or more interfaces:

```sh
sudo xfw start --ifaces eth0
sudo xfw start -i eth0 -i eth1
sudo xfw start --ifaces all
```

### Block an IP or range

```sh
sudo xfw block 203.0.113.42
sudo xfw block 10.2.2.0/24
sudo xfw block 203.0.113.42 198.51.100.0/24
sudo xfw block -f to_block.txt # block ips listed in a file, one per line.
```

### Unblock an IP or range

```sh
sudo xfw unblock 203.0.113.42
sudo xfw unblock --all
```

### List blocked entries

```sh
sudo xfw list          # all blocked IPs
sudo xfw list -4       # IPv4 only
sudo xfw list -6       # IPv6 only
```

### Export blocked IPs

```sh
sudo xfw export                                        # print each ip one per line
sudo xfw export -f json                                # print as JSON
sudo xfw export -f list                                # print as comma-separated list
sudo xfw export -f json -o blocklist.json              # write to a file
```

### Custom maps directory

By default, `xfw` pins its eBPF maps at `/sys/fs/bpf`. Override this globally with `-m`/`--maps-dir`:

```sh
sudo xfw --maps-dir /sys/fs/bpf/xfw start --ifaces eth0
```

## How it works

`xfw` loads an XDP program into the kernel and attaches it to the specified network interface(s). Blocked IPs and CIDR ranges are stored in eBPF maps pinned to the BPF filesystem (`bpffs`), so the blocklist persists across `xfw` process restarts. Packets matching a blocked entry are dropped at the earliest possible point in the receive path, before the kernel does any further processing.

## License

With the exception of eBPF code, `xfw` is distributed under the terms of the [MIT license](LICENSE-MIT).

All eBPF code is distributed under the terms of either the [GNU General Public License, Version 2](LICENSE-GPL2) or the [MIT license](LICENSE-MIT).
