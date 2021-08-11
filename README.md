# ztman

Lightweight alternative to [YubiKey Manager CLI](https://developers.yubico.com/yubikey-manager/) for managing [YubiKey PIV application](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html).

## To Do

- Sign macOS binaries, see https://github.com/mitchellh/gon
- Autotests
- Integration with ztca & ztunnel

## Installation

Download from [official releases](https://github.com/feeltheajf/ztman/releases).

### MacOS

No additional packages are required.

### Linux

To build and run on Linux, [PCSC lite](https://pcsclite.apdu.fr) is required. To install on Debian-based distros, run:

```sh
sudo apt-get install libpcsclite-dev
```

On Fedora/CentOS:

```sh
sudo yum install pcsc-lite-devel
```

On FreeBSD:

```sh
sudo pkg install pcsc-lite
```

### Windows

No prerequisites are needed. However, to use YubiKey for mTLS, SSH, etc. you need to install the official [YubiKey Smart Card Minidriver](https://www.yubico.com/support/download/smart-card-drivers-tools/) as it adds [additional smart functionality](https://www.yubico.com/authentication-standards/smart-card/).

## Usage

If launched without additional parameters or by double-click on the binary, ztman will interactively prompt for all required parameters. Alternatively, it can be launched from CLI with `-f/--force` argument along with other necessary parameters for non-interactive session.

Currently proposed usage workflow consists of 4 steps. Slot `9a` is used for demonstration purposes. For more information see [PIV Certificate Slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html).

1. Initial configuration. Reset the PIV application, set new PIN and PUK. Randomly generated management key will be stored on the card, protected by PIN. For more information see [PIV Admin Access](https://developers.yubico.com/PIV/Introduction/Admin_access.html).

```sh
ztman reset --pin $PIN --puk $PUK
```

2. Generate key pair and attestation statements for the given slot. For more information see [PIV Attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html).

```sh
# will generate the following files
#
# piv-attestation-intermediate.crt  intermediate attestation certificate
# piv-attestation.crt               attestation certificate
# piv-ssh.pub                       public key in OpenSSH format
# piv.pub                           public key
# piv.csr                           certificate signing request

ztman attest --pin $PIN --slot 9a
```

3. Request certificate from your CA using CSR and/or attestation statements. For more information see [ztca](https://github.com/feeltheajf/ztca).

4. Import certificate

```sh
ztman import --pin $PIN --slot 9a --cert ~/ztman/9a/piv.crt
```

If you need to configure another slot, repeat steps 2-4 accordingly.

If a certificate has expired, it is safer to follow steps 3-4 without re-generating the key pair, which might cause troubles e.g. in cases when the same slot is used for making SSH connections.

Finally, you can get current status of the PIV application by running

```sh
ztman info
```
