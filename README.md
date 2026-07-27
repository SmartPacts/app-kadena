# Ledger Kadena app
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build](https://github.com/SmartPacts/app-kadena/actions/workflows/reusable_build.yml/badge.svg)](https://github.com/SmartPacts/app-kadena/actions/workflows/reusable_build.yml)

This project contains the Kadena app for Ledger Nano S+, Nano X, Flex, Stax, and Apex P.

## About this repository

This is the maintained continuation of the Kadena Ledger app, originally developed by
[Zondax](https://www.zondax.ch) (Apache-2.0 — license and copyright headers preserved). The
upstream repository is no longer maintained, and its last release (v1.2.0) targets Ledger
API_LEVEL 24, which current Nano S+ firmware (OS 1.6.x = API_LEVEL 26) refuses to install.

This continuation (v1.2.1):

- rebuilds the app against the current Ledger SDK (API_LEVEL 26) so it installs on today's
  firmware, for all five supported devices;
- includes memory-safety hardening in the transaction-display renderers and the JSON parser;
- keeps the full Zemu test matrix green across all five device targets;
- is maintained by [Smart Pacts](https://smartpacts.io), with the goal of returning the app to
  official availability through the Ledger app store.

- Ledger Nano S+/X, Flex, Stax, and Apex P Kadena app
- Specs / Documentation
- C++ unit tests
- Zemu tests

## ATTENTION

Please:

- **Do not use in production**
- **Do not use a Ledger device with funds for development purposes.**
- **Have a separate and marked device that is used ONLY for development and testing**


## Installing the app

*Once the app is approved by Ledger, it will be available in their app store (Ledger Live).*

Until then, **Nano S+ owners** can install a release build. If you are not a developer, use the
guided installer and its documentation rather than the commands below:

**https://smartpacts.io/ledger/**

Developers can load a release directly. Download `installer_nanos_plus.sh` from the
[release page](https://github.com/SmartPacts/app-kadena/releases), verify it against
`SHA256SUMS.txt`, and run:

```sh
chmod +x ./installer_nanos_plus.sh
./installer_nanos_plus.sh load
```

This requires Python 3 with `ledgerblue` installed. **Verify the application hash your device
displays during installation against the value published in the release notes** — that comparison,
not the checksum of the download, is what proves which binary your device is running.

Sideloading is possible on the Nano S+ only. Nano X, Stax, Flex and Gen 5 have no such path; those
devices need the app to be listed in Ledger Live.

## Troubleshooting / Support
If you encounter any issues while using the app, please open an issue in this repository and the
maintainers will review it. Installation problems are better reported to the
[installer repository](https://github.com/SmartPacts/kadena-ledger-installer/issues).


# Development

## Preconditions

- Be sure you checkout submodules too:

    ```
    git submodule update --init --recursive
    ```

- Install Docker CE
    - Instructions can be found here: https://docs.docker.com/install/

- We only officially support Ubuntu. Install the following packages:
   ```
   sudo apt update && apt-get -y install build-essential git wget cmake \
  libssl-dev libgmp-dev autoconf libtool
   ```

- Install `node > v13.0`. We typically recommend using `n`

- You will need python 3 and then run
    - `make deps`

- This project requires latest Ledger firmware

*Warning*: Some IDEs may not use the same python interpreter or virtual environment as the one you used when running `pip`.
If you see conan is not found, check that you installed the package in the same interpreter as the one that launches `cmake`.

## How to build ?

> We like clion or vscode but let's have some reproducible command line steps
>

- Building the app itself

    If you installed what is described above, just run:
    ```bash
    make
    ```

## Running tests

- Running rust tests (x64)

    If you installed the what is described above, just run:
    ```bash
    make rust_test
    ```

- Running C/C++ tests (x64)

    If you installed the what is described above, just run:
    ```bash
    make cpp_test
    ```

- Running device emulation+integration tests!!

   ```bash
    Use Zemu! Explained below!
    ```

## How to test with Zemu?

> What is Zemu?? Great you asked!!
> As part of this project, we are making public a beta version of our internal testing+emulation framework for Ledger apps.
>
> Npm Package here: https://www.npmjs.com/package/@zondax/zemu
>
> Repo here: https://github.com/Zondax/zemu

Let's go! First install everything:
> At this moment, if you change the app you will need to run `make` before running the test again.

```bash
make zemu_install
```

Then you can run JS tests:

```bash
make zemu_test
```

To run a single specific test:

> At the moment, the recommendation is to run from the IDE. Remember to run `make` if you change the app.

## Quick running
To build the application and run Zemu tests for all devices, we provide a shortcut.

```bash
make test_all
```

This command will build the application for every device with `PRODUCTION_BUILD=1`, install all the JS dependencies, and finally run all the integration tests available in the project.

## Using a real device

### How to prepare your DEVELOPMENT! device:

>  You can use an emulated device for development. This is only required if you are using a physical device
>
>    **Please do not use a Ledger device with funds for development purposes.**
>>
>    **Have a separate and marked device that is used ONLY for development and testing**

   There are a few additional steps that increase reproducibility and simplify development:

**1 - Ensure your device works in your OS**
- In Linux hosts it might be necessary to adjust udev rules, etc.

  Refer to Ledger documentation: https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues

**2 - Set a test mnemonic**

Many of our integration tests expect the device to be configured with a known test mnemonic.

- Plug your device while pressing the right button

- Your device will show "Recovery" in the screen

- Double click

- Run `make dev_init`. This will take about 2 minutes. The device will be initialized to:

   ```
   PIN: 5555
   Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young
   ```

**3 - Add a development certificate**

- Plug your device while pressing the right button

- Your device will show "Recovery" in the screen

- Click both buttons at the same time

- Enter your pin if necessary

- Run `make dev_ca`. The device will receive a development certificate to avoid constant manual confirmations.


### Loading into your development device

The Makefile will build the firmware in a docker container and leave the binary in the correct directory.

- Build

   ```
   make                # Builds the app
   ```

- Upload to a device
   The following command will upload the application to the ledger. _Warning: The application will be deleted before uploading._
   ```
   make load          # Builds and loads the app to the device
   ```

## APDU Specifications

- [APDU Protocol](docs/APDUSPEC.md)
