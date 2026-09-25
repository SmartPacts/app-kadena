# Ledger Kadena app
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build](https://github.com/SmartPacts/app-kadena/actions/workflows/reusable_build.yml/badge.svg)](https://github.com/SmartPacts/app-kadena/actions/workflows/reusable_build.yml)

This project contains the Kadena app for Ledger Nano S+, Nano X, Flex, Stax, and Apex P.

## About this repository

This is the maintained continuation of the Kadena Ledger app, originally developed by
[Zondax](https://www.zondax.ch) (Apache-2.0 — license and copyright headers preserved). The
upstream repository is no longer maintained, and its last release (v1.2.0) targets Ledger
API_LEVEL 24, which current Nano S+ firmware (OS 1.6.x = API_LEVEL 26) refuses to install.

This continuation (current release: v1.3.0):

- rebuilds the app against the current Ledger SDK (API_LEVEL 26) so it installs on today's
  firmware, for all five supported devices;
- includes memory-safety hardening in the transaction-display renderers and the JSON parser;
- v1.3.0 adds a whole-app security review (not only a diff review) and fixes three memory-safety
  defects it found: a legacy HD-path length overflow, a transfer-template buffer capacity error,
  and a parser item-array out-of-bounds write. There is no APDU / wire-protocol change. Details are
  in [CHANGELOG.md](CHANGELOG.md);
- keeps the full Zemu test matrix green across all five device targets (240 tests in v1.3.0);
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
not the checksum of the download, is what proves which binary your device is running. For v1.3.0
on the Nano S+ (target `nanos2`) the expected hash is:

```
068f376be6115e1769952fabb61020ae5070867c9b2299c259f6947c5b5ce1db
```

Kadena is currently not offered in Ledger's My Ledger catalog (as of September 2026). So on the
Nano S+ the app is installed by sideloading, as described above. Nano X, Stax, Flex and Nano Gen5
have no sideloading path; the app stays unavailable on them until it is listed.

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

Builds use Ledger's official builder image, the same image the CI build job and the releases use.
Inside the container, build one target at a time by pointing `BOLOS_SDK` at the SDK the image
ships for that device:

```bash
docker run --rm -it -v "$(pwd):/app" -w /app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest bash
# then, inside the container:
make -C app -j BOLOS_SDK=$NANOSP_SDK    # Nano S Plus  -> app/build/nanos2/bin/app.elf
make -C app -j BOLOS_SDK=$NANOX_SDK     # Nano X       -> app/build/nanox/bin/app.elf
make -C app -j BOLOS_SDK=$STAX_SDK      # Stax         -> app/build/stax/bin/app.elf
make -C app -j BOLOS_SDK=$FLEX_SDK      # Flex         -> app/build/flex/bin/app.elf
make -C app -j BOLOS_SDK=$APEX_P_SDK    # Nano Gen5    -> app/build/apex_p/bin/app.elf
```

`PRODUCTION_BUILD` defaults to 1. The repository's top-level `make` targets from the Zondax
tooling point at an older builder image and are not used for releases or CI.

## Running tests

- C/C++ unit tests (host build):

    ```bash
    make cpp_test
    ```

- Functional tests on the Speculos emulator, through Zemu, for all five device models:

    ```bash
    # 1. place the five ELFs where the suite expects them
    mkdir -p app/output
    cp app/build/nanos2/bin/app.elf  app/output/app_s2.elf
    cp app/build/nanox/bin/app.elf   app/output/app_x.elf
    cp app/build/stax/bin/app.elf    app/output/app_stax.elf
    cp app/build/flex/bin/app.elf    app/output/app_flex.elf
    cp app/build/apex_p/bin/app.elf  app/output/app_apex_p.elf
    # 2. install and run (Docker must be running; Zemu pulls the Speculos image)
    cd tests_zemu
    yarn install --frozen-lockfile
    yarn test
    ```

    The suite is 4 files, 240 tests (5 models). CI runs exactly these steps on every push as the
    `Functional tests (Zemu, five device models)` job in `.github/workflows/reusable_build.yml`,
    against the binaries produced by Ledger's reusable build job in the same run. Failing
    snapshots are uploaded as the `snapshots-tmp` artifact.

    To run a single file: `yarn jest tests/standard.test.ts`.

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
