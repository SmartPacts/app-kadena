# Functional tests

Ragger tests of the device app on the Speculos emulator, for Nano S+, Nano X, Stax, Flex and Apex P. They
drive every command (version, address, JSON, hash and structured-transfer signing, settings) through the
screens, and compare the screens with the snapshots in `snapshots/<device>/<test>/`.

- `conftest.py` — Ragger's fixtures (`--device`, `--golden_run`) and the `kda` fixture.
- `kadena.py` — APDU encoding, the test vectors, signature checks and screen navigation.
- `test_*.py` — the tests, one file per area; `test_review_scope.py` holds the security rules (V9-V26 of
  `docs/APDUSPEC.md`), each refusal checked with its status word and message.

## Run locally

Build the app first (`cargo ledger build <device>` in the repository root, see the top-level README). The
snapshots in this folder were produced in Ledger's dev-tools image pinned by digest in the top-level README:

```bash
python3 -m venv --system-site-packages /tmp/v && . /tmp/v/bin/activate
pip install -r tests/requirements.txt
pytest tests/ --device nanosp          # or nanox, stax, flex, apex_p; --device all for every device
pytest tests/ --device flex -k transfer
```

`--golden_run` writes new snapshots after an intended screen change; review them before committing.

Lint and type check, as CI runs them:

```bash
cd tests && ruff format --check . && ruff check . && mypy .
```

`ruff.toml` (repository root) and `setup.cfg` (`[mypy]`, here) hold the configuration.

## In CI

`.github/workflows/build_and_functional_tests.yml` builds the app with Ledger's builder image and runs this
folder on all five devices through Ledger's reusable Ragger workflow, on its default runner (the workflow
installs `requirements.txt` with pip itself). Started by hand with "golden_run: Open a PR", it regenerates the
snapshots and opens a pull request with them instead of failing. `python_tests_checks.yml` runs the lint and
type check.
