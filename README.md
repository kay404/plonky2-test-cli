# Plonky2 test client

use rust nightly tool chain

## run ecdsa

```sh
cargo +nightly run -r -- -e
```

## run keccak

```sh
cargo +nightly run -r -- -k
```

## run ecdsa with keccak hash message

```sh
cargo +nightly run -r -- -m
```

## rum ecdsa

```sh
cargo +nightly run -r -- --msg MSG_IN_HEX  --pk PUBLIC_KEY_IN_HEX  --sig SIGNATURE_IN_HEX
```
