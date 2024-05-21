# PBA Singapore: Module 1 (encryption) - group assignment 2 (ECB, CBC, CTR)

## Overview

This repository contains implementations of three block cipher modes of operation: Electronic Codebook (ECB), Cipher Block Chaining (CBC), and Counter (CTR). Additionally, we have included utility functions `un_pad` and `un_group`. To ensure the correctness of our implementations, we have added unit tests.

## Implemented Cipher Modes

1. **Electronic Codebook (ECB)**
2. **Cipher Block Chaining (CBC)**
3. **Counter (CTR)**

## Utility Functions

- **un_pad**: Removes padding from the decrypted text.
- **un_group**: Utility function used in conjunction with our cipher modes.

## Unit Tests

We have implemented unit tests to validate the correctness of our cipher modes. The tests check that for a given `plain_text`, applying the decryption function to the ciphered text returns the original `plain_text`. This validation is performed for all three cipher modes (ECB, CBC, CTR).

## Usage

To run the tests, you can use the following command:

```bash
cargo test
```