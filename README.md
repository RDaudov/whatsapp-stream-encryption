# WhatsApp Media Encryptor

A PHP library for encrypting and decrypting WhatsApp media files (images, videos, audio, documents) according to WhatsApp's media encryption specification.

## About

This project implements WhatsApp's media encryption algorithm including:
- AES-256-CBC encryption/decryption
- HKDF key derivation
- Sidecar generation for streamable media (VIDEO, AUDIO)
- Full test coverage

## Installation

### Requirements
- PHP 8.1 or higher
- Composer
- OpenSSL extension

### Setup

1. Clone the repository:
```bash
git clone https://github.com/RDaudov/whatsapp-stream-encryption.git
cd whatsapp-stream-encryption
```
Install dependencies: 
``` composer install ```

## Expected output:

..................................                                34 / 34 (100%)

Time: 00:00.105, Memory: 16.00 MB

OK (34 tests, 57 assertions)

Test Instructions

## To verify the project works correctly:

Install dependencies: ``` composer install ```

Run tests: ``` composer test ```

Confirm all 34 tests pass successfully
