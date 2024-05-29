# Vault 1.0.0

> NOTE: This project is in BETA. It has not been security audited and may contain bugs or vulnerabilities. 

Vault is a CLI tool for securely encrypting and decrypting sensitive text data (such as passwords, crypto keys, recovery phrases and backup codes). It is intended for protecting this data while in long-term storage.

The tool utilises Shamir's Secret Sharing algorithm to split a 4096-bit RSA Private key into multiple 'shares'. 
These shares can be distributed and stored offline in multiple safe locations, eg. safety deposit boxes, or shared with multiple trusted people.
To decrypt data from the vault, a minimum number of shares (threshold) must be retrieved and recombined.

The vault's corresponding RSA Public key is used to encrypt data. This key can remain public, making it easy to add new data to the vault, with no need to retrieve or update any shares.

Data added to the vault is encrypted using a hybrid AES-RSA system:
1. The data is first encrypted using a random 256-bit AES symmetric key
2. A copy of this AES key is encrypted using the vault's RSA public key
3. The AES-encrypted data and RSA-encrypted AES key are packaged and stored together
4. Decrypting the data will require the vault's RSA private key, which requires access to the threshold number of shares

*Note - While this refers to 'data in the vault', the Vault CLI tool does not store any data. It simply provides the functions to generate keys, encrypt and decrypt.*
*It is the user's responsibility to properly store and back-up the private key shares, public key, and any encrypted data*

### Vault CLI features
**Create new vault** - Creates a new vault with the desired number of shares and threshold. Will return a list of private key shares, and the vault's public RSA key.

**Encrypt data** - Encrypts text data using the supplied vault's RSA public key.

**Decrypt data** - Decrypts data using multiple (at least the threshold number of) private key shares

## Usage

### Compiled executables
Compiled executables for Mac OS Intel (x64), Mac OS Silicon (ARM), Linux (x64) and Windows (x64) are availble in the `/compiled` folder.
No installation or dependencies required.

### Compile from source
Run the script `compile.sh` to compile from source. Requires [Deno](https://deno.land)

### Run JIT
`deno run src/app.ts`. Requires [Deno](https://deno.land)

## Unit tests

Run unit tests
`deno test src/tests.ts` Requires [Deno](https://deno.land)


