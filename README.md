# noistr

noise protocol cipher suite that uses sha256, BIP-340 style secp256k1 schnorr ECDH and signatures with 32 byte nonces, block counter mode (CTR) using SHA256 for generating the cipher bitstream

## why

because the clouds of NSA backdoor FUD around the NIST p256 curve have not really eventuated and the secp256k1 curve, which is used by Bitcoin, has not been broken, we think it's probably secure

SHA256 is perfectly fine also, though not as fast as Blake2 and Blake3, in this codebase we use a SIMD implementation which performs much faster than a plain Blake hash

AES is old and has been essentially superseded by chacha-poly-20 CSPRNG bitstreams, which are much faster and at least equally secure by all measures

authentication of the encryption is secured by the BIP-340 secp256k1 schnorr signatures, with the public key present to enable verification of the payload hash

## encryption algorithm

noistr uses a simple block cipher algorithm, and a 32 bit size prefix, and no padding

the basic format of a noistr message is as follows:

- 32 byte nonce - because longer nonces provide more security against preimage attacks
- 32 bit (4 byte) length prefix designating the offset to the end of the message bytes
- Message data of length designated by the previous field
- Remainder after this until the last 96 bytes described below is the Additional Data as prescribed in Noise Protocol
- 32 byte BIP-340 pubkey designating the signer of the message, which is a constant during a connection
- 64 byte schnorr signature that validates authenticity on the hash of the raw message bytes

the byte stream that is XORed on the plaintext is generated by a simple stream of chacha-poly-20 hashes, using a counter mode, to enable random seeking (for possible future optimization of on-demand decryption of expected data formats in a possible gossip protocol)

the encryption bitstream is generated by SHA256 hash of the nonce and the shared secret plus an 8 byte 64 bit counter value - each sequential position in the message is an increment of 1 for each 32 byte block

no padding is needed, the recipient knows the message is complete by the size of the message and the 32 bit size prefix - this is a wire encryption, so this cipher suite has a 4 gigabyte size limit, which is more than sufficient for network messages, which are already segmented usually into tiny pieces, most of the time under 1500 bytes

the reason for using counter mode (CTR) is that it enables selective and progressive decryption of the message, in the case of its use in especially flatbuffers style selective decoding - the position in the stream can be generated just from the secret, the initialization vector and the number of the segment

with network packets, they can be punctured so the signature that appears at the end verifies that the same hash was signed on by the public key that appears in the packet...

the noise protocol also adds an "additional data" field in the encryption algorithm, this is not encrypted

the key used to sign messages should be a new one for each connection, so as to not leak metadata

the HMAC does not use the nonce value from the protocol because of the size of the IV