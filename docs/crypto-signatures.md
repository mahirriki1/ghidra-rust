# FindCrypt and byte decoding

**FindCrypt** looks for a small set of standard constants. A hit identifies
bytes matching a signature. Algorithm use, keys, and decryptable data require
separate evidence.

## Signature provenance

The scanner and signature set were built independently. Constants were entered
from these specifications.

| Signature | Bytes checked | Source |
| --- | --- | --- |
| AES forward S-box | First 64 of 256 bytes | [FIPS 197 (2023), Table 4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) |
| SHA-224 / SHA-256 round constants | First eight 32-bit words | [FIPS 180-4, §4.2.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) |
| SHA-256 initial hash | All eight words | [FIPS 180-4, §5.3.3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) |
| SHA-1 initial hash | All five words | [FIPS 180-4, §5.3.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) |
| Shared MD4 / MD5 / SHA-1 initial state | Four words, reported as ambiguous | [RFC 1320, §3.3](https://www.rfc-editor.org/rfc/rfc1320#section-3.3), [RFC 1321, §3.3](https://www.rfc-editor.org/rfc/rfc1321#section-3.3), and [FIPS 180-4, §5.3.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) |
| ChaCha / Salsa | 16-byte sigma and Salsa20 tau | [Salsa20 specification, §9](https://cr.yp.to/snuffle/spec.pdf), [RFC 8439, §2.3](https://www.rfc-editor.org/rfc/rfc8439#section-2.3) |

Word signatures use both little- and big-endian order. Sigma and tau are also
scanned in ASCII form, which represents the little-endian words. The
13 signatures are checked at every byte alignment, including overlaps.
Streaming callers overlap chunks by 63 bytes and suppress duplicates.
Matches stay within each scanned region. Transformed or computed tables can
be missed.

## Built-in string decoding

Select bytes and choose **Decode selection**. Decode supports strict UTF-8,
UTF-16LE/BE, hex, standard padded Base64, and supplied-key XOR. Hex and Base64
allow ASCII whitespace. UTF-16 uses the selected byte order. Invalid
transformed UTF-8 can still be shown as bytes.

For XOR, use `hex:4142` for two key bytes or `text:4142` for four. Suggestions
include valid hex/Base64 and UTF-16 candidates and single-byte XOR guesses
ranked by readability. Preview a result before saving it as an annotation.
Decode reads the selected bytes without modifying the binary.
[Decode limits](analysis.md#resource-limits-and-trust-boundaries)
