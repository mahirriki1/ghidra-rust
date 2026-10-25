# Built-in constant scanner and string decoder

This is an independent FindCrypt-style scanner with a small initial signature
set. No FindCrypt source code or signature database was copied. Numeric constants
were entered from the algorithm specifications below; matching and UI integration
are original implementation work. This does not provide full FindCrypt coverage.

## Signature provenance

- **AES / Rijndael:** first 64 bytes of the forward substitution box (S-box),
  [NIST FIPS 197, updated 2023, Table 4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).
  This byte table has no separate byte-order variant. The prefix is sufficient
  for this initial scan; the remaining 192 bytes are not verified.
- **SHA-224 / SHA-256:** first eight 32-bit round constants from
  [FIPS 180-4, section 4.2.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
  These constants are shared by both algorithms. Only the first 32 bytes of the
  256-byte table are checked.
- **SHA-256:** all eight initial hash words from FIPS 180-4, section 5.3.3.
- **SHA-1:** all five initial hash words from FIPS 180-4, section 5.3.1.
- **MD4 / MD5 / SHA-1 shared IV:** the four initial words in
  [RFC 1321, section 3.3](https://www.rfc-editor.org/rfc/rfc1321#section-3.3),
  [RFC 1320, section 3.3](https://www.rfc-editor.org/rfc/rfc1320#section-3.3),
  and FIPS 180-4, section 5.3.1. These bytes cannot uniquely identify an algorithm;
  the result explicitly says ambiguous. A complete SHA-1 IV can also produce a
  shared-prefix hit at the same address; overlapping evidence is preserved.
- **ChaCha / Salsa family:** the 16-byte sigma constant and the Salsa20 tau
  constant from [Bernstein's Salsa20 specification, section 9](https://cr.yp.to/snuffle/spec.pdf).
  The sigma constant is also specified as four numeric words by
  [RFC 8439, section 2.3](https://www.rfc-editor.org/rfc/rfc8439#section-2.3).
  The constants identify a family rather than a particular variant or round count.

All contiguous numeric-word signatures are scanned in both little-endian and
big-endian word representation. Sigma/tau are scanned both as their ASCII bytes
(equivalent to little-endian storage of the usual numeric words) and as those
numeric words stored big-endian. There are 13 byte signatures; the longest is
64 bytes. Matches are checked at every byte alignment, including overlapping
signatures. The scanner returns bounded results; streaming callers must overlap
chunks by 63 bytes and suppress duplicates. Isolated region boundaries are not bridged.

These are **constant matches**, not confirmation that an algorithm executes,
that a key is present, or that data can be decrypted. Documentation, unused code,
and deliberate decoys may contain the same constants. Conversely, instructions
that synthesize constants, SIMD layouts, transformed tables, and computed tables
will often be missed. No cryptographic recommendation is implied by a match.

## Built-in string decoding

The decoder works on explicitly selected bytes and does not execute target code.
It supports strict UTF-8, explicit little/big-endian UTF-16, hex, standard padded
Base64, and supplied-key single-byte or repeating-key XOR. Malformed Unicode,
odd hex digit counts, noncanonical Base64 padding/trailing bits, and missing XOR
keys produce errors. ASCII whitespace is allowed within hex and Base64 input.
UTF-16 becomes UTF-8, with no replacement characters or implicit endian detection;
the explicit endian selection also governs BOM interpretation. UTF-8 validates
and preserves its bytes. Other transformations produce arbitrary bytes, so an
invalid UTF-8 result must be shown as bytes rather than repaired text.

XOR key entry requires `hex:` or `text:` to avoid ambiguity: `hex:4142` is two
bytes, while `text:4142` is four UTF-8 bytes. [Input, key, and output limits](analysis.md#resource-limits-and-trust-boundaries)
reject oversized data rather than silently truncating it. A wrong XOR key can
produce valid text; no unauthenticated XOR operation can establish correctness.

Suggestions include valid hex/Base64 transformations, evidence-based UTF-16
interpretations, and ranked nonzero single-byte XOR guesses. The ranking is a
simple readability heuristic, with a bias toward ordinary Latin
text; it is not confidence, automatic decryption, or a general language detector.
Only suggested previews are generated. Applying an annotation is a separate user
action, and decoded output does not modify the source binary.
