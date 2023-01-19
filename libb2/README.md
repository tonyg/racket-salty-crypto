# libb2 bindings for Racket

[`libb2`](https://github.com/BLAKE2/libb2) is a C library offering support for BLAKE2b, BLAKE2s
etc.

This package exposes the BLAKE2 functions along with their parameter values.

The `#:length` parameter defaults in each case to the longest available output for the
hashfunction (...`_OUTBYTES` × 8).

   - `(blake2b` *bytes* [*keybytes*] [`#:length` bits]`)`
   - `(blake2bp` *bytes* [*keybytes*] [`#:length` bits]`)`
   - `BLAKE2B_BLOCKLEN`
   - `BLAKE2B_KEYBYTES`
   - `BLAKE2B_OUTBYTES`

   - `(blake2s` *bytes* [*keybytes*] [`#:length` bits]`)`
   - `(blake2sp` *bytes* [*keybytes*] [`#:length` bits]`)`
   - `BLAKE2S_BLOCKLEN`
   - `BLAKE2S_KEYBYTES`
   - `BLAKE2S_OUTBYTES`
