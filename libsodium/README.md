# libsodium bindings for Racket

[`libsodium`](https://libsodium.org/) is a mature and well-supported library originally built
around [NaCl](http://nacl.cr.yp.to/).

This package offers core support for the default algorithms chosed by `NaCl`/`libsodium`. It
could also readily be extended with support for the other algorithms included in `libsodium`.

 - `aead.rkt`:
   - `crypto_aead_`...`_KEYBYTES`
   - `crypto_aead_`...`_NPUBBYTES`
   - `crypto_aead_`...`_ABYTES`
   - `(crypto-aead-`...`-keygen)`
   - `(crypto-aead-`...`-encrypt` *plaintext associated-data nonce key*`)`
   - `(crypto-aead-`...`-decrypt` *ciphertext associated-data nonce key*`)`

 - `auth.rkt`:
   - `crypto_auth_BYTES`
   - `crypto_auth_KEYBYTES`
   - `crypto_auth_PRIMITIVE` (= `"hmacsha512256"`)
   - `(crypto-auth` *plaintext key*`)`
   - `(crypto-auth-verify` *authenticator plaintext key*`)`

 - `box.rkt`:
   - `crypto_box_SEEDBYTES`
   - `crypto_box_PUBLICKEYBYTES`
   - `crypto_box_SECRETKEYBYTES`
   - `crypto_box_NONCEBYTES`
   - `crypto_box_MACBYTES`
   - `crypto_box_MESSAGEBYTES_MAX`
   - `crypto_box_PRIMITIVE` (= `"curve25519xsalsa20poly1305"`)
   - `crypto_box_BEFORENMBYTES`

   - `(crypto-box-keypair` *pk sk*`)`
   - `(crypto-box-keypair?` *any*`)`
   - `(crypto-box-keypair-pk` *kp*`)`
   - `(crypto-box-keypair-sk` *kp*`)`
   - `(make-crypto-box-keypair)`
   - `(seed->crypto-box-keypair` *seed*`)`
   - `(bytes->crypto-box-keypair` *bytes*`)`
   - `(sk->crypto-box-keypair` *sk*`)`
   - `(crypto-box-random-nonce)`
   - `(crypto-box` *plaintext nonce pk sk*`)`
   - `(crypto-box-open` *ciphertext nonce pk sk*`)`

   - `(crypto-box-state?` *any*`)`
   - `(crypto-box-precompute` *pk sk*`)`
   - `(crypto-box*` *plaintext nonce state*`)`
   - `(crypto-box-open*` *ciphertext nonce state*`)`

 - `hash.rkt`:
   - `crypto_hash_BYTES`
   - `crypto_hash_PRIMITIVE` (= `"sha512"`)
   - `(crypto-hash` *bytes*`)`

 - `onetimeauth.rkt`:
   - `crypto_onetimeauth_BYTES`
   - `crypto_onetimeauth_KEYBYTES`
   - `crypto_onetimeauth_PRIMITIVE` (= `"poly1305"`)

   - `(crypto-onetimeauth` *msg key*`)`
   - `(crypto-onetimeauth-verify` *authenticator msg key*`)`

 - `random.rkt`:
   - `(random-bytes` *count*`)`

 - `scalarmult.rkt`:
   - `crypto_scalarmult_BYTES`
   - `crypto_scalarmult_SCALARBYTES`
   - `crypto_scalarmult_PRIMITIVE` (= `"curve25519"`)

   - `(crypto-scalarmult-base` *scalar-bytes*`)`
   - `(crypto-scalarmult` *scalar-bytes* *point-bytes*`)`

 - `secretbox.rkt`:
   - `crypto_secretbox_KEYBYTES`
   - `crypto_secretbox_NONCEBYTES`
   - `crypto_secretbox_MACBYTES`
   - `crypto_secretbox_MESSAGEBYTES_MAX`
   - `crypto_secretbox_PRIMITIVE` (= `"xsalsa20poly1305"`)

   - `(crypto-secretbox-random-nonce)`
   - `(crypto-secretbox-keygen)`
   - `(crypto-secretbox` *plaintext nonce key*`)`
   - `(crypto-secretbox-open` *ciphertext nonce key*`)`

 - `sign.rkt`:
   - `crypto_sign_BYTES`
   - `crypto_sign_SEEDBYTES`
   - `crypto_sign_PUBLICKEYBYTES`
   - `crypto_sign_SECRETKEYBYTES`
   - `crypto_sign_MESSAGEBYTES_MAX`
   - `crypto_sign_PRIMITIVE` (= `"ed25519"`)

   - `(crypto-sign-keypair pk sk)`
   - `(crypto-sign-keypair?` *any*`)`
   - `(crypto-sign-keypair-pk` *kp*`)`
   - `(crypto-sign-keypair-sk` *kp*`)`
   - `(make-crypto-sign-keypair)`
   - `(seed->crypto-sign-keypair` *seed*`)`
   - `(bytes->crypto-sign-keypair` *bytes*`)`
   - `(crypto-sign` *msg sk*`)`
   - `(crypto-sign-open` *signed-msg pk*`)`

 - `stream.rkt`":
   - `crypto_stream_NONCEBYTES`
   - `crypto_stream_KEYBYTES`
   - `crypto_stream_PRIMITIVE` (= `"xsalsa20"`)

   - `(crypto-stream-random-nonce)`
   - `(crypto-stream-keygen)`
   - `(crypto-stream!` *bytes nonce key*`)`
   - `(crypto-stream` *length nonce key*`)`
   - `(crypto-stream-xor!` *bytes plaintext nonce key*`)`
   - `(crypto-stream-xor` *plaintext nonce key*`)`
