## Usage Example
```c++
. . .

unsigned char key[crypto_stream_chacha20_KEYBYTES];
unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];

memcpy(key, "\x29\x30\xC0\x05\xE2\x55\x3E\x37\xDC\x69\xC3\x0D\xD4\xD9\x1D\xB5\xCD\xC8\xD4\xA2\x91\x09\x81\x68\x69\x68\x80\x42\x5E\x7E\x5A\xF9", crypto_stream_chacha20_KEYBYTES);
memcpy(nonce, "\x35\xC7\x03\xD5\x5D\x90\xAE\x29", crypto_stream_chacha20_NONCEBYTES);

unsigned char encrypted[sizeof(data)];
crypto_stream_chacha20_xor(encrypted, data, sizeof(data), nonce, key);

unsigned char decrypted[sizeof(encrypted)];
crypto_stream_chacha20_xor(decrypted, encrypted, sizeof(encrypted), nonce, key);

. . .
```
