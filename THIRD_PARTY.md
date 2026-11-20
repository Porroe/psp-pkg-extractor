# Third-party acknowledgements

This project uses format knowledge and implementation inspiration from
[mmozeiko/pkg2zip](https://github.com/mmozeiko/pkg2zip), particularly
`pkg2zip.c` (header/metadata layout, PSP content types, item decoding and key
selection) and `pkg2zip_aes.c` (big-endian CTR semantics).

Upstream's [LICENSE](https://github.com/mmozeiko/pkg2zip/blob/master/LICENSE)
was inspected on 2026-11-19. It dedicates the work to the public domain under
the Unlicense and expressly permits copying, modification, publication, use,
compilation, sale, and redistribution for commercial or noncommercial purposes.
That permits this Python implementation and redistribution. The full upstream
Unlicense is preserved in this project's LICENSE; this project uses that same
license. No upstream license-generation, downloading, NPDRM conversion, or
platform-specific code is included.

The [PS3 Developer Wiki PKG format reference](https://www.psdevwiki.com/ps3/PKG_files)
was consulted for field meanings and extended-header layout. Only format facts
were used; no wiki prose or code was copied. The AES code is an original Python
implementation of FIPS 197. Tests use published FIPS 197 and NIST SP 800-38A
known-answer vectors. No other project's executable implementation was copied.
