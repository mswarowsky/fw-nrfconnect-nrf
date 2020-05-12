""""""""""""""""""""""""""""""""""
Coverage of low level crypto tests
""""""""""""""""""""""""""""""""""
This provides a summery of the the low level crypto test function coverage.
The list of functions is taken from mbedtls: https://github.com/ARMmbed/mbedtls/tree/development/include/mbedtls

.. contents:: Overview
   :depth: 2

====================
Crypto hardware list
====================
This is a list which CryptoCell version is used in which board

+------------------+--------------+
|**Board**         |**CryptoCell**|
+------------------+--------------+
|nRF9160           | 310          |
+------------------+--------------+
|nRF5340           | 312          |
+------------------+--------------+
|nRF52840          | 310          |
+------------------+--------------+
|nRF52833          | ---          |
+------------------+--------------+
|nRF52832          | ---          |
+------------------+--------------+
|nRF52820          | ---          |
+------------------+--------------+
|nRF52811          | ---          |
+------------------+--------------+
|nRF52810          | ---          |
+------------------+--------------+

===================================
Symmetric encryption
===================================

---------------------
Unauthenticated modes
---------------------


.. csv-table::
    :header: "Number", "Algorithm", "Key size", "Block Mode" , "Covered", "Test case", Hardware,  Description
    :widths: 10 20 10 10 10 20 10 80

    1/50,AES                ,128    ,ECB    ,YES    , test_aes_ecb  , 310/312   ,AES cipher with 128-bit ECB mode.
    2/50,AES                ,192    ,ECB    ,YES    , test_aes_ecb  , 312       ,AES cipher with 192-bit ECB mode.
    3/50,AES                ,256    ,ECB    ,YES    , test_aes_ecb  , 312       ,AES cipher with 256-bit ECB mode.
    4/50,AES                ,128    ,CBC    ,YES    , test_aes_cbc  , 310/312   ,AES cipher with 128-bit CBC mode.
    5/50,AES                ,192    ,CBC    ,YES    , test_aes_cbc  , 312       ,AES cipher with 192-bit CBC mode.
    6/50,AES                ,256    ,CBC    ,YES    , test_aes_cbc  , 312       ,AES cipher with 256-bit CBC mode.
    7/50,AES                ,128    ,CFB128 ,**NO** ,               , 310/312   ,AES cipher with 128-bit CFB128 mode.
    8/50,AES                ,192    ,CFB128 ,**NO** ,               , 312       ,AES cipher with 192-bit CFB128 mode.
    9/50,AES                ,256    ,CFB128 ,**NO** ,               , 312       ,AES cipher with 256-bit CFB128 mode.
    10/50,AES               ,128    ,CTR    ,YES    , test_aes_ctr  , 310/312   ,AES cipher with 128-bit CTR mode.
    11/50,AES               ,192    ,CTR    ,YES    , test_aes_ctr  , 312       ,AES cipher with 192-bit CTR mode.
    12/50,AES               ,256    ,CTR    ,YES    , test_aes_ctr  , 312       ,AES cipher with 256-bit CTR mode.
    13/50,AES               ,128    ,OFB    ,**NO** ,               , 310/312   ,AES 128-bit cipher in OFB mode.
    14/50,AES               ,192    ,OFB    ,**NO** ,               , 312       ,AES 192-bit cipher in OFB mode.
    15/50,AES               ,256    ,OFB    ,**NO** ,               , 312       ,AES 256-bit cipher in OFB mode.
    16/50,AES               ,128    ,XTS    ,**NO** ,               ,           ,AES 128-bit cipher in XTS block mode.
    17/50,AES               ,256    ,XTS    ,**NO** ,               ,           ,AES 256-bit cipher in XTS block mode.
    18/50,CHACHA20          ,       ,       ,**NO** ,               , 310/312   ,ChaCha20 stream cipher.
    19/50,CHACHA20-POLY1305 ,128    ,ENC    ,**NO** ,               , 310/312   ,ChaCha20-Poly1305 only encrypt mode cipher.
    20/50,CHACHA20-POLY1305 ,256    ,ENC    ,**NO** ,               , 310/312   ,ChaCha20-Poly1305 only encrypt mode cipher.
    21/50,CAMELLIA          ,128    ,ECB    ,**NO** ,               ,           ,Camellia cipher with 128-bit ECB mode.
    22/50,CAMELLIA          ,192    ,ECB    ,**NO** ,               ,           ,Camellia cipher with 192-bit ECB mode.
    23/50,CAMELLIA          ,256    ,ECB    ,**NO** ,               ,           ,Camellia cipher with 256-bit ECB mode.
    24/50,CAMELLIA          ,128    ,CBC    ,**NO** ,               ,           ,Camellia cipher with 128-bit CBC mode.
    25/50,CAMELLIA          ,192    ,CBC    ,**NO** ,               ,           ,Camellia cipher with 192-bit CBC mode.
    26/50,CAMELLIA          ,256    ,CBC    ,**NO** ,               ,           ,Camellia cipher with 256-bit CBC mode.
    27/50,CAMELLIA          ,128    ,CFB128 ,**NO** ,               ,           ,Camellia cipher with 128-bit CFB128 mode.
    28/50,CAMELLIA          ,192    ,CFB128 ,**NO** ,               ,           ,Camellia cipher with 192-bit CFB128 mode.
    29/50,CAMELLIA          ,256    ,CFB128 ,**NO** ,               ,           ,Camellia cipher with 256-bit CFB128 mode.
    30/50,CAMELLIA          ,128    ,CTR    ,**NO** ,               ,           ,Camellia cipher with 128-bit CTR mode.
    31/50,CAMELLIA          ,192    ,CTR    ,**NO** ,               ,           ,Camellia cipher with 192-bit CTR mode.
    32/50,CAMELLIA          ,256    ,CTR    ,**NO** ,               ,           ,Camellia cipher with 256-bit CTR mode.
    33/50,BLOWFISH          ,32-448 ,ECB    ,**NO** ,               ,           ,Blowfish cipher with ECB mode.
    34/50,BLOWFISH          ,32-448 ,CBC    ,**NO** ,               ,           ,Blowfish cipher with CBC mode.
    35/50,BLOWFISH          ,32-448 ,CFB64  ,**NO** ,               ,           ,Blowfish cipher with CFB64 mode.
    36/50,BLOWFISH          ,32-448 ,CTR    ,**NO** ,               ,           ,Blowfish cipher with CTR mode.
    37/50,ARIA              ,128    ,ECB    ,**NO** ,               ,           ,Aria cipher with 128-bit key and ECB mode.
    38/50,ARIA              ,192    ,ECB    ,**NO** ,               ,           ,Aria cipher with 192-bit key and ECB mode.
    39/50,ARIA              ,256    ,ECB    ,**NO** ,               ,           ,Aria cipher with 256-bit key and ECB mode.
    40/50,ARIA              ,128    ,CBC    ,**NO** ,               ,           ,Aria cipher with 128-bit key and CBC mode.
    41/50,ARIA              ,192    ,CBC    ,**NO** ,               ,           ,Aria cipher with 192-bit key and CBC mode.
    42/50,ARIA              ,256    ,CBC    ,**NO** ,               ,           ,Aria cipher with 256-bit key and CBC mode.
    43/50,ARIA              ,128    ,CFB128 ,**NO** ,               ,           ,Aria cipher with 128-bit key and CFB-128 mode.
    44/50,ARIA              ,192    ,CFB128 ,**NO** ,               ,           ,Aria cipher with 192-bit key and CFB-128 mode.
    45/50,ARIA              ,256    ,CFB128 ,**NO** ,               ,           ,Aria cipher with 256-bit key and CFB-128 mode.
    46/50,ARIA              ,128    ,CTR    ,**NO** ,               ,           ,Aria cipher with 128-bit key and CTR mode.
    47/50,ARIA              ,192    ,CTR    ,**NO** ,               ,           ,Aria cipher with 192-bit key and CTR mode.
    48/50,ARIA              ,256    ,CTR    ,**NO** ,               ,           ,Aria cipher with 256-bit key and CTR mode.
    49/50,XTEA              ,128    ,ECB    ,**NO** ,               ,           ,XTEA block cipher (32-bit) in ECB mode
    50/50,XTEA              ,128    ,CBC    ,**NO** ,               ,           ,XTEA block cipher (32-bit) in CBC mode
         ,**Covered total:**, , ,  **9/50**,

--------------------------
Authenticated modes (AEAD)
--------------------------
.. csv-table::
    :header: "Number", "Algorithm", "Key size", "Block Mode" , "Covered", "Test case", "Hardware", Description
    :widths: 10 20 10 10 10 20 10 80

    1/20,AES                ,128    ,GCM    ,YES    ,test_aead_gcm          ,           ,AES cipher with 128-bit GCM mode.
    2/20,AES                ,192    ,GCM    ,YES    ,test_aead_gcm          ,           ,AES cipher with 192-bit GCM mode.
    3/20,AES                ,256    ,GCM    ,YES    ,test_aead_gcm          ,           ,AES cipher with 256-bit GCM mode.
    4/20,AES                ,128    ,CCM    ,YES    ,test_aead_ccm          ,310/312    ,AES cipher with 128-bit CCM mode.
    5/20,AES                ,192    ,CCM    ,YES    ,test_aead_ccm          ,310/312    ,AES cipher with 192-bit CCM mode.
    6/20,AES                ,256    ,CCM    ,YES    ,test_aead_ccm          ,310/312    ,AES cipher with 256-bit CCM mode.
    7/20,CHACHA20-POLY1305 ,128    ,       ,YES    ,test_aead_chachapoly   ,310/312    ,ChaCha20-Poly1305 AEAD cipher.
    8/20,CHACHA20-POLY1305 ,256    ,       ,YES    ,test_aead_chachapoly   ,310/312    ,ChaCha20-Poly1305 AEAD cipher.
    9/20,CAMELLIA           ,128    ,GCM    ,**NO** ,                       ,           ,Camellia cipher with 128-bit GCM mode.
    10/20,CAMELLIA           ,192    ,GCM    ,**NO** ,                       ,           ,Camellia cipher with 192-bit GCM mode.
    11/20,CAMELLIA           ,256    ,GCM    ,**NO** ,                       ,           ,Camellia cipher with 256-bit GCM mode.
    12/20,CAMELLIA          ,128    ,CCM    ,**NO** ,                       ,           ,Camellia cipher with 128-bit CCM mode.
    13/20,CAMELLIA          ,192    ,CCM    ,**NO** ,                       ,           ,Camellia cipher with 192-bit CCM mode.
    14/20,CAMELLIA          ,256    ,CCM    ,**NO** ,                       ,           ,Camellia cipher with 256-bit CCM mode.
    15/20,ARIA              ,128    ,GCM    ,**NO** ,                       ,           ,Aria cipher with 128-bit key and GCM mode.
    16/20,ARIA              ,192    ,GCM    ,**NO** ,                       ,           ,Aria cipher with 192-bit key and GCM mode.
    17/20,ARIA              ,256    ,GCM    ,**NO** ,                       ,           ,Aria cipher with 256-bit key and GCM mode.
    18/20,ARIA              ,128    ,CCM    ,**NO** ,                       ,           ,Aria cipher with 128-bit key and CCM mode.
    19/20,ARIA              ,192    ,CCM    ,**NO** ,                       ,           ,Aria cipher with 192-bit key and CCM mode.
    20/20,ARIA              ,256    ,CCM    ,**NO** ,                       ,           ,Aria cipher with 256-bit key and CCM mode.
         ,**Covered total:**, , ,  **8/20**,





==============
Hash functions
==============
.. csv-table::
    :header: "Number", "Algorithm", "Covered", "Test case", "Hardware", "Description"
    :widths: 10 30 20 20 10 80

    1/5,SHA224      ,YES    , test_sha224   , 310/312   ,The SHA-224 message digest.
    2/5,SHA256      ,YES    , test_sha256   , 310/312   ,The SHA-256 message digest.
    3/5,SHA384      ,YES    , test_sha384   ,           ,The SHA-384 message digest.
    4/5,SHA512      ,YES    , test_sha512   ,           ,The SHA-512 message digest.
    5/5,RIPEMD160   ,YES    , test_ripemd160,           ,The RIPEMD-160 message digest
        ,**Covered total:** ,  **5/5**,

=======
Entropy
=======
.. csv-table::
    :header: "Number", "Algorithm", "Option", "Covered", "Test case", Hardware, "Description"
    :widths: 10 30 40 10 20 10 80

    1/7,CTR_DRBG            ,AES_256    ,**NO** ,           ,310/312    ,PRNG from AES_256 (default)
    2/7,CTR_DRBG            ,AES_128    ,**NO** ,           ,310/312    ,PRNG from AES_128
    3/7,Entropy Accumaltor  ,           ,**NO** ,           ,           ,Retrieve entropy from the accumulator
    4/7,Platform Entropy    ,           ,**NO** ,           ,           ,Entropy poll callback that provides 0 entropy (platform_entropy_poll).
    5/7,HAVEGE              ,           ,**NO** ,           ,           ,Hardware Volatile Entropy Gathering and Expansion
    6/7,HKDF                ,hkdf       ,YES    ,test_hkdf  ,           ,This is the HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
    7/7,HMAC_DRBR           ,           ,**NO** ,           ,           ,PRNG from HMAC (NIST SP 800-90A)
        ,, **Covered total:** ,  **1/7**,

==================================
Message Authentication Codes
==================================
.. csv-table::
    :header: "Number", "Algorithm", "Option", "Covered", "Test case", "Hardware", "Description"
    :widths: 10 20 30 10 20 10 80

    1/12,CMAC       ,AES_128_ECB    ,YES    , test_aes_ecb_mac   ,310/312 ,Cipher-based – MAC with AES 128 bit-ECB
    2/12,CMAC       ,AES_192_ECB    ,YES    , test_aes_ecb_mac   ,312     ,Cipher-based – MAC with AES 192 bit-ECB
    3/12,CMAC       ,AES_256_ECB    ,YES    , test_aes_ecb_mac   ,312     ,Cipher-based – MAC with AES 256 bit-ECB
    4/12,CMAC       ,AES_128_CBC    ,YES    , test_aes_cbc_mac   ,310/312 ,Cipher-based – MAC with AES 128 bit-CBC
    5/12,CMAC       ,AES_192_CBC    ,YES    , test_aes_cbc_mac   ,312     ,Cipher-based – MAC with AES 192 bit-CBC
    6/12,CMAC       ,AES_256_CBC    ,YES    , test_aes_cbc_mac   ,312     ,Cipher-based – MAC with AES 256 bit-CBC
    7/12,Poly1305   ,               ,**NO** ,                    ,310/312 ,Poly1305  one-time message authenticator (Poly1305-AES)
    8/12,HMAC      ,SHA224         ,**NO** ,                    ,310/312 ,Hash-based – MAC with SHA224
    9/12,HMAC      ,SHA256         ,YES    , test_hmac          ,310/312 ,Hash-based – MAC with SHA256
    10/12,HMAC      ,SHA384         ,**NO** ,                    ,        ,Hash-based – MAC with SHA384
    11/12,HMAC      ,SHA512         ,YES    , test_hmac          ,        ,Hash-based – MAC with SHA512
    12/12,HMAC      ,RIPEMD160      ,**NO** ,                    ,        ,Hash-based – MAC with RIPEMD160
         ,     , **Covered total:** ,**8/12**,

====================================
Asymmetric encryption / Key Exchange
====================================
.. csv-table::
    :header: "Number", "Algorithm", "Option", "Covered", "Test case", Hardware, "Description"
    :widths: 10 30 30 10 20 10 80


    1/9,ECDH        ,       ,YES    ,test_ecdh      ,310/312    ,Elliptic Curve-DH KE
    2/9,J-PAKE      ,       ,YES    ,test_ecjpake   ,           ,Elliptic curve J-PAKE
    3/9,RSAES       ,       ,**NO** ,               ,310/312    ,RSA Encryption with padding according to #PKCS1
    4/9,RSAES-PKCS1 , 2048  ,**NO** ,               ,310/312    ,RSA Encryption with padding according to #PKCS1 v1.5
    5/9,RSAES-PKCS1 , 3072  ,**NO** ,               ,312        ,RSA Encryption with padding according to #PKCS1 v1.5
    6/9,RSAES-PKCS1 , 4096  ,**NO** ,               ,           ,RSA Encryption with padding according to #PKCS1 v1.5
    7/9,RSAES-OAEP  , 2048  ,**NO** ,               ,310/312    ,RSA Encryption with padding according to #PKCS1 v2.1
    8/9,RSAES-OAEP  , 3072  ,**NO** ,               ,312        ,RSA Encryption with padding according to #PKCS1 v2.1
    9/9,RSAES-OAEP  , 4096  ,**NO** ,               ,           ,RSA Encryption with padding according to #PKCS1 v2.1

        , **Covered total:** , ,  **2/9**,

==================
Digital signatures
==================
.. csv-table::
    :header: "Number", "Algorithm", "Option", "Covered", "Test case", Hardware, "Description"
    :widths: 10 30 30 10 20 10 80

    1/8,ECDSA           ,       ,YES   , test_ecdsa_random / test_ecdsa_sign / test_ecdsa_verify ,310/312,Elliptic Curve Digital Signature
    2/8,RSASSA          ,       ,**NO**,    ,           ,RSA based Digital Signature
    3/8,RSASSA-PKCS1    , 2048  ,**NO**,    ,310/312    ,RSA based Digital Signature according to #PKCS1 v1.5
    4/8,RSASSA-PKCS1    , 3072  ,**NO**,    ,312        ,RSA based Digital Signature according to #PKCS1 v1.5
    5/8,RSASSA-PKCS1    , 4096  ,**NO**,    ,           ,RSA based Digital Signature according to #PKCS1 v1.5
    6/8,RSASSA-PSS      , 2048  ,**NO**,    ,310/312    ,RSA based Digital Signature according to #PKCS1 v2.1
    7/8,RSASSA-PSS      , 3072  ,**NO**,    ,312        ,RSA based Digital Signature according to #PKCS1 v2.1
    8/8,RSASSA-PSS      , 4096  ,**NO**,    ,           ,RSA based Digital Signature according to #PKCS1 v2.1
        , **Covered total:** , ,  **1/8**,

==================
Deprecated
==================
These algorithms are still supported but they are not recommended anymore for use. As the might be insecure.

.. csv-table::
    :header: "Number", "Algorithm", "Option", "Covered", "Test case", Hardware, "Description"
    :widths: 10 30 30 10 20 10 80

    1/19,DES           ,ECB    ,**NO**,        ,           ,DES cipher with ECB mode.
    2/19,DES           ,CBC    ,**NO**,        ,           ,DES cipher with CBC mode.
    3/19,DES_EDE       ,ECB    ,**NO**,        ,           ,DES cipher with EDE ECB mode.
    4/19,DES_EDE       ,CBC    ,**NO**,        ,           ,DES cipher with EDE CBC mode.
    5/19,DES_EDE3      ,ECB    ,**NO**,        ,           ,DES cipher with EDE3 ECB mode.
    6/19,DES_EDE3      ,CBC    ,**NO**,        ,           ,DES cipher with EDE3 CBC mode.
    7/19,ARC4          ,128    ,**NO**,        ,           ,RC4 cipher with 128-bit mode.
    8/19,MD2             ,       ,**NO**,        ,           ,The MD2 message digest.
    9/19,MD4             ,       ,**NO**,        ,           ,The MD4 message digest.
    10/19,MD5             ,       ,**NO**,        ,           ,The MD5 message digest.
    11/19,SHA1            ,       ,YES, test_sha1 ,310/312    ,The SHA-1 message digest.
    12/19,CMAC           ,DES_EDE3_ECB ,**NO**,  ,           ,Cipher-based – MAC with DES-EDE3 in ECB
    13/19,HMAC           ,MD2    ,**NO**,        ,           ,Hash-based – MAC with MD2
    14/19,HMAC          ,MD4    ,**NO**,        ,           ,Hash-based – MAC with MD4
    15/19,HMAC          ,MD5    ,**NO**,        ,           ,Hash-based – MAC with MD5
    16/19,HMAC          ,SHA1   ,**NO**,        ,310/312    ,Hash-based – MAC with SHA1
    17/19,DHM             ,2048   ,**NO** ,       ,310/312    ,DH-Merkle Key Exchange with  2048-bit MODP Group
    18/19,DHM             ,3072   ,**NO** ,       ,           ,DH-Merkle Key Exchange with  3072-bit MODP Group
    19/19,DHM             ,4096   ,**NO** ,       ,           ,DH-Merkle Key Exchange with  4096-bit MODP Group
        , **Covered total:** , ,  **1/19**,



=======================
Coverage overview
=======================

+-------------------------------------+---------------+----------+
| Category                            | Coverage      |          |
+-------------------------------------+---------------+----------+
|Unauthenticated modes                | 9/50          | 18%      |
+-------------------------------------+---------------+----------+
|Authenticated modes (AEAD)           | 8/20          | 40%      |
+-------------------------------------+---------------+----------+
|Hash functions                       | 5/5           | 100%     |
+-------------------------------------+---------------+----------+
|Entropy                              | 1/7           | 14%      |
+-------------------------------------+---------------+----------+
|Message Authentication Codes         | 8/12          | 66%      |
+-------------------------------------+---------------+----------+
|Asymmetric encryption / Key Exchange | 2/9           | 22%      |
+-------------------------------------+---------------+----------+
|Digital signatures                   | 1/8           | 13%      |
+-------------------------------------+---------------+----------+
|Deprecated                           | 1/19          |  5%      |
+-------------------------------------+---------------+----------+



==============
Not Considered
==============
**Following may be considerable**
 * ecp.h This file provides an API for Elliptic Curves over GF(P) (ECP)


The following files are not considered.
 - asn1.h Generic ASN.1 parsing
 - base64.h RFC 1521 base64 encoding/decoding
 - bignum.h/bn_mul.h Multi-precision integer library
 - certs.h Sample certificates and DHM parameters for testing
 - check_config.h 	Consistency checks for configuration options
 - cipher_internal.h Cipher wrappers
 - compat-1.3.h 	Compatibility definitions for using mbed TLS with client code written for the PolarSSL naming conventions
 - config-ccm-psk-tls1_2.h Minimal configuration for TLS 1.2 with PSK and AES-CCM ciphersuites
 - config-mini-tls1_1.h Minimal configuration for TLS 1.1 (RFC 4346)
 - config-no-entropy.h 	Minimal configuration of features that do not require an entropy source
 - config-suite-b.h Minimal configuration for TLS NSA Suite B Profile (RFC 6460)
 - config-thread.h Minimal configuration for using TLS as part of Thread
 - config.h Configuration options (set of defines)
 - debug.h Functions for controlling and providing debug output from the library
 - doc_XX.h Documentation files
 - ecp_internal.h Function declarations for alternative implementation of elliptic curve point arithmetic
 - error.h 	Error to string translation
 - md_internal.h Message digest wrappers
 - memory_buffer_alloc.h 	Buffer-based memory allocator
 - net.h 	Deprecated header file that includes net_sockets.h
 - net_sockets.h Network sockets abstraction layer to integrate Mbed TLS into a BSD-style sockets API
 - nist_kw.h This file provides an API for key wrapping (KW) and key wrapping with padding (KWP) as defined in NIST SP 800-38F
 - oid.h Object Identifier (OID) database
 - padlock.h VIA PadLock ACE for HW encryption/decryption supported by some processors
 - pem.h Privacy Enhanced Mail (PEM) decoding
 - pk_internal.h Public Key abstraction layer: wrapper functions
 - pkcs11.h Wrapper for PKCS#11 library libpkcs11-helper
 - pkcs12.h PKCS#12 Personal Information Exchange Syntax
 - pkcs5.h PKCS#5 functions
 - platform.h This file contains the definitions and functions of the Mbed TLS platform abstraction layer
 - platform_time.h Mbed TLS Platform time abstraction
 - platform_util.h 	Common and shared functions used by multiple modules in the Mbed TLS library
 - ssl.h SSL/TLS functions
 - ssl_cache.h SSL session cache implementation
 - ssl_ciphersuites.h 	SSL Ciphersuites for mbed TLS
 - ssl_cookie.h DTLS cookie callbacks implementation
 - ssl_internal.h Internal functions shared by the SSL modules
 - ssl_ticket.h TLS server ticket callbacks implementation
 - threading.h 	Threading abstraction layer
 - timing.h Portable interface to timeouts and to the CPU cycle counter
 - version.h Run-time version information
 - x509.h X.509 generic defines and structures
 - x509_crl.h 	X.509 certificate revocation list parsing
 - x509_crt.h X.509 certificate parsing and writing
 - x509_csr.h X.509 certificate signing request parsing and writing
