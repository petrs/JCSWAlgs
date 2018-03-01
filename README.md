 [![Build status](https://travisci.org/JavaCardSpot-dev/JCSWAlgs.svg?branch=master)](https://travisci.org/JavaCardSpot-dev/JCSWAlgs)

:information_source: **IMPORTANT: This repository is used for class [PV204 Security Technologies at
Masaryk University](https://is.muni.cz/auth/predmety/predmet?lang=en;setlang=en;pvysl=3141746). All
meaningful improvements will be attempted to be pushed to upstream repository in June 2018.**

JCSWAlgs
========

The Suite of software reimplementations of selected cryptographic algorithms potentially missing on your smartcard with JavaCard platform. Optimized for speed and small memory footprint.

Following algorithms are included at the moment:
- Advanced Encryption Standard (AES) with 128bit key (soon)
- Optimal Asymmetric Encryption Padding (OAEP)
- SHA2-384 and SHA2-512 cryptographic hash functions (soon)

All algorithms are allows to reuse already allocated cryptographic primitives and RAM memory arrays to decrease memory footprint. Allocation of the algorithm is therefore performed differently from native primitives (e.g., SWAES.getInstance() instead of Cipher.getInstance() is required).

Usage - RSA OAEP
-----
````java
// Allocate instance of RSA with OAEP 
// cipherEngine (Cipher), hashEngine (MessageDigest) and rngEngine (RandomData) are native JavaCard engines
RSAOAEP rsaOAEP = RSAOAEP.getInstance(cipherEngine, hashEngine, rngEngine, optEncParams, optAuxRAMArray);

// Encrypt data
rsaOAEP.init(m_rsaPubKey, Cipher.MODE_ENCRYPT);
short wrapLen = m_rsaOAEP.doFinal(inArray, baseOffset, dataLen, outArray, baseOffset);

// Decrypt data
rsaOAEP.init(m_rsaPrivKey, Cipher.MODE_DECRYPT);
unwrapLen = m_rsaOAEP.doFinal(inArray, baseOffset, wrapLen, outArray, baseOffset);
````


Important: No special protection against side-channels (e.g., timing analysis) added so far. 

