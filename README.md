JCSWAlgs
========

The Suite of software reimplementations of selected cryptographic algorithms potentially missing on your smartcard with JavaCard platform. Optimized for speed and small memory footprint.

Following algorithms are included at the moment:
- Advanced Encryption Standard (AES) with 128bit key
- Optimal Asymmetric Encryption Padding (OAEP)
- SHA2-384 and SHA2-512 cryptographic hash functions

All algorithms are allows to reuse already allocated cryptographic primitives and RAM memory arrays to decrease memory footprint. Allocation of the algorithm is therefore performed differently from native primitives (e.g., SWAES.getInstance() instead of Cipher.getInstance() is required).

Usage
-----
	RSAOAEP rsaOAEP = RSAOAEP.getInstance(cipherEngine, hashEngine, randomData, optionalEncodingParams, optionalHelperRAMArray);

	rsaOAEP.init(m_rsaPubKey, Cipher.MODE_ENCRYPT);
	short wrapLen = m_rsaOAEP.doFinal(inArray, baseOffset, dataLen, outArray, baseOffset);

	rsaOAEP.init(m_rsaPrivKey, Cipher.MODE_DECRYPT);
	unwrapLen = m_rsaOAEP.doFinal(inArray, baseOffset, wrapLen, outArray, baseOffset);



Important: No special protection against side-channels (e.g., timing analysis) added so far. 

