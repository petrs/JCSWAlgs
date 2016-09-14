/*
 * JavaCard software implementation of decoding for OAEP scheme.
 * Based on source code from BouncyCastle (www.bouncycastle.org)
 * Ported by Petr Svenda http://www.svenda.com/petr

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   3. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
USAGE:
  // allocate OAEP engine
  RSAOAEP oaep = new RSAOAEP();
  // initialize cipher engine (e.g., RSACipher), hash engine (e.g., Sha1), optional encoding parameters (can be null, if not used),
  // NOTE: external_array_for_internal_work_can_be_null ... array used for internal computations (if null then array will be allocated interally) - should be RAM array for reasonable speed. you can reuse existing array.
  // if you will use let array to be allocated internally, set MAX_MASK_ARRAY_LENGTH to proper value (depending on cipher modulus - 200B is fine for RSA 2048 with SHA2-512)
  oaep.init(false, cipher_engine, hash_engine, optional_encoding_parameters_can_be_null, external_array_for_internal_work_can_be_null);

  // decode block of data from OAEP encoding
  decLen = oaep.decodeBlock(data_to_decode, start_offset_of_data, length_of_data);
 */

package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

import java.util.Random;

/**
 * JavaCard software implementation of OAEP padding. Based on BouncyCastle implementation (www.bouncycastle.org).
 * Ported by Petr Svenda (petr@svenda.com)
 *
 * @author Petr Svenda
 */
// TODO:
// 1. Add function for temporary storage of internal state of Sha-512 to bypass repeated processing of the same data
// 2. Remove necessity for separate array for mask source data storage in decode() - is it possible?
// 3. Allow to set external RAM array

public class RSAOAEP extends Cipher {
    public static final short OAEP_DECODE_FAIL = (short) 0x6003;
    public static final short ORACLE_PADDING_ATTACK_POSSIBLE = (short) 0x6004;
    
    private static boolean RSA_NOPAD_USED = false;
    private final static short MAX_MASK_ARRAY_LENGTH = (short) 260; // 220 is maximum value required if RSA2048bits OAEP is used
    
    Cipher              rsaEngine;      // underlaying RSA engine
    RandomData          random;         // random data generator
    short               blockLength;    // internal length of data usable for rsaEngine
    short               maxInputLength; // maximum length of user supplied data (smaller than blockLength due to seed and hash of encodingParams)
    byte[]              maskSource;     // auxalarity array used to performed OAEP computation
    byte[]              defHash;        // hash of optional encodingParams provided by user

    // used by maskGeneratorFunction1 internally
    private byte[] tempHash;            
    private byte[] C;
    private MessageDigest hash;
    private MessageDigest mgf1Hash;
    private byte mode;

    public byte getAlgorithm() {
        return Cipher.ALG_RSA_PKCS1_OAEP;
    }

    public void init(Key rsaKey, byte mode, byte[] algSpecificData, short offset, short len) {
        myInit(rsaKey, mode, algSpecificData, offset, len);
    }

    public void init(Key rsaKey, byte mode) {
        myInit(rsaKey, mode, null, (short) 0, (short) 0);
    }

    protected void myInit(Key rsaKey, byte mode, byte[] algSpecificData, short offset, short len) {
        this.mode = mode;
        if (algSpecificData != null) {
            rsaEngine.init(rsaKey, mode, algSpecificData, offset, len);
        }
        else {
            rsaEngine.init(rsaKey, mode);
        }
        short keySize = rsaKey.getSize();
        blockLength = (short) (keySize / 8);    // length of underlaying RSA
        if (RSA_NOPAD_USED == false) {
            blockLength -= 11;                      // overhead for PKCS1 padding
        }
        
        maxInputLength = blockLength;           // length of underlaying RSA
        maxInputLength -= hash.getLength();     // hash of encoding parameters
        maxInputLength -= hash.getLength();     // seed
        maxInputLength -= 1;                    // 1B sentinel
    }
    
    public static RSAOAEP getInstance(
            Cipher rsaEngine,
            MessageDigest hash,
            RandomData random,
            byte[] encodingParams,
            byte[] externalMaskSourceArray) {
        return getInstance(rsaEngine, false, hash, random, encodingParams, externalMaskSourceArray);
    }    
    public static RSAOAEP getInstanceAnyEngine(
            Cipher rsaEngine,
            MessageDigest hash,
            RandomData random,
            byte[] encodingParams,
            byte[] externalMaskSourceArray) {
        return getInstance(rsaEngine, false, hash, random, encodingParams, externalMaskSourceArray);
    }
    public static RSAOAEP getInstance(
            Cipher rsaEngine,
            boolean bPreventPaddingOracle,
            MessageDigest hash,
            RandomData random,
            byte[] encodingParams,
            byte[] externalMaskSourceArray) {

        RSAOAEP newInst = new RSAOAEP();
        
        // For now, prevent other engines than PKCS1
        if (rsaEngine.getAlgorithm() != Cipher.ALG_RSA_PKCS1) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        
        
        // Chcek for engine with potential padding oracle attack
        RSA_NOPAD_USED = (rsaEngine.getAlgorithm() != Cipher.ALG_RSA_NOPAD) ? false : true;
        
        if ((RSA_NOPAD_USED == false) && bPreventPaddingOracle) {
            ISOException.throwIt(ORACLE_PADDING_ATTACK_POSSIBLE);
        }
        
        newInst.rsaEngine = rsaEngine;
        newInst.hash = hash;
        newInst.random = random;
        newInst.mgf1Hash = hash;
        newInst.tempHash = JCSystem.makeTransientByteArray(hash.getLength(), JCSystem.CLEAR_ON_RESET);
        newInst.defHash = JCSystem.makeTransientByteArray(hash.getLength(), JCSystem.CLEAR_ON_RESET);
        newInst.C = JCSystem.makeTransientByteArray((byte) 4, JCSystem.CLEAR_ON_RESET);

        if (externalMaskSourceArray == null) {
            newInst.maskSource = JCSystem.makeTransientByteArray(MAX_MASK_ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
        }
        else {
            // provided array must have at least required length
            if ((short) externalMaskSourceArray.length < MAX_MASK_ARRAY_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            newInst.maskSource = externalMaskSourceArray;
        }

        if (encodingParams != null) {
            hash.doFinal(encodingParams, (short) 0, (short) encodingParams.length, newInst.defHash, (short) 0);
        } else {
            hash.doFinal(newInst.tempHash, (short) 0, (short) 0, newInst.defHash, (short) 0);
        }

        return newInst;
    }


    public short update(
            byte[] in,
            short inOff,
            short inLen,
            byte[] out,
            short outOff) throws ISOException {
        return rsaEngine.update(in, inOff, inLen, out, outOff);
    }

    public short doFinal(
            byte[] in,
            short inOff,
            short inLen,
            byte[] out,
            short outOff) throws ISOException {


        if (mode == MODE_DECRYPT) {
            return decodeDoFinal(in, inOff, inLen, out, outOff);
        }
        if (mode == MODE_ENCRYPT) {
            return encodeDoFinal(in, inOff, inLen, out, outOff);
        }
        return (short) -1;
    }

    public short encodeDoFinal(
            byte[] in,
            short inOff,
            short inLen,
            byte[] out,
            short outOff) throws ISOException {

        if (inLen > maxInputLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayFillNonAtomic(maskSource, (short) 0, blockLength, (byte) 0);

        // copy in the message
        Util.arrayCopyNonAtomic(in, inOff, maskSource, (short) (blockLength - inLen), inLen); // last part of block are set to input data

        // add sentinel
        maskSource[(short) ((short) (blockLength - inLen) - (short) 1)] = 0x01;

        // as the block is already zeroed - there's no need to add PS (the >= 0 pad of 0)

        // add the hash of the encoding params
        Util.arrayCopyNonAtomic(defHash, (short) 0, maskSource, (short) defHash.length, (short) defHash.length);

        // generate random seed
        random.generateData(maskSource, (short) 0, (short) defHash.length);

        // mask the message block
        short maskMsgLen = (short) (blockLength - (short) defHash.length);
        maskGeneratorFunction1(maskSource, (short) 0, (short) defHash.length, maskMsgLen, maskSource, (short) defHash.length);

        // mask the seed.
        maskMsgLen = (short) (blockLength - defHash.length);
        // copy intermediate state into output buffer (will be soon xored with produced mask)
        Util.arrayCopyNonAtomic(maskSource, (short) 0, out, outOff, blockLength);
        maskGeneratorFunction1(maskSource, (short) defHash.length, maskMsgLen, (short) defHash.length, out, outOff);

        short outputLength = rsaEngine.doFinal(out, outOff, blockLength, out, outOff);

        return outputLength;
    }

    public short decodeDoFinal(
            byte[] in,
            short inOff,
            short inLen,
            byte[] out,
            short outOff) throws ISOException {


        short decLen = rsaEngine.doFinal(in, inOff, inLen, out, outOff);

        // WE MUST REMOVE TRAILING ZEROES FROM DECRYPTED RESULT
        // IF RSA_PKCS1 IS USED, THAN IT WAS ALREADY PERFORMED
        // IF RSA_NOPAD IS USED, REMOVE FIRST BYTE
        if (RSA_NOPAD_USED) {
            if (out[outOff] != 0) {
                throw new ISOException(OAEP_DECODE_FAIL);
            } else {
                outOff++;
                decLen--;
            }
        }

        if (decLen < (short) ((2 * defHash.length) + 1)) {
            throw new ISOException(OAEP_DECODE_FAIL);
        }


        //
        // unmask the seed.
        //
        short maskSourceLength = (short) (decLen - (short) defHash.length);
        Util.arrayCopyNonAtomic(out, (short) (outOff + defHash.length), maskSource, (short) 0, maskSourceLength);
        maskGeneratorFunction1(maskSource, (short) 0, maskSourceLength, (short) defHash.length, out, outOff);
        // out now contains message with seed masked out

        //
        // unmask the message block.
        //
        maskSourceLength = (short) defHash.length;
        Util.arrayCopyNonAtomic(out, outOff, maskSource, (short) 0, maskSourceLength);
        maskGeneratorFunction1(maskSource, (short) 0, maskSourceLength, (short) (decLen - defHash.length), out, (short) (outOff + defHash.length));
        // out now contains ummasked message and hash of encoding params

        //
        // check the hash of the encoding params
        //
        for (short i = 0; i != defHash.length; i++) {
            if (defHash[i] != out[(short) (outOff + defHash.length + i)]) {
                throw new ISOException(OAEP_DECODE_FAIL);
            }
        }

        //
        // foutd the data block
        //
        short start;
        for (start = (short) (outOff + 2 * defHash.length); start < (short) (outOff + decLen); start++) {
            if (out[start] == 1 || out[start] != 0) break;
        }

        if (start >= (short) (outOff + decLen - 1)) throw new ISOException(OAEP_DECODE_FAIL);
        if (out[start] != 1) throw new ISOException(OAEP_DECODE_FAIL);

        start++;

        //
        // extract the data block
        //
        short outputLength = (short) (decLen - (short) (start - outOff));
        start -= outOff;

        if (RSA_NOPAD_USED) {
            for (short i = outOff; i < (short) (outOff + outputLength); i++) {
                out[(short) (i - 1)] = out[(short) (start + i)];
            }
            outputLength--;
        } else {
            for (short i = outOff; i < (short) (outOff + outputLength); i++) {
                out[i] = out[(short) (start + i)];
            }
        }

        return outputLength;
    }

    private short maskGeneratorFunction1(
            byte[] Z,
            short zOff,
            short zLen,
            short length,
            byte[] bufferToMask,
            short bufferToMaskOffset) {
        short counter = 0;

        hash.reset();
        mgf1Hash.reset();

        // COPY INPUT

        // ASSUMPTION: WE WILL NOT PROCESS MORE THEN 128 BLOCKS
        C[0] = (byte) 0;
        C[1] = (byte) 0;
        C[2] = (byte) 0;
        C[3] = (byte) -1;
        do {
            C[3] = (byte) (C[3] + 1);

            mgf1Hash.update(Z, zOff, zLen);
            mgf1Hash.doFinal(C, (short) 0, (short) C.length, tempHash, (short) 0);

            // MASK/UNMASK PART OF GIVEN ARRAY
            for (short i = 0; i < (short) tempHash.length; i++)
                bufferToMask[(short) (bufferToMaskOffset + i)] ^= tempHash[i];
            bufferToMaskOffset += (short) (tempHash.length);
        }
        while (++counter < (short) (length / tempHash.length));

        if ((short) (counter * tempHash.length) < length) {
            C[3] = (byte) (C[3] + 1);

            mgf1Hash.update(Z, zOff, zLen);
            mgf1Hash.doFinal(C, (short) 0, (short) C.length, tempHash, (short) 0);

            for (short i = 0; i < (short) tempHash.length; i++)
                bufferToMask[(short) (bufferToMaskOffset + i)] ^= tempHash[i];
            bufferToMaskOffset += (short) tempHash.length;
        }
        return (short) 0;
    }
}
