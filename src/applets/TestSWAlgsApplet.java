/*
 * PACKAGEID: 4C6162616B417070
 * APPLETID: 4C6162616B4170706C6574
 */
package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class TestSWAlgsApplet extends javacard.framework.Applet
{
    boolean         m_isRealCard = false;
    // MAIN INSTRUCTION CLASS
    final static byte CLA_TESTAPPLET            = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_TEST_RSAOAEP          = (byte) 0x5a;
    final static byte INS_TEST_RSAOAEP_PERF     = (byte) 0x5b;
    

    final static short ARRAY_LENGTH                   = (short) 300;
    final static byte  AES_BLOCK_LENGTH               = (short) 0x16;

    // TEMPORARY ARRAY IN RAM
    private byte m_ramArray[] = null;
    private byte m_ramArray2[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte       m_dataArray[] = null;
    
    
    Cipher                  m_rsaEngine = null;
    MessageDigest           m_hash  = null;
    RandomData              m_secureRandom = null;
    KeyPair                 m_rsaKeyPair = null;
    RSAPublicKey            m_rsaPubKey = null;
    RSAPrivateCrtKey        m_rsaPrivKey = null;
    RSAOAEP                 m_rsaOAEP = null;
    
    
    
    protected TestSWAlgsApplet(byte[] buffer, short offset, byte length) {
        short dataOffset = offset;

        if(length > 9) {
            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);
            // go to proprietary data
            dataOffset++;

            if (length == 15) {
                // We have simulator
                m_isRealCard = false;
            } else {
                // This is real card
                m_isRealCard = true;
            }
            
            m_ramArray = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
            m_ramArray2 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
            
            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            m_rsaEngine = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

            if (m_isRealCard == true) {
                //For real cards: we need new instance when generating completelly new key:
                m_rsaKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
            } else {
                // For simulated cards - create KeyPair from two keys
                m_rsaPubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
                m_rsaPrivKey = (RSAPrivateCrtKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
                m_rsaKeyPair = new KeyPair(m_rsaPubKey, m_rsaPrivKey);
            }
            
            m_rsaKeyPair.genKeyPair();
            m_rsaPubKey = (RSAPublicKey) m_rsaKeyPair.getPublic();
            m_rsaPrivKey = (RSAPrivateCrtKey) m_rsaKeyPair.getPrivate();

            m_rsaOAEP = RSAOAEP.getInstance(m_rsaEngine, m_hash, m_secureRandom, null, null);
            
            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
        } 

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet  instance creation 
        new TestSWAlgsApplet (bArray, bOffset, bLength);
    }

    public boolean select() {
      return true;
    }

    public void deselect() {
        return;
    }

    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_TESTAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] ) {
                case INS_TEST_RSAOAEP:
                    Test_RSAOEAP(apdu);
                    break;
                case INS_TEST_RSAOAEP_PERF:
                    Test_RSAOEAP_performance(apdu);
                    break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    void Test_RSAOEAP(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        TestRSAOEAPSingle((short) 0, (short) 0, true);
        TestRSAOEAPSingle((short) 1, (short) 0, false);
        TestRSAOEAPSingle((short) 17, (short) 0, false);
        TestRSAOEAPSingle((short) 180, (short) 0, false);
        TestRSAOEAPSingle((short) 181, (short) 0, true);
        
        // Execute with offset 10 (not starting at 0)
        TestRSAOEAPSingle((short) 17, (short) 10, false);
        TestRSAOEAPSingle((short) 180, (short) 10, false);
    }
    
    short m_wrapLen = 0;
    void Test_RSAOEAP_performance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        short dataLen = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        if (buffer[ISO7816.OFFSET_P1] == 1) {  
            m_rsaOAEP.init(m_rsaPubKey, Cipher.MODE_ENCRYPT);
            m_wrapLen = m_rsaOAEP.doFinal(m_ramArray, (short) 0, dataLen, m_ramArray2, (short) 0);
        }
        if (buffer[ISO7816.OFFSET_P1] == 2) {
            // Assumption: properly wrapped data in m_ramArray2 from previous run of Test_RSAOEAP_performance encode
            m_rsaOAEP.init(m_rsaPrivKey, Cipher.MODE_DECRYPT);
            short unwrapLen = m_rsaOAEP.doFinal(m_ramArray2, (short) 0, m_wrapLen, m_ramArray, (short) 0);
        }
    }
    
    private void TestRSAOEAPSingle(short dataLen, short baseOffset, boolean shouldFail) {
        Util.arrayFillNonAtomic(m_ramArray, (short) 0, (short) m_ramArray.length, (byte) 0);
        Util.arrayFillNonAtomic(m_ramArray2, (short) 0, (short) m_ramArray2.length, (byte) 0);

        m_secureRandom.generateData(m_ramArray, baseOffset, dataLen);
        Util.arrayCopyNonAtomic(m_ramArray, baseOffset, m_ramArray2, baseOffset, dataLen);

        boolean bFailed = false;
        short unwrapLen = 0;
        try {
            m_rsaOAEP.init(m_rsaPubKey, Cipher.MODE_ENCRYPT);
            short wrapLen = m_rsaOAEP.doFinal(m_ramArray2, baseOffset, dataLen, m_ramArray2, baseOffset);

            m_rsaOAEP.init(m_rsaPrivKey, Cipher.MODE_DECRYPT);
            unwrapLen = m_rsaOAEP.doFinal(m_ramArray2, baseOffset, wrapLen, m_ramArray2, baseOffset);
        }
        catch (ISOException e) {
            if (shouldFail) {
                // exception is expected
                bFailed = true;
            }   
            else {
                // Fail not expected, re-throw 
                ISOException.throwIt(e.getReason());
            }
        }
        
        if (shouldFail) {
            if (!bFailed) {
                // Failure was expected, but did not happened
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        else {
            // Compare resulting values
            if (dataLen != unwrapLen) {
                ISOException.throwIt(RSAOAEP.OAEP_DECODE_FAIL);
            }
            if (Util.arrayCompare(m_ramArray, baseOffset, m_ramArray2, baseOffset, dataLen) != 0) {
                ISOException.throwIt(RSAOAEP.OAEP_DECODE_FAIL);
            } 
        }
    }
}

