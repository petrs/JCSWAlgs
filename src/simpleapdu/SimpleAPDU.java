package simpleapdu;

import applets.TestSWAlgsApplet;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;
import javacard.security.KeyPair;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Petr Svenda petr@svenda.com
 */
public class SimpleAPDU {
    static CardMngr cardManager = new CardMngr();

    private final static byte SELECT_TESTAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

    private static byte TEST_RSAOEAP[] = {(byte) 0xB0, (byte) 0x5A, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static byte TEST_RSAOEAP_PERF_ENCODE[] = {(byte) 0xB0, (byte) 0x5B, (byte) 0x01, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x10};
    private static byte TEST_RSAOEAP_PERF_DECODE[] = {(byte) 0xB0, (byte) 0x5C, (byte) 0x02, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0xff};
    
    static short getShort(byte[] array, int offset) {
        return (short) (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));        
    }
    
    public static void main(String[] args) {
        try {
            //
            // SIMULATED CARDS
            //

            // Prepare simulated card 
            byte[] installData = new byte[15]; // no special install data passed now - can be used to pass initial keys etc.
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, TestSWAlgsApplet.class);

            byte[] response = cardManager.sendAPDUSimulator(TEST_RSAOEAP);

            
            
            //
            // REAL CARDS
            //
            if (cardManager.ConnectToCard()) {
                // Select our application on card
                cardManager.sendAPDU(SELECT_TESTAPPLET);

                // Functionla tests
                ResponseAPDU resp = cardManager.sendAPDU(TEST_RSAOEAP);
                
                // Performance tests
                for (int i = 0; i < 5; i++) {
                    resp = cardManager.sendAPDU(TEST_RSAOEAP_PERF_ENCODE);
                }
                for (int i = 0; i < 5; i++) {
                    resp = cardManager.sendAPDU(TEST_RSAOEAP_PERF_DECODE);
                }

                cardManager.DisconnectFromCard();
            } else {
                System.out.println("Failed to connect to card");
            }
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
 }
