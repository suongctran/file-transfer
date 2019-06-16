import java.security.*;
import java.util.Arrays;
import java.io.*;
import javax.crypto.*;

public class Receiver {
	public static SecretKey sessionKey;
	
	public static void main(String[] args) throws Exception {
		File file = new File("receiverPubKey.bin");
		
		if(!file.exists()){
			createKeyPair();
		} else {
	        Crypto crypto = new Crypto();
	        
	        //get saved AES session key
	        File aesFile = new File("AESSessionKey.txt");
	        FileInputStream fis = new FileInputStream(aesFile);
			byte[] key = new byte[(int) aesFile.length()];
		    fis.read(key);
		    fis.close();
	
			//get receiver's private key
			PrivateKey privKey = crypto.getPrivKey("receiverPrivKey.bin");
			
			//decrypt session key with receiver's private key
			sessionKey = crypto.decrypt(privKey, key);
			
			//verify MAC
			if(verify() == true) {
				//decrypt message using AES session key
				decryptFile("Message encrypted.txt", "Message decrypted.txt", sessionKey);
			} else {
				System.out.println("MAC does not match!");
			}
		}
	}
	
	//Creates public and private key for Receiver
	private static void createKeyPair() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(4096);
		KeyPair keyPair = gen.genKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		byte[] privkey = privateKey.getEncoded();
		byte[] pubkey = publicKey.getEncoded();
		try (FileOutputStream fos = new FileOutputStream(new File("receiverPrivKey.bin"))) {
			fos.write(privkey);
		}
		try (FileOutputStream fos = new FileOutputStream(new File("receiverPubKey.bin"))) {
			fos.write(pubkey);
		}
	}
	
	//Decrypt Message file with the decrypted AES session key
    private static void decryptFile(String fileIn, String fileOut, Key key) throws Exception {
		FileInputStream fis = new FileInputStream(fileIn);
		FileOutputStream fos = new FileOutputStream(fileOut);
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, key);
        CipherOutputStream cos = new CipherOutputStream(fos, c);
        byte[] decValue = new byte[1024];
        int x;
        while((x=fis.read(decValue))!=-1) {
        	cos.write(decValue, 0, x);
        }
        fis.close();
        fos.flush();
        cos.close();
    }
    
	private static boolean verify() throws Exception {
        // create a MAC and initialize with the AES session key
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(sessionKey);
        // encrypt with Message encrypted
        FileInputStream fis = new FileInputStream("Message encrypted.txt");
        byte[] dataBytes = new byte[1024];
        int nread = fis.read(dataBytes);
        while (nread > 0) {
          mac.update(dataBytes, 0, nread);
          nread = fis.read(dataBytes);
        }
        byte[] macbytes = mac.doFinal();
        fis.close();
        
		//check if mac are the same
        File macFile = new File("mac");
        FileInputStream fis2 = new FileInputStream(macFile);
		byte[] fileByte2 = new byte[(int) macFile.length()];
	    fis2.read(fileByte2);
	    fis2.close();
		if(Arrays.equals(macbytes, fileByte2)) {
			return true;
		} else {
			return false;
		}		
	}
}
