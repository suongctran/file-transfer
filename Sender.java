import java.security.*;
import java.io.*;
import javax.crypto.*;

public class Sender {
	static SecretKey sessionKey;

	public static void main(String[] args) throws Exception {
		createKeyPair();
        Crypto crypto = new Crypto();
		
		//generate AES session key
		sessionKey = crypto.generateKey();
		//encrypt message using AES session key
		encryptFile("Message.txt", "Message encrypted.txt", sessionKey);

		//turn AES session key to byte array
		byte[] key = sessionKey.getEncoded();
		//get receiver's public key
		PublicKey publicKey = crypto.getPubKey("receiverPubKey.bin");
		//encrypt session key with receiver's public key
		byte[] encryptedKey = crypto.encrypt(publicKey, key);
		//save encrypted AES session key
		try (FileOutputStream fos = new FileOutputStream(new File("AESSessionKey.txt"))) {
			fos.write(encryptedKey);
		}
		authentication();
	}
	
	//Creates public and private key for Sender
	private static void createKeyPair() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(4096);
		KeyPair keyPair = gen.genKeyPair(); 
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		byte[] privkey = privateKey.getEncoded();
		byte[] pubkey = publicKey.getEncoded();
		try (FileOutputStream fos = new FileOutputStream(new File("senderPrivKey.bin"))) {
			fos.write(privkey);
		}
		try (FileOutputStream fos = new FileOutputStream(new File("senderPubKey.bin"))) {
			fos.write(pubkey);
		}
	}
	
	//Encrypt Message file with the AES session key
	private static void encryptFile(String fileIn, String fileOut, SecretKey key) throws Exception {
		FileInputStream fis = new FileInputStream(fileIn);
		FileOutputStream fos = new FileOutputStream(fileOut);
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, key);
        CipherOutputStream cos = new CipherOutputStream(fos, c);
        byte[] encVal = new byte[1024];
        int x;
        while((x=fis.read(encVal))!=-1) {
        	cos.write(encVal, 0, x);
        }
        fis.close();
        fos.flush();
        cos.close();
	}
	
	private static void authentication() throws Exception {
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
        //saves mac
		try (FileOutputStream fos = new FileOutputStream(new File("mac"))) {
			fos.write(macbytes);
		}
		
	}

}
