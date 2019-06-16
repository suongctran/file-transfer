import java.security.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class Crypto {
	
	//To encrypt AES session key with Receiver's public key
	public byte[] encrypt(PublicKey pubKey, byte[] sKey) {
	    try {
	        Cipher c;
	        c = Cipher.getInstance("RSA");
	        c.init(Cipher.ENCRYPT_MODE, pubKey);
	        byte[] encryptedKey = c.doFinal(sKey);
	        return encryptedKey;
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    return null;
	}
	
	//To decrypt AES session key with Receiver's private key
	public SecretKey decrypt(PrivateKey prvKey, byte[] sKey) {
	    try {
	        Cipher c;
	        c = Cipher.getInstance("RSA");
	        c.init(Cipher.DECRYPT_MODE, prvKey);
	        SecretKey key = new SecretKeySpec(c.doFinal(sKey), "AES");
	        return key;
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    return null;
	}

	//Generating AES session key
	public SecretKey generateKey() throws Exception {
		try{
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey secretKey = keyGen.generateKey();
			return secretKey;
		} catch (Exception e) {
			System.out.println(e);
		}

		return null;
	}

	//Retrieving private key
	public PrivateKey getPrivKey(String filename) throws Exception {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int)f.length()];
		dis.readFully(keyBytes);
		dis.close();

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	//Retrieving public key
	public PublicKey getPubKey(String filename) throws Exception {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int)f.length()];
		dis.readFully(keyBytes);
		dis.close();

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
}
