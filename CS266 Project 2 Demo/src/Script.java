import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class Script {
	private static ArrayList<PublicKey> pubKeyList;
	private static Cipher cipher;
	
	public Script() throws NoSuchAlgorithmException, NoSuchPaddingException {
		cipher = Cipher.getInstance("RSA");
	}
	public static ArrayList<PublicKey> multisign(int numOfNodes) throws NoSuchAlgorithmException, IOException {
		final int keySize = 1024;
		setPubKeyList(new ArrayList<>());
		ArrayList<PublicKey> pubKeyList = new ArrayList<PublicKey>();
		boolean exportKey = true;
		for(int i = 0; i<numOfNodes; i++) {
	        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	        keyPairGenerator.initialize(keySize);  
	        KeyPair keyPair = keyPairGenerator.generateKeyPair();
	        pubKeyList.add(keyPair.getPublic());
	        /*if(exportKey) {
	        	 	byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
	        	    FileOutputStream fos = new FileOutputStream("/Users/baopham/publicKeyTest");
	        	    fos.write(publicKeyBytes);
	        	    fos.close();
	        	    byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
	        	    FileOutputStream fos1 = new FileOutputStream("/Users/baopham/privateKeyTest");
	        	    fos1.write(privateKeyBytes);
	        	    fos1.close();
	        	    exportKey = false;
	        }*/
		}
		return pubKeyList;
	}
	
	public String buildMultisignOut(ArrayList<String> pubKeyList) {
		String multiHashValue = "";
		for (String pubKey: pubKeyList) {
			int hashValue = pubKey.hashCode();
			multiHashValue.concat(Integer.toString(hashValue));
		}
		return multiHashValue;
	}
	
	public PrivateKey getPrivate(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
		
	public static String encryptText(String msg, PrivateKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException {
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encode(cipher.doFinal(msg.getBytes("UTF-8")));
	}

	public static String decryptText(String msg, PublicKey key)
			throws InvalidKeyException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException {
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decode(msg)), "UTF-8");
	}
	
	public static boolean evaluate(String msg, String encrypted_msg, PublicKey prikey) throws Exception {
		 KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	        keyPairGenerator.initialize(1024);  
		//String msg = "Project 2 CS 266";
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		//String encrypted_msg = encryptText(msg, prikey);
		String decrypted_msg = decryptText(encrypted_msg, keyPair.getPublic());
		System.out.println("Original Message: " + encrypted_msg +
			"\nEncrypted Message: " + encrypted_msg
			+ "\nDecrypted Message: " + decrypted_msg);
		if(decrypted_msg.equals(msg)) return true;
		else return false;
		
	}
	/*
	public static void main(String[] args) throws Exception {
		//multisign(1);
		Script sc = new Script();
		PrivateKey privateKey = sc.getPrivate("/Users/baopham/privateKeyTest");
		PublicKey publicKey = sc.getPublic("/Users/baopham/publicKeyTest");
		String encrypted_msg = sc.encryptText("CS211", privateKey);
		String decrypted_msg = sc.decryptText(encrypted_msg, publicKey);
		System.out.println("Original Message: CS211 " +
				"\nEncrypted Message: " + encrypted_msg
				+ "\nDecrypted Message: " + decrypted_msg);


	}*/
	public static ArrayList<PublicKey> getPubKeyList() {
		return pubKeyList;
	}
	public static void setPubKeyList(ArrayList<PublicKey> pubKeyList) {
		Script.pubKeyList = pubKeyList;
	}
}