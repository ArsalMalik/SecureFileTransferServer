import java.nio.ByteBuffer;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class FileTransferProtocolServer {
	
	private PrivateKey serverPrivateKey;
	private long sessionKey, IV;
	
	
	public long getSessionKey() {
		return sessionKey;
	}

	public void setSessionKey(long sessionKey) {
		this.sessionKey = sessionKey;
	}

	public long getIV() {
		return IV;
	}

	public void setIV(long iV) {
		IV = iV;
	}

	public PrivateKey getServerPrivateKey() {
		return serverPrivateKey;
	}

	public void setServerPrivateKey(PrivateKey serverPrivateKey) {
		this.serverPrivateKey = serverPrivateKey;
	}

	public long generateRandomNonce() {
		
		SecureRandom random = new SecureRandom();
		return random.nextLong();
	}
	
	public void receiveFileFromClient(Socket socket, DataInputStream dis, String fileName) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// Client uploads file to server
		
		int IVlength = dis.readInt();
		byte[] encryptedIV = new byte[IVlength];
		
		if(IVlength>0){
			dis.read(encryptedIV, 0, encryptedIV.length);
			//dis.close();
			
			//String encrypted = new String(data, 0, data.length);
			//System.out.println(encrypted);
			long decryptedNonce = this.decrypted(this.getServerPrivateKey(), encryptedIV);
			this.setIV(decryptedNonce);
			FileServer.showMessage("The decrypted IV is: " + decryptedNonce + "\n\n");
		}
		
		long encryptionNonce = this.getEncryptionKey(this.getIV());
		System.out.println("Encryption nonce at server : "+encryptionNonce);
		byte[] encryptionKey = this.longToBytes(encryptionNonce);
		System.out.println("Encryption key at server: "+new String(encryptionKey));
		int encryptedDataLength = dis.readInt();
		if(encryptedDataLength > 0) {
			byte[] encryptedIVBlock = new byte[encryptedDataLength];
			dis.read(encryptedIVBlock, 0, encryptedDataLength);
			System.out.println("IV data block at server: "+new String(encryptedIVBlock));
			MessageDigest md = MessageDigest.getInstance("SHA1");
			byte[] concatEncrypted = new byte[encryptionKey.length + encryptedIV.length];
			System.arraycopy(encryptedIV, 0, concatEncrypted, 0, encryptedIV.length);
			System.arraycopy(encryptionKey, 0, concatEncrypted, encryptedIV.length, encryptionKey.length);
			System.out.println("Concatenated IV with key at server: "+new String(concatEncrypted));
			byte[] sha1HashConcat = md.digest(concatEncrypted);
			byte[] plainTextByte = xor(encryptedIVBlock, sha1HashConcat);
			System.out.println("plaintext byte: "+ new String(plainTextByte));
		}
		
		
//		
//		FileOutputStream fos = new FileOutputStream(fileName);
//		BufferedOutputStream bos = new BufferedOutputStream(fos);
//		byte[] fileByte = new byte[64];
//		int bytesRead = 0;
//		while(bytesRead != -1) {
//			bytesRead = dis.read(fileByte,0,fileByte.length);
//			if(bytesRead > 0) {
//				bos.write(fileByte,0,bytesRead);
//			}
//		}
//		bos.close();
//		fos.close();
	}
	
	public long decrypted(PrivateKey key, byte[] encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//Decrypt the nonce
		Cipher ci = Cipher.getInstance("RSA");	
		ci.init(Cipher.DECRYPT_MODE, key);
		byte[] decrypted = ci.doFinal(encrypted);
		long ldecrypted = bytesToLong(decrypted);
		//System.err.println(decrypted);
		//System.out.println("The decrypted random nonce is: " + ldecrypted);
		return ldecrypted;
		} 
	
	
	
	
	public byte[] longToBytes(long x) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.putLong(x);
	    return buffer.array();
	}
	
	public long bytesToLong(byte[] bytes) {
	    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.put(bytes);
	    buffer.flip();//need flip 
	    return buffer.getLong();
	}
	
	public long getEncryptionKey(long sessionKey) {
		if(sessionKey > 0) {
			return sessionKey - 1;
		}
		return sessionKey + 1;
	}
	public long getIntegrityKey(long sessionKey) {
		if(sessionKey > 0) {
			return sessionKey - 2;
		}
		return sessionKey + 2;
	}
	
	 public static byte[] xor(byte[] data1, byte[] data2) {
	        // make data2 the largest...
	        if (data1.length > data2.length) {
	            byte[] tmp = data2;
	            data2 = data1;
	            data1 = tmp;
	        }
	        for (int i = 0; i < data1.length; i++) {
	            data2[i] ^= data1[i];
	        }
	        return data2;
	    }
}
