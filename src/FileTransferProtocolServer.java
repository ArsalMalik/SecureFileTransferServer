import java.nio.ByteBuffer;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
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
import java.security.spec.InvalidKeySpecException;
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
	private byte[] encryptionKey;
	
	
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

	public byte[] getEncryptionKey() {
		return encryptionKey;
	}

	public void setEncryptionKey(byte[] encryptionKey) {
		this.encryptionKey = encryptionKey;
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
		
		long encryptionNonce = this.getEncryptionNonce(this.getSessionKey());
		byte[] encryptionKey = this.longToBytes(encryptionNonce);
		int encryptedDataLength = dis.readInt();
		
		FileOutputStream fos = new FileOutputStream(fileName);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		if(encryptedDataLength > 0) {
			byte[] encryptedBlock = new byte[encryptedDataLength];
			dis.read(encryptedBlock, 0, encryptedDataLength);
			MessageDigest md = MessageDigest.getInstance("SHA1");
			byte[] concatEncrypted = new byte[encryptionKey.length + encryptedIV.length];
			System.arraycopy(encryptedIV, 0, concatEncrypted, 0, encryptedIV.length);
			System.arraycopy(encryptionKey, 0, concatEncrypted, encryptedIV.length, encryptionKey.length);
			byte[] sha1HashConcat = md.digest(concatEncrypted);
			byte[] plainText = xor(encryptedBlock, sha1HashConcat);
			bos.write(plainText);
			bos.flush();
			
			while((encryptedDataLength = dis.readInt()) > 0) {
				byte[] cipherText = new byte[encryptedDataLength];
				dis.read(cipherText, 0, encryptedDataLength);
				concatEncrypted = new byte[encryptedBlock.length + encryptionKey.length];
				System.arraycopy(encryptedBlock, 0, concatEncrypted, 0, encryptedBlock.length);
				System.arraycopy(encryptionKey, 0, concatEncrypted, encryptedBlock.length, encryptionKey.length);
				sha1HashConcat = md.digest(concatEncrypted);
				plainText = xor(cipherText, sha1HashConcat);
				bos.write(plainText, 0, encryptedDataLength);
				bos.flush();
			}
			bos.close();
			fos.close();
		}
	}
	
	public void sendFileToClient(ServerSocket socket, DataInputStream dis, DataOutputStream dos, File file) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		
		this.receiveNonce(dis);
		int len = dis.readInt();
		if(len > 0) {
			byte[] encryptedIV = new byte[len];
			dis.read(encryptedIV, 0 , encryptedIV.length);
			System.out.println("At server, IV = "+this.decrypted(this.getServerPrivateKey(), encryptedIV));
			
			FileInputStream fis = new FileInputStream(file.getAbsolutePath());
			BufferedInputStream bis = new BufferedInputStream(fis);
			long encryptionNonce = this.getEncryptionNonce(this.getSessionKey());
			System.out.println("Encryption nonce at server: "+encryptionNonce);
			byte[] encryptionKey = this.longToBytes(encryptionNonce);
			System.out.println("At server, encryption key: "+new String(encryptionKey));
			byte[] IVdataBlock = new byte[encryptedIV.length + encryptionKey.length];
			System.arraycopy(encryptedIV, 0, IVdataBlock, 0, encryptedIV.length);
			System.arraycopy(encryptionKey, 0, IVdataBlock, encryptedIV.length, encryptionKey.length);
			MessageDigest md = MessageDigest.getInstance("SHA1");
			byte[] sha1Hash = md.digest(IVdataBlock);
			byte[] fileByte = new byte[20];
			int bytesRead = bis.read(fileByte, 0 , fileByte.length);
			System.out.println("At server, plaintext: "+new String(fileByte));
			byte[] xored = xor(fileByte, sha1Hash);
			dos.writeInt(xored.length);
			dos.write(xored, 0, xored.length);
			
			while(bytesRead != -1) {
				bytesRead = bis.read(fileByte, 0, bytesRead);
				if(bytesRead > 0) {
					byte[] hashedBlock = new byte[xored.length + encryptionKey.length];
					System.arraycopy(xored, 0, hashedBlock, 0, xored.length);
					System.arraycopy(encryptionKey, 0, hashedBlock, xored.length, encryptionKey.length);
					byte[] hashValue = md.digest(hashedBlock);
					byte[] cipherText = xor(fileByte, hashValue);
					dos.writeInt(bytesRead);
					dos.write(cipherText, 0 , bytesRead);
				}
			}
		}
		
	}
	
	public long decrypted(PrivateKey key, byte[] encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//Decrypt the once
		Cipher ci = Cipher.getInstance("RSA");	
		ci.init(Cipher.DECRYPT_MODE, key);
		System.out.println("Encrypted data length at server: "+encrypted.length);
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
	
	public long getEncryptionNonce(long sessionKey) {
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
		byte[] data1Local = data1.clone(), data2Local = data2.clone();
        if (data1Local.length > data2Local.length) {
            byte[] tmp = data2Local;
            data2Local = data1Local;
            data1Local = tmp;
        }
        for (int i = 0; i < data1Local.length; i++) {
            data2Local[i] ^= data1Local[i];
        }
        return data2Local;
    }
	
	public void receiveNonce(DataInputStream dis) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		int len = dis.readInt();
		byte[] data = new byte[len];
		if(len>0){
			dis.read(data, 0, data.length);
			//dis.close();

			//String encrypted = new String(data, 0, data.length);
			//System.out.println(encrypted);
			
			long decryptedNonce = this.decrypted(this.getServerPrivateKey(), data);
			this.setSessionKey(decryptedNonce);
			FileServer.showMessage("The decrypted Nonce is: " + decryptedNonce + "\n\n");
		}

	}
}
