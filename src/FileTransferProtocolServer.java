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
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class FileTransferProtocolServer {
	
	private PrivateKey serverPrivateKey;
	private long sessionKey, IV;
	private byte[] encryptionKey;
	private long sequenceNumber;
	private static String hashAlgorithm = "HmacSHA256";
	
	public long getSequenceNumber() {
		return sequenceNumber;
	}

	public void setSequenceNumber(long sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}

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
	
	public void receiveFileFromClient(Socket socket, DataInputStream dis, String fileName) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		// Client uploads file to server
		
		int IVlength = dis.readInt();
		byte[] encryptedIV = new byte[IVlength];
		
		if(IVlength>0){
			dis.read(encryptedIV, 0, encryptedIV.length);
			//dis.close();
			System.out.println("Encrypted IV at server: "+new String(encryptedIV));
			//String encrypted = new String(data, 0, data.length);
			//System.out.println(encrypted);
			long decryptedNonce = this.decrypted(this.getServerPrivateKey(), encryptedIV);
			this.setIV(decryptedNonce);
			FileServer.showMessage("The decrypted IV is: " + decryptedNonce + "\n\n");
		}
		
		Mac sha256Hmac = Mac.getInstance(hashAlgorithm);
		SecretKeySpec secretKey = new SecretKeySpec(encryptionKey,hashAlgorithm);
		sha256Hmac.init(secretKey);
		
		long encryptionNonce = this.getEncryptionNonce(this.getSessionKey());
		byte[] encryptionKey = this.longToBytes(encryptionNonce);
		int encryptedDataLength = dis.readInt();
		
		File file = new File(fileName);
		FileOutputStream fos = new FileOutputStream(file);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		if(encryptedDataLength > 0) {
			byte[] encryptedBlock = new byte[encryptedDataLength];
			dis.read(encryptedBlock, 0, encryptedDataLength);
//			MessageDigest md = MessageDigest.getInstance("SHA-256");
//			byte[] concatEncrypted = new byte[encryptionKey.length + encryptedIV.length];
//			System.arraycopy(encryptedIV, 0, concatEncrypted, 0, encryptedIV.length);
//			System.arraycopy(encryptionKey, 0, concatEncrypted, encryptedIV.length, encryptionKey.length);
			
//			byte[] sha1HashConcat = md.digest(concatEncrypted);
			byte[] hmacArr = sha256Hmac.doFinal(encryptedIV);
			byte[] plainText = xor(encryptedBlock, hmacArr);
			byte[] seqNo = Arrays.copyOfRange(plainText, 0, 8);
			byte[] plainTextWithoutSeqNo = Arrays.copyOfRange(plainText, 8, plainText.length);
			long seqNoLong = this.bytesToLong(seqNo);
			this.setSequenceNumber(seqNoLong);
			bos.write(plainTextWithoutSeqNo);
			bos.flush();
			boolean changeKey = false;
			String exitStr = null;
			while(true) {
				exitStr = dis.readUTF();
				if(exitStr != null && exitStr.equals("close")) {
					break;
				}
				changeKey = dis.readBoolean();
				if(changeKey) {
					receiveNonce(dis);
					encryptionKey = this.getEncryptionKey();
					secretKey = new SecretKeySpec(encryptionKey, hashAlgorithm);
					sha256Hmac.init(secretKey);
				}
				encryptedDataLength = dis.readInt();
				if(encryptedDataLength > 0) {
					byte[] cipherText = new byte[encryptedDataLength];
					dis.read(cipherText, 0, encryptedDataLength);
//					System.out.println("xored at server: "+new String(cipherText));
//					concatEncrypted = new byte[encryptedBlock.length + encryptionKey.length];
//					System.arraycopy(encryptedBlock, 0, concatEncrypted, 0, encryptedBlock.length);
//					System.arraycopy(encryptionKey, 0, concatEncrypted, encryptedBlock.length, encryptionKey.length);
//					sha1HashConcat = md.digest(concatEncrypted);
//					System.out.println("hash at server: "+new String(sha1HashConcat));
					hmacArr = sha256Hmac.doFinal(encryptedBlock);
					plainText = Arrays.copyOfRange(xor(cipherText,hmacArr),0, encryptedDataLength);
					
//					plainText = Arrays.copyOfRange(xor(cipherText, sha1HashConcat),0,encryptedDataLength);
					seqNo = Arrays.copyOfRange(plainText, 0, 8);
					seqNoLong = this.bytesToLong(seqNo);
					if(!changeKey && seqNoLong - this.getSequenceNumber() != encryptedBlock.length) {
						FileServer.showMessage("Invalid sequence number, rejecting transfer");
						bos.close();
						fos.close();
						file.delete();
						break;
					}
					else{
						this.setSequenceNumber(seqNoLong);
						plainTextWithoutSeqNo = Arrays.copyOfRange(plainText, 8, plainText.length);
//						System.out.println("Plaintext at server: "+new String(plainTextWithoutSeqNo));
						bos.write(plainTextWithoutSeqNo, 0, plainTextWithoutSeqNo.length);
						bos.flush();
						encryptedBlock = cipherText;
					}
				}
				else {
					bos.close();
					fos.close();
					break;
				}
			}
		}
	}
	
	public void sendFileToClient(ServerSocket socket, DataInputStream dis, DataOutputStream dos, File file) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		
		this.receiveNonce(dis);
		
		int len = dis.readInt();
		if(len > 0) {
			byte[] encryptedIV = new byte[len];
			dis.read(encryptedIV, 0 , encryptedIV.length);			
			long currentSeqNo = Math.abs(generateRandomNonce());
			this.setSequenceNumber(currentSeqNo);
			this.setIV(generateRandomNonce());
			FileInputStream fis = new FileInputStream(file.getAbsolutePath());
			BufferedInputStream bis = new BufferedInputStream(fis);
			byte[] encryptionKey = this.getEncryptionKey();
			byte[] fileByte = new byte[248];
			int bytesRead = bis.read(fileByte, 0 , fileByte.length);
			if(bytesRead > 0) {
				System.out.println("Current seq at server: "+currentSeqNo);
				byte[] seqNoBytes = this.longToBytes(currentSeqNo);
				
				System.out.println("Seq no bytes at server: "+new String(seqNoBytes));
				byte[] seqNoWithFileData = new byte[bytesRead + seqNoBytes.length];
				System.arraycopy(seqNoBytes, 0, seqNoWithFileData, 0, seqNoBytes.length);
				System.arraycopy(fileByte, 0, seqNoWithFileData, seqNoBytes.length, bytesRead);
				
				Mac sha256HashMac = Mac.getInstance(hashAlgorithm);
				SecretKeySpec secretKey = new SecretKeySpec(this.getEncryptionKey(), hashAlgorithm);
				sha256HashMac.init(secretKey);
				byte[] hashArr = sha256HashMac.doFinal(encryptedIV);
				
//				byte[] IVdataBlock = new byte[encryptedIV.length + encryptionKey.length];
//				MessageDigest md = MessageDigest.getInstance("SHA-256");
//				System.arraycopy(encryptedIV, 0, IVdataBlock,0, encryptedIV.length);
//				System.arraycopy(encryptionKey, 0, IVdataBlock, encryptedIV.length, encryptionKey.length);
//				byte[] sha256Hash = md.digest(IVdataBlock);
				
				byte[] xored = xor(seqNoWithFileData, hashArr);
				dos.writeInt(xored.length);
				dos.write(xored, 0, xored.length);
				
				while(bytesRead != -1) {
					bytesRead = bis.read(fileByte, 0, bytesRead);
					if(bytesRead > 0) {
						dos.writeUTF("running");
						currentSeqNo = getNextSequenceNumber(xored.length, dos);
						this.setSequenceNumber(currentSeqNo);
						if(currentSeqNo < this.getSequenceNumber()) {
							dos.writeBoolean(true);
							this.keyRollOver(dos);
							secretKey = new SecretKeySpec(this.getEncryptionKey(),hashAlgorithm);
							sha256HashMac.init(secretKey);
						}
						else {
							dos.writeBoolean(false);
						}
//						byte[] hashedBlock = new byte[xored.length + encryptionKey.length];
						encryptionKey = this.getEncryptionKey();
						
						System.out.println("Plaintext at server: "+new String(fileByte));
						
						seqNoBytes = this.longToBytes(currentSeqNo);
						
						System.out.println("Seq no bytes at server: "+new String(seqNoBytes));
						seqNoWithFileData = new byte[bytesRead + seqNoBytes.length];
						System.arraycopy(seqNoBytes, 0, seqNoWithFileData, 0, seqNoBytes.length);
						System.arraycopy(fileByte, 0, seqNoWithFileData, seqNoBytes.length, bytesRead);
						
						hashArr = sha256HashMac.doFinal(xored);
//						System.arraycopy(xored, 0, hashedBlock, 0, xored.length);
//						System.arraycopy(encryptionKey, 0, hashedBlock, xored.length, encryptionKey.length);
//						byte[] hashValue = md.digest(hashedBlock);
						
//						System.out.println("Hash at server: "+new String(hashValue));
						
						xored = xor(seqNoWithFileData, hashArr);
						
						System.out.println("xored at server: "+new String(xored));
						dos.writeInt(seqNoWithFileData.length);
						dos.write(xored, 0 ,seqNoWithFileData.length);
					}
				}
				dos.writeUTF("close");
				FileServer.showMessage("\nFile has been uploaded successfully to the server!\n");
			}
			bis.close();
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
			this.setEncryptionKey(this.longToBytes(this.getEncryptionNonce(decryptedNonce)));
		}

	}
	private long getNextSequenceNumber(int dataLength, DataOutputStream dos) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException {
		 
		long seqNum = (this.getSequenceNumber() + dataLength) % Long.MAX_VALUE;
		return seqNum;
	 }

	private void sendNonceToClient(long sessionKey, DataOutputStream dos) throws NoSuchAlgorithmException, IOException {
		byte[] encryptionKey = this.getEncryptionKey();
		byte[] sessionKeyBytes = this.longToBytes(sessionKey);
		byte[] IV = this.longToBytes(this.getIV());
		byte[] encryptedNonce = this.encryptWithSHA256(sessionKeyBytes, IV, encryptionKey);
		dos.writeInt(encryptedNonce.length);
		dos.write(encryptedNonce, 0, encryptedNonce.length);
	}
	private byte[] encryptWithSHA256(byte[] plainText, byte[] IVbytes, byte[] encryptionKey) throws NoSuchAlgorithmException {
		
		byte[] IVdataBlock = new byte[IVbytes.length + encryptionKey.length];
		System.arraycopy(IVbytes, 0, IVdataBlock, 0, IVbytes.length);
		System.arraycopy(encryptionKey, 0, IVdataBlock, IVbytes.length, encryptionKey.length);
		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] sha1Hash = md.digest(IVdataBlock);
		return xor(plainText, sha1Hash);
	}

	public byte[] encrypted(long rand, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException  {
		//Encrypt the nonce
		//String text = "This is the session key. It is encrypted using server's public key and will be decrypted by the server using its private key!";
		Cipher ci = Cipher.getInstance("RSA");
		ci.init(Cipher.ENCRYPT_MODE, key);
		byte[] encrypted = ci.doFinal(longToBytes(rand));
		//System.err.println(new String(encrypted));
		//System.out.println(new String(encrypted));
		//dos.writeInt(1);
		//dos.flush();
		return encrypted;				
	}
	private void keyRollOver(DataOutputStream dos) throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		 this.setSessionKey(this.generateRandomNonce());
		 this.setEncryptionKey(this.longToBytes(this.getEncryptionNonce(this.getSessionKey())));
		 dos.writeBoolean(true);
		 sendNonceToClient(this.getSessionKey(), dos);
	 }
}
