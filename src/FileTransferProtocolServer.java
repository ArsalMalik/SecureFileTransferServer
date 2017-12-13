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
import javax.sound.midi.Sequence;

public class FileTransferProtocolServer {
	
	private PrivateKey serverPrivateKey;
	private long sessionKey, IV;
	private byte[] encryptionKey, integrityKey;
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

	public byte[] getIntegrityKey() {
		return integrityKey;
	}

	public void setIntegrityKey(byte[] integrityKey) {
		this.integrityKey = integrityKey;
	}

	public long generateRandomNonce() {
		
		SecureRandom random = new SecureRandom();
		return random.nextLong();
	}
	
	public void receiveFileFromClient(Socket socket, DataInputStream dis, DataOutputStream dos, String fileName) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		// Client uploads file to server
		
		int IVlength = dis.readInt();
		byte[] encryptedIV = new byte[IVlength];
		
		if(IVlength>0){
			dis.read(encryptedIV, 0, encryptedIV.length);
			long decryptedNonce = this.decrypted(this.getServerPrivateKey(), encryptedIV);
			this.setIV(decryptedNonce);
		}
		
		Mac sha256Hmac = Mac.getInstance(hashAlgorithm);
		SecretKeySpec secretKey = new SecretKeySpec(this.getEncryptionKey(),hashAlgorithm);
		sha256Hmac.init(secretKey);
		
		Mac integrityHmac = Mac.getInstance(hashAlgorithm);
		SecretKeySpec integritySecretKey = new SecretKeySpec(this.getIntegrityKey(), hashAlgorithm);
		integrityHmac.init(integritySecretKey);
		int encryptedDataLength = dis.readInt();
		
		File file = new File(fileName);
		FileOutputStream fos = new FileOutputStream(file);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		if(encryptedDataLength > 0) {
			byte[] encryptedBlockWithMac = new byte[encryptedDataLength];
			dis.read(encryptedBlockWithMac, 0, encryptedDataLength);
			byte[] integrityHmacArr = new byte[32];
			byte[] hmacArr = sha256Hmac.doFinal(encryptedIV);
			byte[] hashLong = new byte[encryptedDataLength - 32];
			for(int i = 0; i < hashLong.length; i++) {
				hashLong[i] = hmacArr[i%32];
			}
			byte[] cipherText = new byte[encryptedBlockWithMac.length - 32];
			
			cipherText = Arrays.copyOfRange(encryptedBlockWithMac, 0, cipherText.length);
			integrityHmacArr = Arrays.copyOfRange(encryptedBlockWithMac, cipherText.length,encryptedBlockWithMac.length);
			byte[] localIntegrityMacArr = integrityHmac.doFinal(cipherText);
			if(!Arrays.equals(localIntegrityMacArr, integrityHmacArr)) {
				dos.writeUTF("reject");
				bos.close();
				fos.close();
				file.delete();
			}
			else {
				dos.writeUTF("good");
			}
			byte[] encryptedBlock = cipherText;
			byte[] plainText = xor(cipherText, hashLong);
			byte[] seqNo = Arrays.copyOfRange(plainText, 0, 8);
			byte[] plainTextWithoutSeqNo = Arrays.copyOfRange(plainText, 8, plainText.length);
			long seqNoLong = this.bytesToLong(seqNo);
			this.setSequenceNumber(seqNoLong);
			bos.write(plainTextWithoutSeqNo);
			bos.flush();
			boolean changeKey = false;
			String exitStr = null;
			while(true) {
				try{
					exitStr = dis.readUTF();
				}catch(Exception e) {
					e.printStackTrace();
				}
				if(exitStr != null && exitStr.equals("close")) {
					break;
				}
				changeKey = dis.readBoolean();
				if(changeKey) {
					receiveNonce(dis);
					encryptionKey = this.getEncryptionKey();
					secretKey = new SecretKeySpec(encryptionKey, hashAlgorithm);
					integritySecretKey = new SecretKeySpec(this.getIntegrityKey(), hashAlgorithm);
					sha256Hmac.init(secretKey);
					integrityHmac.init(integritySecretKey);
				}
				encryptedDataLength = dis.readInt();
				if(encryptedDataLength > 0) {
					byte[] cipherTextWithMac = new byte[encryptedDataLength];
					dis.read(cipherTextWithMac, 0, encryptedDataLength);
					cipherText = Arrays.copyOfRange(cipherTextWithMac,0, cipherTextWithMac.length - 32);
					byte[] integrityMacArr = Arrays.copyOfRange(cipherTextWithMac, cipherTextWithMac.length - 32, cipherTextWithMac.length);
					localIntegrityMacArr = integrityHmac.doFinal(cipherText);
					if(!Arrays.equals(localIntegrityMacArr, integrityMacArr)){
						break;
					}
					hmacArr = sha256Hmac.doFinal(encryptedBlock);	
					for(int i = 0; i < cipherText.length; i++) {
						hashLong[i] = hmacArr[i%32];
					}
					plainText = xor(cipherText, hashLong);
					seqNo = Arrays.copyOfRange(plainText, 0, 8);
					seqNoLong = this.bytesToLong(seqNo);
					if(!changeKey && seqNoLong - this.getSequenceNumber() != encryptedBlock.length) {
						FileServer.showMessage("Invalid sequence number, rejecting transfer");
						dos.writeUTF("reject");
						bos.close();
						fos.close();
						file.delete();
						break;
					}
					else{
						this.setSequenceNumber(seqNoLong);
						plainTextWithoutSeqNo = Arrays.copyOfRange(plainText, 8, plainText.length);
						bos.write(plainTextWithoutSeqNo, 0, plainTextWithoutSeqNo.length);
						bos.flush();
						encryptedBlock = cipherText;
						dos.writeUTF("good");
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
			byte[] fileByte = new byte[1024];
			int bytesRead = bis.read(fileByte, 0 , fileByte.length);
			if(bytesRead > 0) {
				byte[] seqNoBytes = this.longToBytes(currentSeqNo);
				
				byte[] seqNoWithFileData = new byte[bytesRead + seqNoBytes.length];
				System.arraycopy(seqNoBytes, 0, seqNoWithFileData, 0, seqNoBytes.length);
				System.arraycopy(fileByte, 0, seqNoWithFileData, seqNoBytes.length, bytesRead);
				
				Mac sha256HashMac = Mac.getInstance(hashAlgorithm);
				SecretKeySpec secretKey = new SecretKeySpec(this.getEncryptionKey(), hashAlgorithm);
				sha256HashMac.init(secretKey);
				
				Mac integrityMac = Mac.getInstance(hashAlgorithm);
				SecretKeySpec integritySecretKey = new SecretKeySpec(this.getIntegrityKey(),hashAlgorithm);
				integrityMac.init(integritySecretKey);
				
				byte[] hashArr = sha256HashMac.doFinal(encryptedIV);
				byte[] hashLong = new byte[seqNoWithFileData.length];
				for(int i = 0; i < hashLong.length; i++) {
					hashLong[i] = hashArr[i%32];
				}
				byte[] xored = xor(seqNoWithFileData, Arrays.copyOfRange(hashLong,0, seqNoWithFileData.length));
				byte[] integrityHmacArr = integrityMac.doFinal(Arrays.copyOfRange(xored, 0, seqNoWithFileData.length));
				
				byte[] xoredWithMacArr = new byte[xored.length + integrityHmacArr.length]; 
				System.arraycopy(xored, 0, xoredWithMacArr,0, seqNoWithFileData.length);
				System.arraycopy(integrityHmacArr, 0, xoredWithMacArr, seqNoWithFileData.length, integrityHmacArr.length);
				dos.writeInt(seqNoWithFileData.length + integrityHmacArr.length);
				dos.write(xoredWithMacArr, 0, seqNoWithFileData.length + integrityHmacArr.length);
				String goodData = dis.readUTF();
				boolean transferDone = true;
				if(goodData.equals("good")) {
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
							encryptionKey = this.getEncryptionKey();
							
							seqNoBytes = this.longToBytes(currentSeqNo);
							
							seqNoWithFileData = new byte[bytesRead + seqNoBytes.length];
							System.arraycopy(seqNoBytes, 0, seqNoWithFileData, 0, seqNoBytes.length);
							System.arraycopy(fileByte, 0, seqNoWithFileData, seqNoBytes.length, bytesRead);
							
							hashArr = sha256HashMac.doFinal(xored);
							for(int i = 0; i < seqNoWithFileData.length; i++) {
								hashLong[i] = hashArr[i%32];
							}
							xored = xor(seqNoWithFileData, Arrays.copyOfRange(hashLong, 0,seqNoWithFileData.length));
							integrityHmacArr = integrityMac.doFinal(Arrays.copyOfRange(xored, 0, seqNoWithFileData.length));
							
							System.arraycopy(xored, 0, xoredWithMacArr, 0, seqNoWithFileData.length);
							System.arraycopy(integrityHmacArr, 0, xoredWithMacArr,seqNoWithFileData.length, integrityHmacArr.length);
							dos.writeInt(seqNoWithFileData.length + integrityHmacArr.length);
							dos.write(xoredWithMacArr, 0 ,seqNoWithFileData.length + integrityHmacArr.length);
							if(!((goodData = dis.readUTF()).equals("good"))){
								FileServer.showMessage("\nError in file transfer!");
								transferDone = false;
								break;
							}
						}
					}
					if(transferDone) {
						FileServer.showMessage("\n File transfer completed successfully");
					}
					dos.writeUTF("close");
				}
				else {
					FileServer.showMessage("\nError in file transfer");
				}
			}
			bis.close();
		}
	}
		
	
	public long decrypted(PrivateKey key, byte[] encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//Decrypt the once
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
	
	public long getEncryptionNonce(long sessionKey) {
		if(sessionKey > 0) {
			return sessionKey - 1;
		}
		return sessionKey + 1;
	}
	public long getIntegrityNonce(long sessionKey) {
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
			this.setIntegrityKey(this.longToBytes(this.getIntegrityNonce(decryptedNonce)));
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
		 this.setIntegrityKey(this.longToBytes(this.getIntegrityNonce(this.getSessionKey())));
		 dos.writeBoolean(true);
		 sendNonceToClient(this.getSessionKey(), dos);
	}
}
