package test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import android.util.Log;

public class AES {
	private Socket socket;
	private OutputStream outputStream;
	private InputStream inputStream;
	private BigInteger dhmKey;
	private Cipher cipher, cypherDecrypt;
	private MessageDigest md;
	private int newSize, alignSize, totalSize, 
			headerSize, payloadSize, bufSize;
	private byte[] header, buf, payloadBuf, md5; 
	private int TOTAL_SIZE, ALIGN_SIZE, MD5_SIZE;
	private int bufferedSize, transferredBytes;
	
	private byte[] IV;
	private AlgorithmParameterSpec IVSpec;
	private SecretKeySpec skeySpec;
	
	public AES(Socket socket) {
		this.socket = socket;
		headerSize = 32;
		header = new byte[headerSize];
		md5 = new byte[16];
		TOTAL_SIZE = 8;
		ALIGN_SIZE = 8;
		MD5_SIZE = 16;
	}
	
	public void setDhmKey(BigInteger key) throws NoSuchAlgorithmException {
		this.dhmKey = key;
		md = MessageDigest.getInstance("MD5");
	}
	
	public void setOuputStream() throws IOException {
		this.outputStream = socket.getOutputStream();
	}
	
	public void setInputStream() throws IOException {
		this.inputStream = socket.getInputStream();
	}
	
	public void initAESEncryption() throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	UnsupportedEncodingException, InvalidAlgorithmParameterException {
		byte[] key = dhmKey.toByteArray();
		byte[] cleanKey = new byte[256];
		byte[] aesKey = new byte[32];
		
		/* clean dhm key */
		if (key[0] == (byte) 0x00) {
			cleanKey = Arrays.copyOfRange(key, 1, 257);
		}
		else
			cleanKey = key;
	     
		/* initialization vector */
		IV = md.digest(cleanKey);
		
		/* aes key */
		aesKey = Arrays.copyOfRange(cleanKey, 0, 32);
		
		setSkeySpec(new SecretKeySpec(aesKey, "AES"));
		cipher = Cipher.getInstance("AES/CBC/NOPADDING");
		setIVSpec(new IvParameterSpec(IV));
	    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, getIVSpec());
}
	
	public void initAESDecryption() throws 
		InvalidKeyException, InvalidAlgorithmParameterException, 
		NoSuchAlgorithmException, NoSuchPaddingException {
		cypherDecrypt = Cipher.getInstance("AES/CBC/NOPADDING");
		cypherDecrypt.init(Cipher.DECRYPT_MODE, skeySpec, getIVSpec());
	}

	public int write(byte[] b, int off, int len) throws IOException {
		/* make len divisible by 16 for AES */
		if ((len % 16) != 0) {
			newSize = roundUp(len, 16);
			alignSize = newSize - len;
		}
		else {
			newSize = len;
			alignSize = 0;
		}
		
		totalSize = newSize + TOTAL_SIZE + ALIGN_SIZE + MD5_SIZE;
		if ((bufSize == 0) || (bufSize < totalSize)) {
			buf = new byte[totalSize];
			bufSize = totalSize;
		}
		if ((payloadSize == 0) || (payloadSize != newSize)) {
			payloadBuf = new byte[newSize];
			payloadSize = newSize;
		}
		
		Arrays.fill(buf, (byte)0x00);
		Arrays.fill(payloadBuf, (byte)0x00);
		System.arraycopy(b, 0, payloadBuf, 0, len);
		
		/* get crc */
		md5 = md.digest(payloadBuf);
		/* get sizes */
		String sizes = String.format("%d %d", newSize, alignSize);
		byte[] sizesByte = sizes.getBytes();
		/* encrypt data */
		try {
			payloadBuf = cipher.doFinal(payloadBuf);
		} catch (BadPaddingException e) {
	 			Log.e("decrypt", "Bad Padding");
				e.printStackTrace();
				throw new IOException();
	 	} catch (IllegalBlockSizeException e) {
	 			Log.e("decrypt", "Illegal Block");
				e.printStackTrace();
				throw new IOException();
	 	}
		
		/* transfer data */
		System.arraycopy(payloadBuf, 0,
				buf, TOTAL_SIZE + ALIGN_SIZE + MD5_SIZE, newSize);
		/* transfer md5 */
		System.arraycopy(md5, 0, buf, TOTAL_SIZE + ALIGN_SIZE, 16);
		/* transfer sizes */
		System.arraycopy(sizesByte, 0, buf, 0, sizesByte.length);
		
		/* send data */
		outputStream.write(buf, 0, totalSize);
		
		return len;
	}
	
	public int read(byte[] b, int off, int len) throws IOException {
 		Integer ret;
 		String decoded;
 		Scanner scanner = null;
 		if (bufferedSize == 0) {
 			/* receive header */
 	 		ret = inputStream.read(header, 0, headerSize);
 	 		if (ret == -1)
 	 			return ret;
 	 		if (ret != headerSize) {
 	 			Log.e("error reading header", ret.toString());
 	 			throw new IOException();
 	 		}
 	 		decoded = new String(header, "UTF-8");
	 	    scanner = new Scanner(decoded);
 	 		/* get total size and align size*/
 	 		 try {	
 	 	 		totalSize = scanner.nextInt();
 	 	 		alignSize = scanner.nextInt();
 	 	 	} catch (InputMismatchException e) {
 	 	 		Log.e("header", "corrupt");
 	 	 		e.printStackTrace();
 	 	 	}
 	 		scanner.close();
 	 		/* adjust receive buffer */
 	 		if ((bufSize == 0) || (bufSize < totalSize)) {
 	 			buf = new byte[totalSize];
 	 			bufSize = totalSize;
 	 		}
 	 		
 	 		/* receive data */
 	 		ret = inputStream.read(buf, 0, totalSize);
 	 		if (ret.compareTo(totalSize) == 1) {
 	 			Log.e("error reading data", ret.toString());
 	 			throw new IOException();
 	 		}
 	 		bufferedSize = totalSize - alignSize;
 	 		try {
 	 			buf = cypherDecrypt.doFinal(buf, 0, totalSize);
 	 			if (checkCrc(header, buf) == 0) {
 	 				Log.e("crc", "corrupt crc");
 	 				throw new IOException();
 	 			}
 	 			decoded = new String(buf, 0, bufferedSize, "UTF-8");
 	 		} catch (BadPaddingException e) {
 	 			Log.e("decrypt", "Bad Padding");
 				e.printStackTrace();
 				throw new IOException();
 	 		} catch (IllegalBlockSizeException e) {
 	 			Log.e("decrypt", "Illegal Block");
 				e.printStackTrace();
 				throw new IOException();
 	 		}
 		}
 		if (bufferedSize > len) {
 			System.arraycopy(buf, transferredBytes, b, 0, len);
 			bufferedSize -= len;
 			transferredBytes += len;
 			ret = len;
 		}
 		else {
 			System.arraycopy(buf, transferredBytes, b, 0, bufferedSize);
 			ret = bufferedSize;
 			bufferedSize = 0;
 			transferredBytes = 0;
 		}
 		return ret;
 	}
	
	private Integer checkCrc(byte[] header, byte[] data) {
 		byte[] headerCrc = new byte[16];
 		byte[] calcCrc = new byte[16];
 		
 		/* get crc */
 		System.arraycopy(header, 16, headerCrc, 0, 16);
 		calcCrc = md.digest(data);
 	 		
 		if (Arrays.equals(headerCrc, calcCrc) == true)
 			return 1;
 	
 		return 0;
 	}
	
	public void close() throws IOException {
		outputStream.close();
	}
	
	int roundUp(int numToRound, int multiple) { 
		if(multiple == 0) { 
	  		return numToRound; 
	 	} 

	 	int remainder = numToRound % multiple;
	 	if (remainder == 0)
	  		return numToRound;
	 	return numToRound + multiple - remainder;
	} 	
	
	public void setSkeySpec(SecretKeySpec skeySpec) {
		this.skeySpec = skeySpec;
	}
	
	public SecretKeySpec getSkeySpec() {
		return this.skeySpec;
	}

	public void setIVSpec(AlgorithmParameterSpec iVSpec) {
		IVSpec = iVSpec;
	}
	
	public AlgorithmParameterSpec getIVSpec() {
		return IVSpec;
	}
}
