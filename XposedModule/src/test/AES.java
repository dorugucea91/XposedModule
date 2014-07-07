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
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.util.Log;

public class AES {
	private Socket socket;
	private InputStream inputStream;
	private OutputStream outputStream;
	private BigInteger dhmKey;
	private SecretKeySpec skeySpec;
	private Cipher cipher, cypherDecrypt;
	private Scanner scanner;
	private Integer headerModifiedSize, ret;
	private MessageDigest md;
	private AlgorithmParameterSpec IVSpec;
	
	private byte[] headerModified, headerClean, md5Header, buf, IV, sizesByte;
	private int PAYLOAD_SIZE, ALIGN_SIZE, MD5_SIZE, FLAG_SIZE, MD5_OFFSET_M;
	private int newPayloadSize, remainingSize, flag, offset;
	private int bufSize, bufferedSize, transferredBytes, payloadSize, alignSize,
	 			headerCleanSize;
	private int bufSizeW, bufferedSizeW, newSizeW, newBufferedSizeW, alignSizeW, 
				modifiedLenW, offsetW, sendSizeW;
	private int newSize, totalSize;
	
	public AES(Socket socket) {
		this.socket = socket;
		PAYLOAD_SIZE = 5;
		ALIGN_SIZE = 2;
		MD5_SIZE = 16;
		FLAG_SIZE = 1;
		MD5_OFFSET_M = FLAG_SIZE + PAYLOAD_SIZE + ALIGN_SIZE + MD5_SIZE;
		headerModifiedSize = PAYLOAD_SIZE + ALIGN_SIZE + MD5_SIZE + FLAG_SIZE;
		headerModified = new byte[headerModifiedSize];
		headerCleanSize = FLAG_SIZE + MD5_SIZE;
		headerClean = new byte[headerCleanSize];
		md5Header = new byte[MD5_SIZE];
		flag = 1;
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
		setIV(md.digest(cleanKey));
		
		/* aes key */
		aesKey = Arrays.copyOfRange(cleanKey, 0, 32);
		
		setSkeySpec(new SecretKeySpec(aesKey, "AES"));
		cipher = Cipher.getInstance("AES/CBC/NOPADDING");
		setIVSpec(new IvParameterSpec(getIV()));
	    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, getIVSpec());
}
	
	public void initAESDecryption() throws 
		InvalidKeyException, InvalidAlgorithmParameterException, 
		NoSuchAlgorithmException, NoSuchPaddingException {
		cypherDecrypt = Cipher.getInstance("AES/CBC/NOPADDING");
		cypherDecrypt.init(Cipher.DECRYPT_MODE, skeySpec, getIVSpec());
	}
	
	public int write(byte[] b, int off, int len) throws IOException {
		int smaller_buf = 0;
		
		/* make len divisible by 16 for AES */
		if ((len % 16) != 0) {
			newSizeW = roundUp(len, 16);
			alignSizeW = newSizeW - len;
		}
		else {
			newSizeW = len;
			alignSizeW = 0;
		}
		
		newBufferedSizeW = newSizeW - alignSizeW;
		modifiedLenW = 0;
		if (bufSizeW == 0 || (bufferedSizeW != newBufferedSizeW)) {
			modifiedLenW = 1;
			if ((bufSizeW != 0) && (newBufferedSizeW < bufferedSizeW))
				smaller_buf = 1;
			totalSize = MD5_OFFSET_M + newSizeW;
			buf = new byte[totalSize];
			bufSizeW = totalSize;
			bufferedSizeW = newBufferedSizeW;
		}
		
		totalSize = bufSizeW;

		Arrays.fill(buf, (byte)0x00);		
		if (modifiedLenW == 0) {
			offsetW = FLAG_SIZE + MD5_SIZE;
			buf[0] = 0x30;
			sendSizeW = totalSize - PAYLOAD_SIZE - ALIGN_SIZE;
		}
		else {
			offsetW = MD5_OFFSET_M;
			String sizes = String.format("%d%d %d", 1, newSizeW, alignSizeW);
			sizesByte = sizes.getBytes();
			System.arraycopy(sizesByte, 0, buf, 0, sizesByte.length);
			sendSizeW = totalSize;
		}
		
		System.arraycopy(b, 0, buf, offsetW, len);
		md.update(buf, offsetW, newSizeW);
		System.arraycopy(md.digest(), 0, buf, offsetW - MD5_SIZE, MD5_SIZE);
		
		try {
			cipher.doFinal(buf, offsetW, newSizeW, buf, offsetW);
		} catch (ShortBufferException e) {
			e.printStackTrace();
			throw new IOException();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			throw new IOException();
		} catch (BadPaddingException e) {
			e.printStackTrace();
			throw new IOException();
		}
		
		outputStream.write(buf, 0, sendSizeW);
		if (smaller_buf == 1) 
			socket.getInputStream().read();
		
		return len;
	}

	public int read(byte[] b, int off, int len) throws IOException {
		/* 0 bytes buffered => read from socket */
		if (bufferedSize == 0) {
			/* first receive of data*/
			if (bufSize == 0) {
				ret = readAll(headerModified, 0, headerModifiedSize, 0);
				if (ret < 0)
					return ret;
				System.arraycopy(headerModified, MD5_OFFSET_M - MD5_SIZE,
								md5Header, 0, MD5_SIZE);
				setPayloadAlignSize(headerModified);
				offset = 0;
				buf = new byte[payloadSize + headerCleanSize];
				bufSize = payloadSize + headerCleanSize;
			}
			
			remainingSize = bufSize - flag * headerCleanSize;
			ret = readAll(buf, 0, remainingSize, 1);
			if (ret == -1)
				return ret;
			bufferedSize = payloadSize - alignSize;
	
			if (flag == 0) {
				offset = MD5_SIZE + FLAG_SIZE;
				/* consider that we receive a clean packet */
				System.arraycopy(buf, 0, headerClean, 0, headerCleanSize);
				
				if (headerClean[0] == (byte)0x30) 
					System.arraycopy(buf, FLAG_SIZE, md5Header, 0, MD5_SIZE);
				else {
					setPayloadAlignSize(headerClean);
					remainingSize = payloadSize  + MD5_OFFSET_M - bufSize;
					bufferedSize = payloadSize - alignSize;
					
					if (remainingSize > 0) {
						byte[] tempBuf = new byte[payloadSize + headerModifiedSize];
						System.arraycopy(buf, 0, tempBuf, 0, bufSize);
						ret = readAll(tempBuf, bufSize, remainingSize, 0);
						if (ret < 0 ) {
							scanner.close();
							return ret;
						}
						bufSize = payloadSize + headerCleanSize;
						buf = new byte[bufSize];
						System.arraycopy(tempBuf, MD5_OFFSET_M - MD5_SIZE , 
										md5Header, 0, MD5_SIZE);
						System.arraycopy(tempBuf, MD5_OFFSET_M, buf, 
										FLAG_SIZE + MD5_SIZE, newPayloadSize);
					}
					else {
						System.arraycopy(buf, MD5_OFFSET_M - MD5_SIZE, 
										md5Header, 0, MD5_SIZE);
						offset = MD5_OFFSET_M;
					}
				}
			}
			flag = 0;
			try {
				cypherDecrypt.doFinal(buf, offset, payloadSize, buf);
				md.update(buf, 0, payloadSize);
				if (Arrays.equals(md5Header, md.digest()) == false)
					throw new IOException();
				} catch (BadPaddingException e) {
					Log.e("decrypt", "Bad Padding");
					e.printStackTrace();
					throw new IOException();
				} catch (IllegalBlockSizeException e) {
					Log.e("decrypt", "Illegal Block");
					e.printStackTrace();
					throw new IOException();
				} catch (ShortBufferException e) {
					Log.e("decrypt", "Short Buffer");
					e.printStackTrace();
					throw new IOException();
				}
		}
		
		if (bufferedSize <= len) {
			System.arraycopy(buf, transferredBytes, b, 0, bufferedSize);
			ret = bufferedSize;
			bufferedSize = 0;
			transferredBytes = 0;
		}
		else {
			System.arraycopy(buf, transferredBytes, b, 0, len);
			bufferedSize -= len;
			transferredBytes += len;
			ret = len;
		} 
		return ret;
	}
	
	
	private void setPayloadAlignSize(byte[] headerModified) throws IOException { 
		String  payloadSizeS = new String(Arrays.copyOfRange(headerModified, FLAG_SIZE, 
				FLAG_SIZE + PAYLOAD_SIZE), "UTF-8");
		String alignSizeS = new String(Arrays.copyOfRange(headerModified, FLAG_SIZE + PAYLOAD_SIZE, 
				FLAG_SIZE + PAYLOAD_SIZE + ALIGN_SIZE), "UTF-8");
		
		/* get total size and align size */
		try {
			payloadSize = ((Number)NumberFormat.getInstance().parse(payloadSizeS)).intValue();
			alignSize = ((Number)NumberFormat.getInstance().parse(alignSizeS)).intValue();
		} catch (ParseException e) {
			e.printStackTrace();
			throw new IOException();
		}
	}
	
	private int readAll(byte[] b, int off, int totalSize, int checkLast) 
			throws IOException {
	
		int received = 0, realSize = 0, smallerBuf = 0;
		ret = 0;
		
		while (ret != totalSize) {
			received = inputStream.read(b, off + ret.intValue(), totalSize-ret);
			if (received == -1) {
				if (ret == 0)
					return -1;
				else {
					
					return ret;
				}
			}
			ret += received;
			
			if ((checkLast == 1) && (ret > (FLAG_SIZE + PAYLOAD_SIZE))) {
				if (b[0] == 0x31) {
					String realSizeS = new String(Arrays.copyOfRange(b, FLAG_SIZE, 
							FLAG_SIZE + PAYLOAD_SIZE), "UTF-8");
					
					try {
						realSize = ((Number)NumberFormat.getInstance().parse(realSizeS)).intValue();
					} catch (ParseException e) {
						// TODO Auto-generated catch block
						Log.e("real", realSizeS);
						throw new IOException();
					}
					
					realSize += headerModifiedSize;
					if (realSize < totalSize)
						smallerBuf = 1;
				}
				checkLast = 0;
			}	
			if ((smallerBuf == 1) && (realSize == ret)) {
				outputStream.write(0x00);
				return ret;
			}
		}	
		
		return ret;
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

	public byte[] getIV() {
		return IV;
	}
	
	public String getIVString() {
		return debug(IV, 16);
	}

	public void setIV(byte[] iV) {
		IV = iV;
	}
	
	public String debug (byte[] buf, int size) {
		String [] arr = new String[size];
	    for (int i = 0; i < size; i++) {
	       arr[i] = String.format("%02x", buf[i]);
	    }
	    return java.util.Arrays.toString(arr);
	}
	
}
