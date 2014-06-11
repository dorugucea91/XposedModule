package test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Random;

import android.util.Log;

public class DiffieHellman {
	private BigInteger P, G, X, b, y, k_b;
	private String decoded, yStr;
	private OutputStream os;
	private InputStream is;
	Socket socket;
	
	public DiffieHellman(Socket socket) {
		this.socket = socket;
	}
	
	public void negociate() throws IOException {
		byte[] buffer = new byte[1024];
		Integer bytesRead;
		os = socket.getOutputStream();
		is = socket.getInputStream();
		
		/* get P parameter */	
		bytesRead = is.read(buffer, 0, 513);
		if (bytesRead == -1) {
			Log.e("error reading ", bytesRead.toString());
			throw new IOException();
		}
		if (bytesRead != 513) {
			Log.e("P parameter, length", bytesRead.toString());
			throw new IOException();
		}
        decoded = new String(buffer, 0, bytesRead -1, "UTF-8");
        P = new BigInteger(decoded, 16);
		
		/* get G parameter */	
		bytesRead = is.read(buffer, 0, 3);
		if (bytesRead == -1) {
			Log.e("error reading ", bytesRead.toString());
			throw new IOException();
		}
		if (bytesRead != 3) {
			Log.e("G paramter, length", bytesRead.toString());
			throw new IOException();
		}
        String decoded = new String(buffer, 0, bytesRead -1, "UTF-8");
        G = new BigInteger(decoded, 16);
     
        /* get X parameter */	
		bytesRead = is.read(buffer, 0, 513);
		if (bytesRead == -1) {
			Log.e("error reading ", bytesRead.toString());
			throw new IOException();
		}
		if (bytesRead != 513) {
			Log.e("X paramter, length", bytesRead.toString());
			throw new IOException();
		}
        decoded = new String(buffer, 0, bytesRead -1, "UTF-8");
        X = new BigInteger(decoded, 16);
        
        /* generate big random value < p -1 */
        b = nextRandomBigInteger(P);
        
        /* y = g^b mod p */
        y = G.modPow(b, P);
        yStr = y.toString(16);
        os.write(yStr.getBytes());
        
        /* k_b = x^b mod p */
        setKey(X.modPow(b, P));
	}
	
	public BigInteger nextRandomBigInteger(BigInteger n) {
	    Random rand = new Random();
	    BigInteger result = new BigInteger(n.bitLength(), rand);
	    while( result.compareTo(n) >= 0 ) {
	        result = new BigInteger(n.bitLength(), rand);
	    }
	    return result;
	}

	public BigInteger getKey() {
		return k_b;
	}

	public void setKey(BigInteger k_b) {
		this.k_b = k_b;
	}
}
