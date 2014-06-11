package test;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class CryptInputStream extends InputStream {
	private Socket socket;
	private AES aes;
	
	public CryptInputStream(Socket socket, AES aes) {
		this.socket = socket;
		this.aes = aes;
	}

	@Override
	public int read() throws IOException {
		return socket.getInputStream().read();
	}
	
	@Override
	public int read(byte[] buffer, int offset, int length) throws IOException {
		return aes.read(buffer, offset, length);
	}
}
