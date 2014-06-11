package test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class CryptOutputStream extends OutputStream {
	private Socket socket;
	private AES aes;
	
	public CryptOutputStream(Socket socket, AES aes) {
		this.socket = socket;
		this.aes = aes;
	}
	
	@Override
	public void write(int arg0) throws IOException {
		socket.getOutputStream().write(arg0);
	}
	
	@Override
	public void write(byte[] buffer, int offset, int count) throws IOException {
		aes.write(buffer, offset, count);
	}
}
