package test;

import java.io.InputStream;
import java.io.OutputStream;

public class Streams {
	private InputStream cryptIs;
	private OutputStream cryptOs;
	
	public Streams(InputStream is, OutputStream os) {
		this.setCryptIs(is);
		this.setCryptOs(os);
	}

	public InputStream getCryptIs() {
		return cryptIs;
	}

	public void setCryptIs(InputStream cryptIs) {
		this.cryptIs = cryptIs;
	}

	public OutputStream getCryptOs() {
		return cryptOs;
	}

	public void setCryptOs(OutputStream cryptOs) {
		this.cryptOs = cryptOs;
	}
}
