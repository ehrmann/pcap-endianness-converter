package pcap;

public class PCAPParseException extends Exception {

	private static final long serialVersionUID = -4536230483458921483L;

	public PCAPParseException() {
		super();
	}

	public PCAPParseException(String message, Throwable cause) {
		super(message, cause);
	}

	public PCAPParseException(String message) {
		super(message);
	}

	public PCAPParseException(Throwable cause) {
		super(cause);
	}
}
