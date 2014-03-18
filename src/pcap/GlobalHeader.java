package pcap;

import java.nio.ByteBuffer;

public class GlobalHeader {

	public static final int GLOBAL_HEADER_SIZE = 24;
	public static final int MAGIC_NUMBER = 0xa1b2c3d4;
	
    public final int magic_number;
    public final short version_major;
    public final short version_minor;
    public final int  thiszone;
    public final int sigfigs;
    public final int snaplen;
    public final int network;

    public GlobalHeader(ByteBuffer buffer) throws PCAPParseException {
    	this.magic_number = buffer.getInt();
    	this.version_major = buffer.getShort();
    	this.version_minor = buffer.getShort();
    	this.thiszone = buffer.getInt();
    	this.sigfigs = buffer.getInt();
    	this.snaplen = buffer.getInt();
    	this.network = buffer.getInt();
    	
    	if (this.magic_number != MAGIC_NUMBER) {
    		throw new PCAPParseException("Bad magic number");
    	}
    }
    
    public void putToByteBuffer(ByteBuffer buffer) {
    	buffer.putInt(this.magic_number);
    	buffer.putShort(this.version_major);
    	buffer.putShort(this.version_minor);
    	buffer.putInt(this.thiszone);
    	buffer.putInt(this.sigfigs);
    	buffer.putInt(this.snaplen);
    	buffer.putInt(this.network);
    }
}
