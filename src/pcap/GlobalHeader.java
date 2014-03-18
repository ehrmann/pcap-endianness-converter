package pcap;

import java.nio.ByteBuffer;

public class GlobalHeader {

	// See http://wiki.wireshark.org/Development/LibpcapFileFormat
	
	public static final int GLOBAL_HEADER_SIZE = 24;
	public static final int MAGIC_NUMBER = 0xa1b2c3d4;
	
    public final int magicNumber;
    public final short versionMajor;
    public final short versionMinor;
    public final int  thisZone;
    public final int sigFigs;
    public final int snapLen;
    public final int network;

    public GlobalHeader(ByteBuffer buffer) throws PCAPParseException {
    	this.magicNumber = buffer.getInt();
    	this.versionMajor = buffer.getShort();
    	this.versionMinor = buffer.getShort();
    	this.thisZone = buffer.getInt();
    	this.sigFigs = buffer.getInt();
    	this.snapLen = buffer.getInt();
    	this.network = buffer.getInt();
    	
    	if (this.magicNumber != MAGIC_NUMBER) {
    		throw new PCAPParseException("Bad magic number");
    	}
    	if (this.getVersionMajor() != 2 || this.getVersionMinor() != 4) {
    		throw new PCAPParseException(String.format("Unsupported version: %d.%d", this.getVersionMajor(), this.getVersionMinor()));
    	}
    }
    
    public void putToByteBuffer(ByteBuffer buffer) {
    	buffer.putInt(this.magicNumber);
    	buffer.putShort(this.versionMajor);
    	buffer.putShort(this.versionMinor);
    	buffer.putInt(this.thisZone);
    	buffer.putInt(this.sigFigs);
    	buffer.putInt(this.snapLen);
    	buffer.putInt(this.network);
    }
    
    public long getSnaplen() {
    	return this.snapLen & 0xffffffff;
    }
    
    public int getVersionMajor() {
    	return this.versionMajor & 0xffff;
    }
    
    public int getVersionMinor() {
    	return this.versionMinor & 0xffff;
    }
}
