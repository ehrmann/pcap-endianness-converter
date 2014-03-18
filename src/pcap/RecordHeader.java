package pcap;

import java.nio.ByteBuffer;

public class RecordHeader {
	
	// See http://wiki.wireshark.org/Development/LibpcapFileFormat

	public static final int RECORD_HEADER_SIZE = 16;
	
	public final int tsSec;
    public final int tsUSec;
    public final int inclLen;
    public final int origLen;

    public RecordHeader(ByteBuffer buffer) {
    	this.tsSec = buffer.getInt();
    	this.tsUSec = buffer.getInt();
    	this.inclLen = buffer.getInt();
    	this.origLen = buffer.getInt();
    }
    
    public void putToByteBuffer(ByteBuffer buffer) {
    	buffer.putInt(this.tsSec);
    	buffer.putInt(this.tsUSec);
    	buffer.putInt(this.inclLen);
    	buffer.putInt(this.origLen);
    }
    
    public long getInclLen() {
    	return this.inclLen & 0xffffffff;
    }
    
    public long getOrigLen() {
    	return this.origLen & 0xffffffff;
    }
}
