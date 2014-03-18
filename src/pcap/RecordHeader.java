package pcap;

import java.nio.ByteBuffer;

public class RecordHeader {

	public static final int RECORD_HEADER_SIZE = 16;
	
	public final int ts_sec;
    public final int ts_usec;
    public final int incl_len;
    public final int orig_len;

    public RecordHeader(ByteBuffer buffer) {
    	this.ts_sec = buffer.getInt();
    	this.ts_usec = buffer.getInt();
    	this.incl_len = buffer.getInt();
    	this.orig_len = buffer.getInt();
    }
    
    public void putToByteBuffer(ByteBuffer buffer) {
    	buffer.putInt(this.ts_sec);
    	buffer.putInt(this.ts_usec);
    	buffer.putInt(this.incl_len);
    	buffer.putInt(this.orig_len);
    }
    
    public long getInclLen() {
    	return this.incl_len & 0xffffffff;
    }
    
    public long getOrigLen() {
    	return this.orig_len & 0xffffffff;
    }
}
