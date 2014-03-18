package pcap.converter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

import pcap.GlobalHeader;
import pcap.PCAPParseException;
import pcap.RecordHeader;

public class PCAPEndiannessConverter {
	
	// This is ~100x larger than a Jumbo Frame
	protected final int MAX_RECORD_SIZE = 1024 * 1024;
	
	protected final OutputStream out;
	protected final PushbackInputStream in;
	
	protected final ByteOrder outOrder;

	public PCAPEndiannessConverter(OutputStream out, InputStream in, ByteOrder outOrder) {
		this.out = Objects.requireNonNull(out, "out was null");
		this.in = new PushbackInputStream(Objects.requireNonNull(in, "in was null"), 1);
		this.outOrder = Objects.requireNonNull(outOrder, "outOrder was null");
	}
	
	public Stats convert() throws IOException, PCAPParseException {

		GlobalHeaderWithByteOrder globalHeaderWithByteOrder = readGlobalHeader();
		writeGlobalHeader(globalHeaderWithByteOrder.globalHeader, this.outOrder);
		
		long converted = 0;
		long ignored = 0;
		
		byte[] buffer = new byte[MAX_RECORD_SIZE];
		
		int peek;
		while ((peek = this.in.read()) >= 0) {
			this.in.unread(peek);
			
			RecordHeader recordHeader = readRecordHeader(globalHeaderWithByteOrder.order);
			
			if (recordHeader.incl_len > MAX_RECORD_SIZE) {
				ignored++;
				
				long totalRead = 0;
				int read;
				while ((read = this.in.read(buffer, 0, (int)Math.min(recordHeader.incl_len - totalRead, buffer.length))) >= 0) {
					totalRead += read;
				}
			} else {
				int offset = 0;
				int read;
				while (recordHeader.incl_len - offset > 0 && (read = this.in.read(buffer, offset, recordHeader.incl_len - offset)) >= 0) {
					offset += read;
				}
				
				// Incomplete read, i.e. EOF
				if (offset < recordHeader.incl_len) {
					ignored++;
				}
				// Complete read
				else {
					converted++;
					this.writeRecordHeader(recordHeader, this.outOrder);
					out.write(buffer, 0, offset);
				}
			}
		}
		
		return new Stats(converted, ignored);
	}
	
	private GlobalHeaderWithByteOrder readGlobalHeader() throws PCAPParseException, IOException {
		ByteBuffer buffer = ByteBuffer.allocate(GlobalHeader.GLOBAL_HEADER_SIZE);
		fillBuffer(buffer, in);
		
		if (buffer.hasRemaining()) {
			throw new PCAPParseException("No PCAP global header");
		}

		buffer.flip();
		
		buffer.mark();
		buffer.order(ByteOrder.BIG_ENDIAN);
		
		try {
			return new GlobalHeaderWithByteOrder(new GlobalHeader(buffer), ByteOrder.BIG_ENDIAN);
		} catch (PCAPParseException e) { }
		
		buffer.reset();
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		
		return new GlobalHeaderWithByteOrder(new GlobalHeader(buffer), ByteOrder.LITTLE_ENDIAN);
	}
	
	private RecordHeader readRecordHeader(ByteOrder byteOrder) throws PCAPParseException, IOException {
		ByteBuffer buffer = ByteBuffer.allocate(RecordHeader.RECORD_HEADER_SIZE);
		fillBuffer(buffer, in);
		
		if (buffer.hasRemaining()) {
			throw new PCAPParseException("No PCAP record header");
		}
		
		buffer.flip();
		buffer.order(byteOrder);
		
		return new RecordHeader(buffer);
	}
	
	private void writeGlobalHeader(GlobalHeader header, ByteOrder order) throws IOException {
		ByteBuffer buffer = ByteBuffer.allocate(GlobalHeader.GLOBAL_HEADER_SIZE);
		buffer.order(order);
		header.putToByteBuffer(buffer);
		buffer.flip();
		this.out.write(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
	}
	
	private void writeRecordHeader(RecordHeader header, ByteOrder order) throws IOException {
		ByteBuffer buffer = ByteBuffer.allocate(RecordHeader.RECORD_HEADER_SIZE);
		buffer.order(order);
		header.putToByteBuffer(buffer);
		buffer.flip();
		this.out.write(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining());
	}
	
	private static class GlobalHeaderWithByteOrder {
		public final GlobalHeader globalHeader;
		public final ByteOrder order;
		
		public GlobalHeaderWithByteOrder(GlobalHeader globalHeader, ByteOrder byteOrder) {
			this.globalHeader = Objects.requireNonNull(globalHeader);
			this.order = Objects.requireNonNull(byteOrder);
		}
	}
	
	public static void fillBuffer(ByteBuffer buffer, InputStream in) throws IOException {
		byte[] temp = new byte[4096];
		int read;
		
		while (buffer.hasRemaining() && (read = in.read(temp, 0, buffer.remaining())) >= 0) {
			buffer.put(temp, 0, read);
		}
	}
	
	public static class Stats {
		public final long converted;
		public final long ignored;
		
		public Stats(long converted, long ignored) {
			this.converted = converted;
			this.ignored = ignored;
		}
	}
	
}

