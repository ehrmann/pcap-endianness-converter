package pcap.converter;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;

import org.junit.Test;

import pcap.PCAPParseException;
import pcap.converter.PCAPEndiannessConverter.Stats;

public class PCAPEndiannessConverterTest {

	protected static final byte[] DATA_1500_0 = new byte[1500];
	protected static final byte[] DATA_1500_1 = new byte[1500];
	protected static final byte[] DATA_1500_2 = new byte[1500];
	
	protected static final byte[] DATA_64K_0 = new byte[0x10000];
	
	static {
		Random r = new Random(0);
		
		r.nextBytes(DATA_1500_0);
		r.nextBytes(DATA_1500_1);
		r.nextBytes(DATA_1500_2);
		
		r.nextBytes(DATA_64K_0);
	}
	
	protected static final byte[] CORRUPT_BE_GLOBAL_HEADER = new byte[] {
		(byte)0xa1, (byte)0xb1, (byte)0xc3, (byte)0xd4,
		0x00, 0x02,
		0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x50, 0x18,
		0x00, 0x00, 0x10, 0x00,
		0x00, 0x00, 0x10, 0x00,
	};
	protected static final byte[] BAD_VERSION_BE_GLOBAL_HEADER = new byte[] {
		(byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4,
		0x00, 0x02,
		0x00, 0x03,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x50, 0x18,
		0x00, 0x00, 0x10, 0x00,
		0x00, 0x00, 0x10, 0x00,
	};

	protected static final byte[] BE_4K_GLOBAL_HEADER = new byte[] {
		(byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4,
		0x00, 0x02,
		0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x50, 0x18,
		0x00, 0x00, 0x10, 0x00,
		0x00, 0x00, 0x10, 0x00,
	};

	protected static final byte[] LE_4K_GLOBAL_HEADER = new byte[] {
		(byte)0xd4, (byte)0xc3, (byte)0xb2, (byte)0xa1, 
		0x02, 0x00,
		0x04, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x18, 0x50, 0x00, 0x00,
		0x00, 0x10, 0x00, 0x00,
		0x00, 0x10, 0x00, 0x00,
	};

	protected static final byte[] LE_1500B_RECORD_HEADER = new byte[] {
		(byte)0xBA, (byte)0xA5, 0x28, 0x53,
		0x00, 0x00, 0x00, 0x00,
		(byte)0xdc, 0x05, 0x00, 0x00,
		(byte)0xdc, 0x05, 0x00, 0x00,
	};

	protected static final byte[] BE_1500B_RECORD_HEADER = new byte[] {
		0x53, 0x28, (byte)0xA5, (byte)0xBA,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x05, (byte)0xdc,
		0x00, 0x00, 0x05, (byte)0xdc,
	};

	protected static final byte[] LE_64K_RECORD_HEADER = new byte[] {
		(byte)0xBA, (byte)0xA5, 0x28, 0x53,
		0x00, 0x00, 0x00, 0x00,
		(byte)0x00, 0x00, 0x01, 0x00,
		(byte)0x00, 0x00, 0x01, 0x00,
	};

	protected static final byte[] BE_64K_RECORD_HEADER = new byte[] {
		0x53, 0x28, (byte)0xA5, (byte)0xBA,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00,
	};

	protected static byte[] concatenate(byte[][] arrays) {
		int length = 0;
		for (byte[] a : arrays) {
			length += a.length;
		}

		byte[] result = new byte[length];
		int offset = 0;
		for (byte[] a : arrays) {
			for (byte b : a) {
				result[offset++] = b;
			}
		}

		return result;
	}

	@Test(expected=PCAPParseException.class)
	public void testBadMagic() throws IOException, PCAPParseException {
		InputStream in = new ByteArrayInputStream(CORRUPT_BE_GLOBAL_HEADER);
		OutputStream out = new ByteArrayOutputStream();

		PCAPEndiannessConverter converter = new PCAPEndiannessConverter(out, in, BIG_ENDIAN);
		converter.convert();
	}

	@Test(expected=PCAPParseException.class)
	public void testUnrecognizedVersion() throws IOException, PCAPParseException {
		InputStream in = new ByteArrayInputStream(BAD_VERSION_BE_GLOBAL_HEADER);
		OutputStream out = new ByteArrayOutputStream();

		PCAPEndiannessConverter converter = new PCAPEndiannessConverter(out, in, BIG_ENDIAN);
		converter.convert();
	}

	@Test
	public void testBENop() throws IOException, PCAPParseException {
		InputStream in = new ByteArrayInputStream(BE_4K_GLOBAL_HEADER);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		PCAPEndiannessConverter converter = new PCAPEndiannessConverter(out, in, BIG_ENDIAN);
		Stats stats = converter.convert();

		assertArrayEquals(BE_4K_GLOBAL_HEADER, out.toByteArray());
		assertEquals(0, stats.converted);
		assertEquals(0, stats.ignored);
	}

	@Test
	public void testLENop() throws IOException, PCAPParseException {
		InputStream in = new ByteArrayInputStream(LE_4K_GLOBAL_HEADER);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		PCAPEndiannessConverter converter = new PCAPEndiannessConverter(out, in, LITTLE_ENDIAN);
		Stats stats = converter.convert();

		assertArrayEquals(LE_4K_GLOBAL_HEADER, out.toByteArray());
		assertEquals(0, stats.converted);
		assertEquals(0, stats.ignored);
	}

	@Test
	public void testBEToLE() throws IOException, PCAPParseException {
		byte[] input = concatenate(new byte[][] {
				BE_4K_GLOBAL_HEADER,
				BE_1500B_RECORD_HEADER,
				DATA_1500_0,
				BE_64K_RECORD_HEADER,
				DATA_64K_0,
				BE_1500B_RECORD_HEADER,
				DATA_1500_1,
				BE_1500B_RECORD_HEADER,
				DATA_1500_2,
				BE_1500B_RECORD_HEADER,
				new byte[3],
		});

		byte[] expected = concatenate(new byte[][] {
				LE_4K_GLOBAL_HEADER,
				LE_1500B_RECORD_HEADER,
				DATA_1500_0,
				LE_1500B_RECORD_HEADER,
				DATA_1500_1,
				LE_1500B_RECORD_HEADER,
				DATA_1500_2,
		});

		InputStream in = new ByteArrayInputStream(input);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		PCAPEndiannessConverter converter = new PCAPEndiannessConverter(out, in, LITTLE_ENDIAN);
		Stats stats = converter.convert();

		assertArrayEquals(expected, out.toByteArray());
		assertEquals(3, stats.converted);
		assertEquals(2, stats.ignored);
	}

	@Test
	public void testLEToBE() throws IOException, PCAPParseException {		
		byte[] input = concatenate(new byte[][] {
				LE_4K_GLOBAL_HEADER,
				LE_1500B_RECORD_HEADER,
				DATA_1500_0,
				LE_64K_RECORD_HEADER,
				DATA_64K_0,
				LE_1500B_RECORD_HEADER,
				DATA_1500_1,
				LE_1500B_RECORD_HEADER,
				DATA_1500_2,
				LE_1500B_RECORD_HEADER,
				new byte[3],
		});

		byte[] expected = concatenate(new byte[][] {
				BE_4K_GLOBAL_HEADER,
				BE_1500B_RECORD_HEADER,
				DATA_1500_0,
				BE_1500B_RECORD_HEADER,
				DATA_1500_1,
				BE_1500B_RECORD_HEADER,
				DATA_1500_2,
		});

		InputStream in = new ByteArrayInputStream(input);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		PCAPEndiannessConverter converter = new PCAPEndiannessConverter(out, in, BIG_ENDIAN);
		Stats stats = converter.convert();

		assertArrayEquals(expected, out.toByteArray());
		assertEquals(3, stats.converted);
		assertEquals(2, stats.ignored);
	}
	
	@Test
	public void testCleanup() throws IOException, PCAPParseException {
		byte[] input = concatenate(new byte[][] {
				LE_4K_GLOBAL_HEADER,
				LE_1500B_RECORD_HEADER,
				DATA_1500_0,
				LE_64K_RECORD_HEADER,
				DATA_64K_0,
				LE_64K_RECORD_HEADER,
				DATA_64K_0,
				LE_1500B_RECORD_HEADER,
				DATA_1500_1,
				LE_1500B_RECORD_HEADER,
				DATA_1500_2,
				LE_64K_RECORD_HEADER,
				DATA_64K_0,
				LE_1500B_RECORD_HEADER,
		});

		byte[] expected = concatenate(new byte[][] {
				LE_4K_GLOBAL_HEADER,
				LE_1500B_RECORD_HEADER,
				DATA_1500_0,
				LE_1500B_RECORD_HEADER,
				DATA_1500_1,
				LE_1500B_RECORD_HEADER,
				DATA_1500_2,
		});

		InputStream in = new ByteArrayInputStream(input);
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		PCAPEndiannessConverter converter = new PCAPEndiannessConverter(out, in, LITTLE_ENDIAN);
		Stats stats = converter.convert();

		assertArrayEquals(expected, out.toByteArray());
		assertEquals(3, stats.converted);
		assertEquals(4, stats.ignored);
	}
}
