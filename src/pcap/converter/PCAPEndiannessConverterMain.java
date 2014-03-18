package pcap.converter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteOrder;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import pcap.PCAPParseException;
import pcap.converter.PCAPEndiannessConverter.Stats;

public class PCAPEndiannessConverterMain {

	protected static final Map<String, ByteOrder> CLI_TO_ORDER;
	static {
		Map<String, ByteOrder> cliToOrder = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
		
		cliToOrder.put("big-endian", ByteOrder.BIG_ENDIAN);
		cliToOrder.put("big_endian", ByteOrder.BIG_ENDIAN);
		cliToOrder.put("be", ByteOrder.BIG_ENDIAN);
		
		cliToOrder.put("little-endian", ByteOrder.LITTLE_ENDIAN);
		cliToOrder.put("little_endian", ByteOrder.LITTLE_ENDIAN);
		cliToOrder.put("le", ByteOrder.LITTLE_ENDIAN);
		
		CLI_TO_ORDER = Collections.unmodifiableMap(cliToOrder);
	}
	
	public static void main(String[] args) {
		if (args.length != 3 || !CLI_TO_ORDER.containsKey(args[0])) {
			System.err.println("Usage: <app command> big-endian|little-endian|be|le <outfile pcap> <infile pcap>");
			System.exit(-1);
		}
		
		ByteOrder order = CLI_TO_ORDER.get(args[0]);
		String inputFile = args[2];
		String outputFile = args[1];
		
		try (InputStream in = new FileInputStream(inputFile)) {
			try (OutputStream out = new FileOutputStream(outputFile)) {
				
				PCAPEndiannessConverter converter = new PCAPEndiannessConverter(out, in, order);
				Stats stats = converter.convert();
				
				System.err.printf("Records converted: %d", stats.converted);
				System.err.printf("Records ignored: %d", stats.ignored);
				
			} catch (FileNotFoundException e) {
				System.err.println("Unable to open output file '" + outputFile + "': " + e.getMessage());
				System.exit(-2);
			} catch (PCAPParseException e) {
				System.err.println("PCAP parsing error: " + e.getMessage());
				System.exit(-5);
			}
		} catch (FileNotFoundException e) {
			System.err.println("Unable to open input file '" + inputFile + "': " + e.getMessage());
			System.exit(-3);
		} catch (IOException e) {
			System.err.println("IOException: " + e.getLocalizedMessage());
			System.exit(-4);
		}
	}

}
