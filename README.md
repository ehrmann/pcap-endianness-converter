pcap endianness converter
=========================

Tool for converter pcap capture files between endiannesses. It's useful for working with buggy tools that only support one endianness.

## Usage

```
java -jar pcap-endianness-converter.jar big-endian|little-endian|be|le <outfile pcap> <infile pcap>
```

Or put ```pcap-endianness-converter.jar``` in ```~/bin``` and create ```~/bin/pcap-endianness-converter``` as follows:

```
#! /bin/sh

/usr/local/bin/java -jar "${basedir}/pcap-endianness-converter.jar" "$@"
```
