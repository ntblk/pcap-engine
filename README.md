
## pcap-engine

Core ring-buffer infrastructure for PCAP network traffic collection and extraction pipelines

## Synopsis

<img src="https://netblocks.org/netblocks.png" width="100px" align="right" />

pcap-engine provides a ring-buffer pipeline and extraction facilities for the collection of streaming
network packet capture data. It is built around the [libpcap file format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
and exposes core functionality that can be used to build a digital forensic capability into metrics/measurement systems or to otherwise automate capture and classification of network traffic.

In conjunction with the [http-measurement-agent](https://github.com/ntblk/http-measurement-agent) this module can be used to compose an automatic packet capture collection pipeline for http agent requests and responses, a technique that's used at the core of the NetBlocks measurement stack.

This package is maintained as part of the the [NetBlocks.org](https://netblocks.org) network observation framework.

## Implementation notes

The library collects and processes network data using the [Wireshark](https://www.wireshark.org/) command-line utilities by default and can alternatively support classic [tcpdump](http://www.tcpdump.org/) utilities. Additional processing is done using a lightweight implementation of the libpcap format. Input and output are specified to be interoperable with standard network analysis tools.

```C
typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
```

## Status

pcap-engine is part of an ongoing research project; hence the interfaces are subject to change and ongoing improvement. We do not yet recommend integration into third-party software projects or production use.
