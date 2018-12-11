#!/usr/bin/python3
import ctypes, struct

class FlagsBitsTCP(ctypes.LittleEndianStructure):
    _fields_ = [
            ("FIN", ctypes.c_uint16, 1),
            ("SYN", ctypes.c_uint16, 1),
            ("RST", ctypes.c_uint16, 1),
            ("PSH", ctypes.c_uint16, 1),
            ("ACK", ctypes.c_uint16, 1),
            ("URG", ctypes.c_uint16, 1),
            ("ECE", ctypes.c_uint16, 1),
            ("CWR", ctypes.c_uint16, 1),
            ("NS", ctypes.c_uint16, 1),
        ]
class FlagsTCP(ctypes.Union):
    # Flags (9 bits) (aka Control bits) Contains 9 1-bit flags
    FLAG_NS  = 1<<8 #(1 bit): ECN-nonce - concealment protection (experimental: see RFC 3540).
    FLAG_CWR = 1<<7 #(1 bit): Congestion Window Reduced (CWR) flag is set by the sending host to indicate that
        # it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
    FLAG_ECE = 1<<6 #(1 bit): ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
        # If the SYN flag is set #(1), that the TCP peer is ECN capable.
        # If the SYN flag is clear (0), that a packet with Congestion Experienced flag set (ECN=11) in the IP header was
        # received during normal transmission (added to header by RFC 3168). This serves as an indication of network
        # congestion (or impending congestion) to the TCP sender.
    FLAG_URG = 1<<5 #(1 bit): indicates that the Urgent pointer field is significant
    FLAG_ACK = 1<<4 #(1 bit): indicates that the Acknowledgment field is significant. All packets after the initial SYN
    # packet sent by the client should have this flag set.
    FLAG_PSH = 1<<3 #(1 bit): Push function. Asks to push the buffered data to the receiving application.
    FLAG_RST = 1<<2 #(1 bit): Reset the connection
    FLAG_SYN = 1<<1 #(1 bit): Synchronize sequence numbers. Only the first packet sent from each end should have this flag set.
    # Some other flags and fields change meaning based on this flag, and some are only valid when it is set, and others when it is clear.
    FLAG_FIN = 1<<0 #(1 bit): Last packet from sender.
    _fields_ = [("b", FlagsBitsTCP), ("asbyte", ctypes.c_uint16)]
    def __str__(self):
        return hex(self.asbyte) + ' ' + ', '.join([key for key, value in {
            'NS':   self.b.NS,
            'CWR':  self.b.CWR,
            'ECE':  self.b.ECE,
            'URG':  self.b.URG,
            'ACK':  self.b.ACK,
            'PSH':  self.b.PSH,
            'RST':  self.b.RST,
            'SYN':  self.b.SYN,
            'FIN':  self.b.FIN,
        }.items() if value])

class SegmentBitsTCP(ctypes.LittleEndianStructure):
    """
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Source Port          |       Destination Port        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Acknowledgment Number                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Data |           |U|A|P|R|S|F|                               |
        | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
        |       |           |G|K|H|T|N|N|                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Checksum            |         Urgent Pointer        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             data                              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #
                               TCP Header Format
        #
             Note that one tick mark represents one bit position.
        Data Offset:  4 bits
        Reserved:  6 bits
        Control Bits:  6 bits (from left to right):
            URG:  Urgent Pointer field significant
            ACK:  Acknowledgment field significant
            PSH:  Push Function
            RST:  Reset the connection
            SYN:  Synchronize sequence numbers
            FIN:  No more data from sender
        Window:  16 bits
        Checksum:  16 bits
        Urgent Pointer:  16 bits
    """
    _fields_ = [
            ("src_port", ctypes.c_uint32, 16),
            ("dst_port", ctypes.c_uint32, 16),
            ("sq", ctypes.c_uint32, 32),
            ("ack", ctypes.c_uint32, 32),
            ("data_offset", ctypes.c_uint32, 4),
            ("reserved", ctypes.c_uint32, 3),
            ("flags", ctypes.c_uint32, 9),
            ("window", ctypes.c_uint32, 16),
            ("checksum", ctypes.c_uint32, 16),
            ("urg_ptr", ctypes.c_uint32, 16),
        ]
class SegmentTCP(ctypes.Union):
    _fields_ = [("b", SegmentBitsTCP), ("asbyte", 10 * ctypes.c_uint16)]
    def __str__(self):
        return hex(self.asbyte) + ' ' + ', '.join([key for key, value in {
            'src_port': self.b.src_port,
            'dst_port': self.b.dst_port,
            'sq': self.b.sq,
            'ack': self.b.ack,
            'data_offset': self.b.data_offset,
            'reserved': self.b.reserved,
            'flags': self.b.flags,
            'window': self.b.window,
            'checksum': self.b.checksum,
            'urg_ptr': self.b.urg_ptr,
        }.items() if value])


seg = SegmentTCP()
seg.asbyte = 0x4500003ce092400040060204ac110001ac110002ea221f909e9c61ff00000000a002721058540000020405b40402080ad3eb39c40000000001030307
