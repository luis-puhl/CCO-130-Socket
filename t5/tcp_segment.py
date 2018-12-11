#!/usr/bin/python3
import ctypes, struct

def addr2str(addr):
    return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

def str2addr(addr):
    return bytes(int(x) for x in addr.split('.'))

def int_to_bits(x):
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='little')

def bits_to_int(x):
    return int.from_bytes(x, byteorder='little')

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

class SegmentTCP(object):
    """
        | Len      | Meanig                         |
        |----------|--------------------------------|
        | 16 16    | src-port#, dst-port#           |
        | 32       | sq#                            |
        | 32       | ack#                           |
        | 4 3 9 16 | hed-len, empty, flags, Wind    |
        | 16 16    | chk-sum, urg-ptr               |
        | <var>    | Options                        |
        | <var>    | Data                           |
        #
        Flags = (URG, ACK, PSH, RST, SYN, FIN)
        Options = (MMS, win mgm, RFC 854 1323)

        0xffff = 16 bits = hed-len + emtpy + flags
        header length = Data offset: 4 bits ()
        empty = Reserved: 3 bits
        Flags = Control bits: 9 bits
    """
    def __init__(self):
        # self.src_ip = bits_to_int(str2addr('192.168.1.1'))
        # self.dst_ip = bits_to_int(str2addr('192.168.1.1'))
        self.src_ip = 0xac110001 # 172.17.0.1
        self.dst_ip = 0xac110002 # 172.17.0.2
        self.src_port = 0xd820 # 55328
        self.dst_port = 0x1f90 # 8080
        self.seq_no = 0x0000
        self.ack_no = 0x0000
        # Overall flags_line()
        # self.header_len = 5 Use data_offset() # (0xa <<12) & 0xf000
        # self.empty = 0x0                      # (0x0 <<9) & 0x0e00
        self.flags = FlagsTCP()
        # self.flags.asbyte = 0x01ff            # (0x2 & 0x01ff)
        self.flags.b.SYN = 1
        self.window_size = 0x0400
        # self.checksum = 30 Use checksum()
        # (0xa <<12) & 0xffff
        self.urg_ptr = 0x0000
        self.payload = b''
        self.options = b''
    def data_offset(self):
        return 5 + int(len(self.options) / 4)
    def flags_line(self):
        return 0xffff & (((self.data_offset() <<12) & 0xf000) | ((0 <<9) & 0x0e00) | (self.flags.asbyte & 0x01ff))
    def segment_body(self):
        #
        checksum_placeholder = 0x0000
        items = [
            self.src_port, self.dst_port,
            self.seq_no,
            self.ack_no,
            self.flags_line(), self.window_size,
            checksum_placeholder, self.urg_ptr,
            self.options,
            self.payload,
        ]
        int2bytes = lambda x: x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
        bytes2int = lambda x: int.from_bytes(x, byteorder='big')
        composed = bytearray()
        for item in items:
            print(item)
            if isinstance(item, int):
                item = int2bytes(item)
            if not isinstance(item, bytes):
                raise "Bytes expected"
            for i in range(0, len(item), 2):
                composed += item[i:i+2]
        return bytes(composed)
    def checksum(self):
        """
            Checksum (16 bits)
            The 16-bit checksum field is used for error-checking of the header, the Payload and a Pseudo-Header.
            The Pseudo-Header consists of the Source IP Address, the Destination IP Address,
            the protocol number for the TCP-Protocol (0x0006) and the length of the TCP-Headers including Payload (in Bytes).
            +--------+--------+--------+--------+
            |           Source Address          |
            +--------+--------+--------+--------+
            |         Destination Address       |
            +--------+--------+--------+--------+
            |  zero  |  PTCL  |    TCP Length   |
            +--------+--------+--------+--------+
            |          ...TCP Segment...        |
            +--------+--------+--------+--------+
        """
        protocol_number = 0x0006
        zero = 0x0000
        tcp_len = ((self.data_offset() * 4) + len(self.payload))
        #
        checksum_placeholder = 0x0000
        items = [
            self.src_ip,
            self.dst_ip,
            zero, protocol_number, tcp_len,
            self.src_port, self.dst_port,
            self.seq_no,
            self.ack_no,
            self.flags_line(), self.window_size,
            checksum_placeholder, self.urg_ptr,
            self.options,
            self.payload,
        ]
        int2bytes = lambda x: x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
        bytes2int = lambda x: int.from_bytes(x, byteorder='big')
        composed = bytearray()
        checksum = 0
        for item in items:
            print(item)
            if isinstance(item, int):
                item = int2bytes(item)
            if not isinstance(item, bytes):
                raise "Bytes expected"
            for i in range(0, len(item), 2):
                composed += item[i:i+2]
                checksum += bytes2int(item[i:i+2])
                while checksum > 0xffff:
                    checksum = (checksum & 0xffff) + 1
        print(
            'checksum test\n',
            'checksum', hex(checksum), '\n',
            'composed', composed.hex(), '\n',
        )
        return checksum
    def __bytes__(self):
        chk_sum = 0
        segment = bytearray(
            struct.pack(
                '!HHIIHHHH',
                self.src_port, self.dst_port,
                self.seq_no,
                self.ack_no,
                flags_line, self.window_size,
                chk_sum, self.urg_ptr
            ) +
            self.options +
            self.payload
        )
        if len(segment) % 2 == 1:
            # se for ímpar, faz padding à direita
            segment += b'\x00'
        segment[16:18] = self.calc_checksum(segment)
        return bytes(segment)
    def __repr__(self):
        return self.__str__()
    def __str__(self):
        return ' '.join(['\tTransmission Control Protocol',
            '\n\tsrc_ip                         => ', hex(self.src_ip), addr2str(int_to_bits(self.src_ip)),
            '\n\tdst_ip                         => ', hex(self.dst_ip), addr2str(int_to_bits(self.dst_ip)),
            '\n\tsrc_port | dst_port            => ', hex(self.src_port), str(self.src_port), '|', hex(self.dst_port), str(self.dst_port),
            '\n\tseq_no                         => ', hex(self.seq_no),
            '\n\tack_no                         => ', hex(self.ack_no),
            '\n\thed_len | flags | window_size  => ', hex(self.data_offset()), '|', str(self.flags), '|', hex(self.window_size),
            '\n\tchecksum | urg_ptr             => ', hex(self.checksum()), '|', hex(self.urg_ptr),
            '\n\toptions                        => ', self.options.hex(),
            '\n\tpayload                        => ', self.payload.hex()
        ])
    def hexdump(self):
        byte = bytes(self)
        hexdump = ''
        for i in range(0, len(byte)):
            if i % 16 == 0:
                hexdump += '{:04x}'.format(i)
            hexdump += ' {:02x}'.format(byte[i])
        return hexdump
    def unpack(self, bytes):
        return self.from_tcp_segment(bytes)
    def pack(self):
        return bytes(self)
    def calc_checksum(self, segment):
        segment[16:18] = b'\x00\x00'
        pseudohdr = struct.pack('!IIHH', self.src_ip, self.dst_ip, 0x0006, len(segment))
        chk_segment = bytearray(pseudohdr + segment)
        checksum = 0
        for i in range(0, len(chk_segment), 2):
            x, = struct.unpack('!H', chk_segment[i:i+2])
            checksum += x
            while checksum > 0xffff:
                checksum = (checksum & 0xffff) + 1
        checksum = (~checksum) & 0xffff
        return struct.pack('!H', checksum)
    #
    def from_ip_packet(self, packet):
        self.ip_packet = packet
        # IP Header
        version = packet[0] >> 4
        ihl = packet[0] & 0xf
        assert version == 4
        self.src_ip = bits_to_int(packet[12:16])
        self.dst_ip = bits_to_int(packet[16:20])
        self.segment = packet[4*ihl:]
        return self.from_tcp_segment(self.segment)
    #
    def from_tcp_segment(self, segment):
        # unpack TCP
        self.src_port, self.dst_port, self.seq_no, self.ack_no, flags_line, self.window_size, \
            self.checksum, self.urg_ptr = struct.unpack('!HHIIHHHH', segment[:20])
        hed_len = (flags_line & 0xf000) >>12
        empty = flags_line & 0x0e00 >>9
        self.flags = flags_line & 0x01ff
        self.options = segment[4*5:4*hed_len]
        self.payload = segment[4*hed_len:]

if __name__ == '__main__':
    # run tests
    seg = SegmentTCP()
    print(seg.checksum(), '\n', seg.segment_body())
