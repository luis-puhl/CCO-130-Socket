#!/usr/bin/python3
import ctypes, struct

def addr2str(addr):
    return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

def str2addr(addr):
    return bytes(int(x) for x in addr.split('.'))

def int_to_bits(x):
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def bits_to_int(x):
    return int.from_bytes(x, byteorder='big')

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
    #
    def __init__(self):
        self.src_ip = bits_to_int(str2addr('192.168.1.1'))
        self.dst_ip = bits_to_int(str2addr('192.168.1.1'))
        self.src_port = 8080
        self.dst_port = 8080
        self.seq_no = 10
        self.ack_no = 20
        self.flags = SegmentTCP.FLAG_FIN|SegmentTCP.FLAG_SYN|SegmentTCP.FLAG_RST|SegmentTCP.FLAG_ACK
        self.checksum = 30
        self.window_size = 40
        self.urg_ptr = 50
        self.payload = b''
        self.options = b''
    def __repr__(self):
        return self.__str__()
    def __str__(self):
        flags = FlagsTCP()
        flags.asbyte = self.flags
        text_flags = str(flags)
        return ' '.join(['\tTransmission Control Protocol',
            '\n\tsrc_ip                         => ', hex(self.src_ip), addr2str(int_to_bits(self.src_ip)),
            '\n\tdst_ip                         => ', hex(self.dst_ip), addr2str(int_to_bits(self.dst_ip)),
            '\n\tsrc_port | dst_port            => ', hex(self.src_port), str(self.src_port), '|', hex(self.dst_port), str(self.dst_port),
            '\n\tseq_no                         => ', hex(self.seq_no),
            '\n\tack_no                         => ', hex(self.ack_no),
            '\n\thed_len | flags | window_size  => ', hex(self.data_offset()), '|', text_flags, '|', hex(self.window_size),
            '\n\tchecksum | urg_ptr             => ', hex(self.checksum), '|', hex(self.urg_ptr),
            '\n\toptions                        => ', self.options.hex(),
            '\n\tpayload                        => ', self.payload.hex()
        ])
    def data_offset(self):
        return 5 + int(len(self.options) / 4)
    def __bytes__(self):
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
        header length = Data offset: 4 bits
        empty = Reserved: 3 bits
        Flags = Control bits: 9 bits
        """
        hed_len = self.data_offset() <<12
        empty = 0 <<9
        flags_line = 0xffff & ((hed_len & 0xf000) | (empty & 0x0e00) | (self.flags & 0x01ff))
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

def test1():
    s2 = SegmentTCP()
    s2.src_ip = bits_to_int(str2addr('192.168.1.1'))
    s2.dst_ip = bits_to_int(str2addr('192.168.1.1'))
    s2.src_port = 8080
    s2.dst_port = 8080
    s2.seq_no = 10
    s2.ack_no = 20
    s2.flags = SegmentTCP.FLAGS_FIN|SegmentTCP.FLAGS_SYN|SegmentTCP.FLAGS_RST|SegmentTCP.FLAGS_ACK
    s2.checksum = 30
    s2.window_size = 40
    s2.urg_ptr = 50
    s2.payload = b''
    s2.options = b''
    s2 = bytes(s2)
    s1 = SegmentTCP()
    s1.from_tcp_segment(s2)
    s1 = bytes(s1)
    r = bytearray(len(s1))
    for i in range(0, len(s1)):
        r[i] = s1[i] ^ s2[i]
    print('test segment\n', s1, '\n', s2, '\n', s1 == s2, '\n', r)

def test2():
    packet = b'E\x00\x00<\xc1\x89@\x00@\x06!\r\xac\x11\x00\x01\xac\x11\x00\x02\xd8 \x1f\x90\x80\x1ab\xb6\x00\x00\x00\x00\xa0\x02r\x10XT\x00\x00\x02\x04\x05\xb4\x04\x02\x08\n\xd3\xb3\xc1z\x00\x00\x00\x00\x01\x03\x03\x07'
    # 0x4500003ce092400040060204ac110001ac110002ea221f909e9c61ff00000000a002721058540000020405b40402080ad3eb39c40000000001030307
    segment = SegmentTCP()
    segment.from_ip_packet(packet)
    segment_srt = str(segment)
    segment = packet[:20] + bytes(segment)
    r = bytearray(len(packet))
    for i in range(0, len(segment)):
        r[i] = segment[i] ^ packet[i]
    print(
        'test packet\n',
        'packet      ', packet.hex(), '\n',
        'segment bits', segment.hex(), '\n',
        'diff bits   ', bytes(r).hex(), '\n',
        'segment str ', segment_srt, '\n',
        segment == packet, len(packet), len(segment), '\n',
    )
def test_flags():
    flags = FlagsTCP()
    flags.asbyte = 0xa002
    print(str(flags))
def test():
    test_flags()
    # test1()
    test2()

if __name__ == '__main__':
    # run tests
    test()

last_run = """
root@fcedf9b7c81d:/code# python3 t5/tcp_segment.py
0xa002 SYN
test packet
 packet       4500003cc18940004006210dac110001ac110002d8201f90801a62b600000000a002721058540000020405b40402080ad3b3c17a0000000001030307
 segment bits 4500003cc18940004006210dac110001ac110002d8201f90801a62b600000000a00272100e1a0000020405b40402080ad3b3c17a0000000001030307
 diff bits    000000000000000000000000000000000000000000000000000000000000000000000000564e00000000000000000000000000000000000000000000
 segment str  	Transmission Control Protocol
	src_ip                         =>  0xac110001 172.17.0.1
	dst_ip                         =>  0xac110002 172.17.0.2
	src_port | dst_port            =>  0xd820 55328 | 0x1f90 8080
	seq_no                         =>  0x801a62b6
	ack_no                         =>  0x0
	hed_len | flags | window_size  =>  0xa | 0x2 SYN | 0x7210
	checksum | urg_ptr             =>  0x5854 | 0x0
	options                        =>  020405b40402080ad3b3c17a0000000001030307
	payload                        =>
 False 60 60
"""
