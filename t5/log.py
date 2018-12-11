
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
def test_chksum():
    # IP
    # 0000   45 00 00 3c a2 1d 40 00 40 06 40 79 ac 11 00 01
    # 0010   ac 11 00 02
    src_ip = bytearray([0xac, 0x11, 0x00, 0x01])
    dst_ip = bytearray([0xac, 0x11, 0x00, 0x02])
    # TCP
    # 0000   b2 04 1f 90 50 f1 3a de 00 00 00 00 a0 02 72 10
    # 0010   58 54 00 00 02 04 05 b4 04 02 08 0a 40 75 24 e9
    # 0020   00 00 00 00 01 03 03 07
    segment = bytearray([
        0xb2, 0x04, 0x1f, 0x90, 0x50, 0xf1, 0x3a, 0xde, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10,
        0x58, 0x54, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x40, 0x75, 0x24, 0xe9,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07
    ])
    chk_sum_org = bytearray([0x58, 0x54])
    chk_sum_correct = bytearray([0xbb, 0x07])

    tcp_len = len(segment) & 0xffff
    tcp_len = tcp_len.to_bytes((tcp_len.bit_length() + 7) // 8, byteorder='little')
    print('tcp_len', hex(len(segment)), tcp_len.hex(), len(segment))
    pseudohdr = bytearray() + src_ip + dst_ip + bytes([0x00, 0x06]) + tcp_len
    chk_segment = bytearray() + pseudohdr + segment
    checksum = 0
    for i in range(0, len(chk_segment), 2):
        section = chk_segment[i:i+2]
        if len(section) < 2:
            section += b'\x00'
        x, = struct.unpack('!H', section)
        y = section[0] << 1 + section[1]
        print(hex(checksum), '+', hex(x))
        checksum += x
        while checksum > 0xffff:
            print('ov', hex(checksum))
            checksum = (checksum & 0xffff) + 1
    print('sum', hex(checksum))
    checksum = ~checksum
    print('neg sum', hex(checksum))
    checksum = checksum & 0xffff
    print('trim sum', hex(checksum))
    checksum = struct.pack('!H', checksum)
    print('checksum', checksum.hex())
    print(
        'checksum test\n',
        'checksum           ', checksum.hex(), '\n',
        'chk_sum_org        ', chk_sum_org.hex(), '\n',
        'chk_sum_correct    ', chk_sum_correct.hex(), '\n',
        '0x5854             ', hex(0x5854), '\n',
        'segment            ', segment.hex(), '\n',
        'chk_segment        ', chk_segment.hex(), '\n',
    )

def test_chksum1():
    # segment str  	Transmission Control Protocol
    #     src_ip                         =>  0xac110001 172.17.0.1
    #     dst_ip                         =>  0xac110002 172.17.0.2
    #     src_port | dst_port            =>  0xd820 55328 | 0x1f90 8080
    #     seq_no                         =>  0x801a62b6
    #     ack_no                         =>  0x0
    #     hed_len | flags | window_size  =>  0xa | 0x2 SYN | 0x7210
    #     checksum | urg_ptr             =>  0x5854 | 0x0
    #     options                        =>  020405b40402080ad3b3c17a0000000001030307
    #     payload                        =>
    # segment = bytearray([0xffff, 0xffff, 0xffffaaaa, 0xffffaaaa, 0xf000 | 0x0e00 | 0x01ff, 0xffff, 0xffff])
    for x in [0xd820, 0x1f90, 0x801a62b6, 0x0, ((0xa <<12) & 0xf000) | ((0x0 <<9) & 0x0e00) | (0x2 & 0x01ff), 0x5854, 0x0, 0x020405b40402080ad3b3c17a0000000001030307]:
        segment += int_to_bits(x)
    segment[16:18] = b'\x00\x00'
    pseudohdr = struct.pack('!IIHH', bits_to_int(str2addr('172.17.0.1')), bits_to_int(str2addr('172.17.0.2')), 0x0006, len(segment))
    chk_segment = bytearray(pseudohdr + segment)
    checksum = 0
    for i in range(0, len(chk_segment), 2):
        x, = struct.unpack('!H', chk_segment[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = (~checksum) & 0xffff
    checksum = struct.pack('!H', checksum)
    print(
        'checksum', checksum.hex(), '\n',
        '0x5854', hex(0x5854), '\n',
    )

def test_chksum2():
    packet = b'E\x00\x00<\xc1\x89@\x00@\x06!\r\xac\x11\x00\x01\xac\x11\x00\x02\xd8 \x1f\x90\x80\x1ab\xb6\x00\x00\x00\x00\xa0\x02r\x10XT\x00\x00\x02\x04\x05\xb4\x04\x02\x08\n\xd3\xb3\xc1z\x00\x00\x00\x00\x01\x03\x03\x07'
    # 0x4500003ce092400040060204ac110001ac110002ea221f909e9c61ff00000000a002721058540000020405b40402080ad3eb39c40000000001030307
    seg_obj = SegmentTCP()
    seg_obj.from_ip_packet(packet)
    seg_obj_srt = str(seg_obj)

    segment = bytearray(packet[20:])
    org_chk = segment[16:18]
    segment[16:18] = b'\x00\x00'
    chk = seg_obj.calc_checksum(segment)

    diff = bytearray(len(segment))
    pkt = packet[20:]
    for i in range(0, len(segment)):
        diff[i] = segment[i] ^ pkt[i]

    diff_chk = bytearray(len(chk))
    for i in range(0, len(chk)):
        diff_chk[i] = org_chk[i] ^ chk[i]

    print(
        'seg_obj_srt    ', seg_obj_srt, '\n',
        'org_chk        ', org_chk.hex(), '\n',
        'new chk        ', chk.hex(), '\n',
        'diff chk       ', diff_chk.hex(), '\n',
        'segment        ', bytes(segment).hex(), '\n',
        'seg_obj        ', bytes(seg_obj).hex(), '\n',
        'diff           ', bytes(diff).hex(), '\n',
    )



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
