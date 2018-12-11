import socket, asyncio, struct, random, os, ctypes

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

ETH_P_ALL = 0x0003
ETH_P_IP  = 0x0800
ETH_P_IP_BIN = struct.pack('!H', ETH_P_IP)

pacotes = {}
dest_ip = '10.216.22.1'
src_ip = '10.216.22.219'
if_name = 'eth0'
dest_mac = 'fe:aa:fd:e8:df:7a'
src_mac = '00:16:3e:0b:58:0c'

# https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
ICMP = 0x01
TCP = 0x06
# https://en.wikipedia.org/wiki/Maximum_segment_size
MSS = 1460

TESTAR_PERDA_ENVIO = False

class Conexao:
    def __init__(self, id_conexao, seq_no, ack_no):
        self.id_conexao = id_conexao
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.send_queue = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + 1000000 * b"hello pombo\n"
conexoes = {}

def addr2str(addr):
    return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

def str2addr(addr):
    return bytes(int(x) for x in addr.split('.'))

def int_to_bits(x):
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='little')

def bits_to_int(x):
    return int.from_bytes(x, byteorder='little')

def ip_addr_to_bytes(addr):
    return bytes(map(int, addr.split('.')))

def bytes_to_ip_addr(byte):
    return '.'.join(str(ord(s)) for s in struct.unpack('!4c', byte))

def mac_addr_to_bytes(addr):
    return bytes(int('0x'+s, 16) for s in addr.split(':'))

def bytes_to_mac_addr(byte):
    byte = byte.hex()
    return ':'.join(byte[i:i+2] for i in range(0, len(byte), 2))

def calc_checksum(segment):
    if len(segment) % 2 == 1:
        segment += b'\x00'
    checksum = 0
    for i in range(0, len(segment), 2):
        x, = struct.unpack('!H', segment[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff

def fix_checksum(segment, src_addr, dst_addr):
    pseudohdr = str2addr(src_addr) + str2addr(dst_addr) + \
        struct.pack('!HH', 0x0006, len(segment))
    seg = bytearray(segment)
    seg[16:18] = b'\x00\x00'
    seg[16:18] = struct.pack('!H', calc_checksum(pseudohdr + seg))
    return bytes(seg)

def send_next_tcp(fd, conexao):
    payload = conexao.send_queue[:MSS]
    conexao.send_queue = conexao.send_queue[MSS:]

    (dst_addr, dst_port, src_addr, src_port) = conexao.id_conexao

    segment = struct.pack(
        '!HHIIHHHH',
        src_port,
        dst_port,
        conexao.seq_no,
        conexao.ack_no,
        (5<<12)|FLAGS_ACK,
        1024,
        0,
        0
    ) + payload

    conexao.seq_no = (conexao.seq_no + len(payload)) & 0xffffffff

    segment = fix_checksum(segment, src_addr, dst_addr)
    send_ip(
        fd=fd,
        msg=segment,
        protocol=TCP,
        loc_ip=ip_addr_to_bytes(src_ip),
        dst_ip=ip_addr_to_bytes(dst_addr)
    )

    if conexao.send_queue == b"":
        segment = struct.pack('!HHIIHHHH', src_port, dst_port, conexao.seq_no,
                          conexao.ack_no, (5<<12)|FLAGS_FIN|FLAGS_ACK,
                          0, 0, 0)
        segment = fix_checksum(segment, src_addr, dst_addr)
        send_ip(
            fd=fd,
            msg=segment,
            protocol=TCP,
            loc_ip=ip_addr_to_bytes(src_ip),
            dst_ip=ip_addr_to_bytes(dst_addr)
        )
    else:
        asyncio.get_event_loop().call_later(.001, send_next_tcp, fd, conexao)

def raw_recv_tcp(fd, src_addr, dst_addr, segment):
    print('TCP-->\t', 'recebido segmento de %d bytes' % len(segment))
    # src_addr, dst_addr, segment = handle_ipv4_header(packet)
    src_port, dst_port, seq_no, ack_no, flags_line, window_size, checksum, urg_ptr = struct.unpack('!HHIIHHHH', segment[:20])
    hed_len = (flags_line & 0xf000) >>12
    empty = flags_line & 0x0e00 >>9
    flags = FlagsTCP()
    flags.asbyte = flags_line & 0x01ff

    options = segment[20:hed_len*4]
    payload = segment[hed_len*4:]

    id_conexao = (src_addr, src_port, dst_addr, dst_port)

    print(
        'TCP Recebido-->\t',
        '\n\tsrc_ip                         =>', src_addr, addr2str(int_to_bits(src_addr)),
        '\n\tdst_ip                         =>', dst_addr, addr2str(int_to_bits(dst_addr)),
        '\n\tsrc_port | dst_port            =>', src_port, '|', dst_port,
        '\n\tseq_no                         =>', seq_no,
        '\n\tack_no                         =>', ack_no,
        '\n\thed_len | flags | window_size  =>', hex(hed_len), '|', str(flags), '|', hex(window_size),
        '\n\tchecksum | urg_ptr             =>', hex(checksum), '|', hex(urg_ptr),
        '\n\toptions                        =>', options.hex(),
        '\n\tpayload                        =>', payload.hex(),
    )

    if dst_port != 8080:
        print('TCP-->\t', 'porta não usada', dst_port)
        segment = struct.pack('!HHIIHHHH', dst_port, src_port, 0,
                          seq_no, (5<<12)|FLAGS_RST|FLAGS_ACK,
                          0, 0, 0)
                fix_checksum(segment, src_addr, dst_addr)
        segment = fix_checksum(segment, src_addr, dst_addr)
        send_ip(
            fd=fd,
            msg=segment,
            protocol=TCP,
            loc_ip=ip_addr_to_bytes(src_ip),
            dst_ip=ip_addr_to_bytes(dst_addr)
        )
        return

    if (flags & FLAGS_SYN) == FLAGS_SYN:
        print('%s:%d -> %s:%d (seq=%d)' % (src_addr, src_port,
                                           dst_addr, dst_port, seq_no))

        conexoes[id_conexao] = conexao = Conexao(id_conexao=id_conexao,
                                                 seq_no=struct.unpack('I', os.urandom(4))[0],
                                                 ack_no=seq_no + 1)

        # make_synack(dst_port, src_port, conexao.seq_no, conexao.ack_no)
        segment = struct.pack('!HHIIHHHH', src_port, dst_port, seq_no,
                       ack_no, (5<<12)|FLAGS_ACK|FLAGS_SYN,
                       1024, 0, 0)
        send_ip(
            fd=fd,
            msg=fix_checksum(segment, src_addr, dst_addr),
            protocol=TCP,
            loc_ip=ip_addr_to_bytes(src_ip),
            dst_ip=ip_addr_to_bytes(src_addr)
        )

        conexao.seq_no += 1

        asyncio.get_event_loop().call_later(.1, send_next_tcp, fd, conexao)
    elif id_conexao in conexoes:
        conexao = conexoes[id_conexao]
        conexao.ack_no += len(payload)
    else:
        print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' % (src_addr, src_port, dst_addr, dst_port))

def raw_send_tcp(fd, segment, ):
    segment = struct.pack(
        '!HHIIHHHH',
        src_port,
        dst_port,
        seq_no,
        ack_no,
        (5<<12)|FLAGS_ACK|FLAGS_SYN,
        1024,
        0,
        0
    )
    send_ip(
        fd=fd,
        msg=fix_checksum(segment, src_addr, dst_addr),
        protocol=TCP,
        loc_ip=ip_addr_to_bytes(src_ip),
        dst_ip=ip_addr_to_bytes(src_addr)
    )

def send_eth(fd, datagram, protocol):
    eth_header = mac_addr_to_bytes(dest_mac) + \
        mac_addr_to_bytes(src_mac) + \
        struct.pack('!H', protocol)
    fd.send(eth_header + datagram)

ip_pkt_id = 0
def send_ip(fd, msg, protocol, loc_ip, dst_ip):
    global ip_pkt_id
    ip_header = bytearray(struct.pack('!BBHHHBBH',
                            0x45, 0,
                            20 + len(msg),
                            ip_pkt_id,
                            0,
                            15,
                            protocol,
                            0) +
                          loc_ip +
                          dst_ip)
    ip_header[10:12] = struct.pack('!H', calc_checksum(ip_header))
    ip_pkt_id += 1
    send_eth(fd, ip_header + msg, ETH_P_IP)

def send_ping(fd):
    print('enviando ping')
    msg = bytearray(b"\x08\x00\x00\x00" + 2*b"\xba\xdc\x0f\xfe")
    msg[2:4] = struct.pack('!H', calc_checksum(msg))

    send_ip(fd=fd, msg=msg, protocol=ICMP, loc_ip=ip_addr_to_bytes(src_ip), dst_ip=ip_addr_to_bytes(dest_ip))

    asyncio.get_event_loop().call_later(1, send_ping, fd)

def calc_checksum(segment):
    if len(segment) % 2 == 1:
        segment += b'\x00'
    checksum = 0
    for i in range(0, len(segment), 2):
        x, = struct.unpack('!H', segment[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff

def guilotine(packet):
    version = packet[0] >> 4
    IHL = packet[0] & 0x0f
    if version != 4:
        print('Não é ipv4. --> ', version)
        return None
    head = packet[:IHL*4]
    body = packet[IHL*4:]

    return head, body

def strip_head(head):
    VersionIHL, DSCPECN, TotalLength, Identification, FlagsFragmentOffset, TimeToLive, Protocol, \
    HeaderChecksum, SourceIPAddress, DestinationIPAddress = struct.unpack('!BBHHHBBHII', head[:20])

    SourceIPAddress = bytes_to_ip_addr(head[12:16])
    DestinationIPAddress = bytes_to_ip_addr(head[16:20])

    Version = VersionIHL >> 4
    IHL = VersionIHL & 0x0f
    DSCP = DSCPECN >> 2
    ECN = DSCPECN & 0x03
    Flags = (FlagsFragmentOffset & 0b1110000000000000) >> 13
    FragmentOffset = FlagsFragmentOffset & 0b0001111111111111
    Options = head[20:]

    FlagsExplicit = {
        'Evilbit': Flags & 0b100 > 0,
        'DontFragment': Flags & 0b010 > 0,
        'MoreFragments': Flags & 0b001 > 0,
    }
    return Version, IHL, DSCP, ECN, TotalLength, Identification, Flags, FlagsExplicit, \
    FragmentOffset, TimeToLive, \
    Protocol, HeaderChecksum, SourceIPAddress, DestinationIPAddress, Options

def raw_recv_ip(datagrama):
    ticktockman()
    print('IPv4-->\t', 'recebido pacote de %d bytes' % len(datagrama))

    head, body = guilotine(datagrama)

    Version, IHL, DSCP, ECN, TotalLength, Identification, Flags, FlagsExplicit, FragmentOffset, \
    TimeToLive, \
    Protocol, HeaderChecksum, SourceIPAddress, DestinationIPAddress, Options = strip_head(head)

    if Protocol not in [TCP, ICMP]:
        print('Protocolo estranho', Protocol)
        return None

    if DestinationIPAddress != src_ip:
        print('Ip destino não é ', src_ip)
        return None

    print(
        'IPv4-->\t',
        'Version:', Version,
        'IHL:', IHL,
        'DSCP:', DSCP,
        'ECN:', ECN,
        'TotalLength:', TotalLength,
        'Identification:', Identification,
        'FlagsExplicit:', FlagsExplicit,
        'FragmentOffset:', FragmentOffset,
        '\n\t\t',
        'TimeToLive:', TimeToLive,
        'Protocol:', Protocol,
        'HeaderChecksum:', HeaderChecksum,
        'SourceIPAddress:', SourceIPAddress,
        'DestinationIPAddress:', DestinationIPAddress,
        'Options:', Options,
        'Len:', len(datagrama),
        'LenBody:', len(body),
    )

    tripla = (SourceIPAddress, DestinationIPAddress, Identification)
    if not tripla in pacotes.keys():
        pacotes[tripla] = {'size': 0, 'payload': {}, 'maxSize': None, 'Ticktockman': 200}
    pacotes[tripla]['Ticktockman'] = 200

    if FlagsExplicit['MoreFragments']:
        pacotes[tripla]['maxSize'] = FragmentOffset*8 + TotalLength - len(head)
    else:
        pacotes[tripla]['maxSize'] = TotalLength - len(head)

    if not FragmentOffset in pacotes[tripla]['payload'].keys():
        pacotes[tripla]['size'] += len(body)
        pacotes[tripla]['payload'][FragmentOffset] = body

    print('IPv4-->\t', 'Pacote \n\t', pacotes[tripla], '\n')
    if pacotes[tripla]['maxSize'] == pacotes[tripla]['size']:
        ordenado = sorted(pacotes[tripla]['payload'].keys())
        completo = b''
        for i in ordenado:
            completo += pacotes[tripla]['payload'][i]
        print('IPv4-->\t', 'Pacote Completo\n\t', completo.hex(), '\n')
        if Protocol == TCP:
            raw_recv_tcp(fd=fd, src_addr=SourceIPAddress, dst_addr=DestinationIPAddress, segment=body)
        if Protocol == ICMP:
            pass
        del pacotes[tripla]

def ticktockman():
    """
    A ideia dessa função é que o buffer de pacotes inacabados é limpo proporcionalmente
    ao número de pacotes recebidos.
    Como padrão, 200 pacotes podem ser recebidos entre uma parcela e outra do segmentado.
    """
    for tripla in pacotes.copy().keys():
        pacotes[tripla]['Ticktockman'] -= 1
        if pacotes[tripla]['Ticktockman'] == 0:
            print('\nTicktockman got you Harlequin\n')
            del pacotes[tripla]

def raw_recv_eth(fd):
    frame = fd.recv(12000)
    print('Ethernet-->', 'recebido quadro de %d bytes' % len(frame))

    expected = mac_addr_to_bytes(src_mac) + mac_addr_to_bytes(dest_mac) + ETH_P_IP_BIN
    if expected != frame[:14]:
        return

    dst = frame[:6]
    src = frame[6:12]
    payloadtype = frame[12:14]
    payload = frame[14:]
    print('Ethernet-->\tdst:', bytes_to_mac_addr(dst), '\tsrc:', bytes_to_mac_addr(src), '\ttype:', payloadtype.hex())

    if bytes_to_mac_addr(dst) == src_mac and bytes_to_mac_addr(src) == dest_mac and payloadtype == ETH_P_IP_BIN:
        raw_recv_ip(payload)

if __name__ == '__main__':
    fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    fd.bind((if_name, 0))

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv_eth, fd)
    try:
        loop.run_forever()
    except Exception as e:
        raise e
        # logging...etc
        loop.call_later(1, exit)
        pass
    except KeyboardInterrupt as e:
        print('KeyboardInterrupt...')
        exit()
