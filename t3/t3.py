import socket
import asyncio
import struct


ETH_P_IP = 0x0800

# Coloque aqui o endereço de destino para onde você quer mandar o ping
# dest_addr = '192.168.15.1'
# dest_addr = '0.0.0.0'
dest_addr = '127.0.0.1'

pacote = {}


def send_ping(send_fd):
    print('enviando ping')
    # Exemplo de pacote ping (ICMP echo request) com payload grande
    msg = bytearray(b"\x08\x00\x00\x00" + 5000*b"\xba\xdc\x0f\xfe")
    msg[2:4] = struct.pack('!H', calc_checksum(msg))
    send_fd.sendto(msg, (dest_addr, 0))

    asyncio.get_event_loop().call_later(1, send_ping, send_fd)

def calc_checksum(segment):
    if len(segment) % 2 == 1:
        # se for ímpar, faz padding à direita
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
    # The Internet Header Length (IHL) field has 4 bits
    # IHL diz quantas 'linhas' de 4 bytes tem o cabeçalho
    head = packet[:IHL*4]
    body = packet[IHL*4:]

    return head, body

def strip_head(head):
    # Version, IHL, DSCP, ECN, TotalLength, Identification, Flags, FragmentOffset, TimeToLive,
    # Protocol, HeaderChecksum, SourceIPAddress, DestinationIPAddress, Options
    VersionIHL, DSCPECN, TotalLength, Identification, FlagsFragmentOffset, TimeToLive, \
    Protocol, HeaderChecksum, SourceIPAddress, DestinationIPAddress = struct.unpack('!BBHHHBBHII', head[:20])

    Version = VersionIHL >> 4
    IHL = VersionIHL & 0x0f
    DSCP = DSCPECN >> 2
    ECN = DSCPECN & 0x03
    # Flags -> A three-bit field follows and is used to control or identify fragments. They are (in order, from most significant to least significant):
    Flags = FlagsFragmentOffset >> 13
    FragmentOffset = FlagsFragmentOffset & 0x0d
    Options = head[20:]

    return Version, IHL, DSCP, ECN, TotalLength, Identification, Flags, FragmentOffset, TimeToLive, \
    Protocol, HeaderChecksum, SourceIPAddress, DestinationIPAddress, Options

def raw_recv(recv_fd):
    packet = recv_fd.recv(2400)
    print('recebido pacote de %d bytes' % len(packet))
    head, body = guilotine(packet)
    if head == None:
        print('sem cabeça')
        return None

    Version, IHL, DSCP, ECN, TotalLength, Identification, Flags, FragmentOffset, TimeToLive, \
    Protocol, HeaderChecksum, SourceIPAddress, DestinationIPAddress, Options = strip_head(head)

    if 1 != Protocol:
        # print('Protocol not icmp echo')
        return None

    if 2130706433 != DestinationIPAddress:
        print('Not home')
        return None

    tripla = (SourceIPAddress, DestinationIPAddress, Identification)
    if not tripla in pacote.keys():
        pacote[tripla] = {'size': 0, 'payload': {}, 'maxSize': None}

    if Flags & 0x01 == 0:
        pacote[tripla]['maxSize'] = FragmentOffset*8 + TotalLength - len(head)

    if not FragmentOffset in pacote[tripla]['payload'].keys():
        pacote[tripla]['size'] += len(body)
        pacote[tripla]['payload'][FragmentOffset] = body

    if pacote[tripla]['maxSize'] == pacote[tripla]['size']:
        del pacote[tripla]

    ordenado = sorted(pacote[tripla]['payload'].keys())
    for i in ordenado:
        print(pacote[tripla]['payload'][i].decode('utf-8'), end = '')
        print()

    # if Flags & 0x01 == 1:
    #     print('fraged')
    #     pacote[]
    #     return None

    print(
        'Version:', Version,
        'IHL:', IHL,
        'DSCP:', DSCP,
        'ECN:', ECN,
        'TotalLength:', TotalLength,
        'Identification:', Identification,
        'Flags:', Flags,
        'FragmentOffset:', FragmentOffset,
        'TimeToLive:', TimeToLive,
        'Protocol:', Protocol,
        'HeaderChecksum:', HeaderChecksum,
        'SourceIPAddress:', SourceIPAddress,
        'DestinationIPAddress:', DestinationIPAddress,
        'Options:', Options,
        'Len:', len(packet),
        'LenBody:', len(body),
    )

if __name__ == '__main__':
    # Ver http://man7.org/linux/man-pages/man7/raw.7.html
    send_fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Para receber existem duas abordagens. A primeira é a da etapa anterior
    # do trabalho, de colocar socket.IPPROTO_TCP, socket.IPPROTO_UDP ou
    # socket.IPPROTO_ICMP. Assim ele filtra só datagramas IP que contenham um
    # segmento TCP, UDP ou mensagem ICMP, respectivamente, e permite que esses
    # datagramas sejam recebidos. No entanto, essa abordagem faz com que o
    # próprio sistema operacional realize boa parte do trabalho da camada IP,
    # como remontar datagramas fragmentados. Para que essa questão fique a
    # cargo do nosso programa, é necessário uma outra abordagem: usar um socket
    # de camada de enlace, porém pedir para que as informações de camada de
    # enlace não sejam apresentadas a nós, como abaixo. Esse socket também
    # poderia ser usado para enviar pacotes, mas somente se eles forem quadros,
    # ou seja, se incluírem cabeçalhos da camada de enlace.
    # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    recv_fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))

    loop = asyncio.get_event_loop()
    loop.add_reader(recv_fd, raw_recv, recv_fd)
    asyncio.get_event_loop().call_later(1, send_ping, send_fd)
    loop.run_forever()
