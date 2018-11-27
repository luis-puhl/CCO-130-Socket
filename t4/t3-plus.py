import socket
import asyncio
import struct
import random

ETH_P_IP = 0x0800

# Coloque aqui o endereço de destino para onde você quer mandar o ping
# dest_addr = '192.168.15.1'
# dest_addr = '0.0.0.0'
dest_addr = '127.0.0.1'
pacotes = {}
globalPrintCount = 25

Mussum = """Mussum Ipsum, cacilds vidis litro abertis. Quem num gosta di mim que vai caçá sua turmis!
    Todo mundo vê os porris que eu tomo, mas ninguém vê os tombis que eu levo!
    Viva Forevis aptent taciti sociosqu ad litora torquent. Interagi no mé,
    cursus quis, vehicula ac nisi.

    Quem num gosta di mé, boa gentis num é. Pra lá , depois divoltis porris, paradis.
    Mé faiz elementum girarzis, nisi eros vermeio. Admodum accumsan disputationi eu sit.
    Vide electram sadipscing et per.

    Atirei o pau no gatis, per gatis num morreus. Interessantiss quisso pudia ce receita de bolis,
    mais bolis eu num gostis. Não sou faixa preta cumpadi, sou preto inteiris, inteiris.
    Suco de cevadiss deixa as pessoas mais interessantis.
""".encode()

def send_ping(send_fd):
    print('enviando ping')
    # Exemplo de pacotes ping (ICMP echo request) com payload grande
    msg = bytearray(b"\x08\x00\x00\x00" + 5000*b"\xba\xdc\x0f\xfe")
    # msg = bytearray(50*Mussum)
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
    VersionIHL, DSCPECN, TotalLength, Identification, FlagsFragmentOffset, TimeToLive, Protocol, \
    HeaderChecksum, SourceIPAddress, DestinationIPAddress = struct.unpack('!BBHHHBBHII', head[:20])

    Version = VersionIHL >> 4
    IHL = VersionIHL & 0x0f
    DSCP = DSCPECN >> 2
    ECN = DSCPECN & 0x03
    # Flags -> A three-bit field follows and is used to control or identify fragments.
    # They are (in order, from most significant to least significant):
    # bit 0: Reserved; must be zero.[note 1]
    # bit 1: Don't Fragment (DF)
    # bit 2: More Fragments (MF)
    Flags = (FlagsFragmentOffset & 0b1110000000000000) >> 13
    # 0b 1 1111 1111 1111
    FragmentOffset = FlagsFragmentOffset & 0b0001111111111111
    Options = head[20:]

    FlagsExplicit = {
        'Evilbit': Flags & 0b100 > 0,
        'DontFragment': Flags & 0b010 > 0,
        'MoreFragments': Flags & 0b001 > 0,
    }
    # 100 000000000000
    return Version, IHL, DSCP, ECN, TotalLength, Identification, Flags, FlagsExplicit, \
    FragmentOffset, TimeToLive, \
    Protocol, HeaderChecksum, SourceIPAddress, DestinationIPAddress, Options

def raw_recv(recv_fd):
    packet = recv_fd.recv(2400)
    ticktockman()
    # print('recebido pacote de %d bytes' % len(packet))

    # introduzir erro
    if random.randrange(10) > 8:
        return

    head, body = guilotine(packet)

    Version, IHL, DSCP, ECN, TotalLength, Identification, Flags, FlagsExplicit, FragmentOffset, \
    TimeToLive, \
    Protocol, HeaderChecksum, SourceIPAddress, DestinationIPAddress, Options = strip_head(head)

    if 1 != Protocol:
        print('Protocolo estranho', Protocol)
        return None

    if 2130706433 != DestinationIPAddress:
        print('Ip destino não é localhost')
        return None

    print(
        'Version:', Version,
        'IHL:', IHL,
        'DSCP:', DSCP,
        'ECN:', ECN,
        'TotalLength:', TotalLength,
        'Identification:', Identification,
        'FlagsExplicit:', FlagsExplicit,
        'FragmentOffset:', FragmentOffset,
    )
    print(
        'TimeToLive:', TimeToLive,
        'Protocol:', Protocol,
        'HeaderChecksum:', HeaderChecksum,
        'SourceIPAddress:', SourceIPAddress,
        'DestinationIPAddress:', DestinationIPAddress,
        'Options:', Options,
        'Len:', len(packet),
        'LenBody:', len(body),
    )

    # remonta pacote
    tripla = (SourceIPAddress, DestinationIPAddress, Identification)
    if not tripla in pacotes.keys():
        pacotes[tripla] = {'size': 0, 'payload': {}, 'maxSize': None, 'Ticktockman': 200}
    # reseta o tempo de vida do pacote parcial
    pacotes[tripla]['Ticktockman'] = 200

    if FlagsExplicit['MoreFragments']:
        pacotes[tripla]['maxSize'] = FragmentOffset*8 + TotalLength - len(head)

    if not FragmentOffset in pacotes[tripla]['payload'].keys():
        pacotes[tripla]['size'] += len(body)
        pacotes[tripla]['payload'][FragmentOffset] = body

    if pacotes[tripla]['maxSize'] == pacotes[tripla]['size']:
        print('\nPacote Completo')
        ordenado = sorted(pacotes[tripla]['payload'].keys())
        for i in ordenado:
            print(pacotes[tripla]['payload'][i], end = '')
        del pacotes[tripla]
        print('\n')

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

if __name__ == '__main__':
    # Ver http://man7.org/linux/man-pages/man7/raw.7.html
    send_fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    """ Para receber existem duas abordagens. A primeira é a da etapa anterior
        # do trabalho, de colocar socket.IPPROTO_TCP, socket.IPPROTO_UDP ou
        # socket.IPPROTO_ICMP. Assim ele filtra só datagramas IP que contenham um
        # segmento TCP, UDP ou mensagem ICMP, respectivamente, e permite que esses
        # datagramas sejam recebidos. No entanto, essa abordagem faz com que o
        # próprio sistema operacional realize boa parte do trabalho da camada IP,
        # como remontar datagramas fragmentados. Para que essa questão fique a
        # cargo do nosso programa, é necessário uma outra abordagem: usar um socket
        # de camada de enlace, porém pedir para que as informações de camada de
        # enlace não sejam apresentadas a nós, como abaixo. Esse socket também
        # poderia ser usado para enviar pacotess, mas somente se eles forem quadros,
        # ou seja, se incluírem cabeçalhos da camada de enlace.
        # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    """
    recv_fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))

    loop = asyncio.get_event_loop()
    loop.add_reader(recv_fd, raw_recv, recv_fd)
    asyncio.get_event_loop().call_later(1, send_ping, send_fd)
    loop.run_forever()
