import socket
import asyncio
import struct
import t3_plus


ETH_P_ALL = 0x0003
ETH_P_IP  = 0x0800

ETH_P_IP_BIN = struct.pack('!H', ETH_P_IP)

ICMP = 0x01  # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers


# Coloque aqui o endereço de destino para onde você quer mandar o ping
# dest_ip = '127.0.0.1'
dest_ip = '192.168.15.17'

# Coloque abaixo o endereço IP do seu computador na sua rede local
# src_ip = '127.0.0.1'
src_ip = '192.168.15.13'

# Coloque aqui o nome da sua placa de rede
# if_name = 'wlan0'
# if_name = 'lo'
if_name = 'wlp8s0'

# Coloque aqui o endereço MAC do roteador da sua rede local (arp -a | grep _gateway)
# jade (192.168.15.17) at 5c:c9:d3:5b:3e:b9 [ether] on wlp8s0
dest_mac = '5c:c9:d3:5b:3e:b9'

# Coloque aqui o endereço MAC da sua placa de rede (ip link show dev wlan0)
src_mac = '0c:84:dc:d4:98:0b'

def ip_addr_to_bytes(addr):
    return bytes(map(int, addr.split('.')))

def mac_addr_to_bytes(addr):
    return bytes(int('0x'+s, 16) for s in addr.split(':'))

def bytes_to_mac_addr(byte):
    # return ':'.join('%02x' % ord(s) for s in struct.unpack('!6c', byte))
    byte = byte.hex()
    return ':'.join(byte[i:i+2] for i in range(0, len(byte), 2))

def send_eth(fd, datagram, protocol):
    eth_header = mac_addr_to_bytes(dest_mac) + \
        mac_addr_to_bytes(src_mac) + \
        struct.pack('!H', protocol)
    fd.send(eth_header + datagram)

ip_pkt_id = 0
def send_ip(fd, msg, protocol):
    global ip_pkt_id
    ip_header = bytearray(struct.pack('!BBHHHBBH',
                            0x45, 0,
                            20 + len(msg),
                            ip_pkt_id,
                            0,
                            15,
                            protocol,
                            0) +
                          ip_addr_to_bytes(src_ip) +
                          ip_addr_to_bytes(dest_ip))
    ip_header[10:12] = struct.pack('!H', calc_checksum(ip_header))
    ip_pkt_id += 1
    send_eth(fd, ip_header + msg, ETH_P_IP)

def send_ping(fd):
    print('enviando ping')
    # Exemplo de pacote ping (ICMP echo request) com payload grande
    msg = bytearray(b"\x08\x00\x00\x00" + 2*b"\xba\xdc\x0f\xfe")
    msg[2:4] = struct.pack('!H', calc_checksum(msg))

    send_ip(fd, msg, ICMP)

    asyncio.get_event_loop().call_later(1, send_ping, fd)

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

def raw_recv(fd):
    """Etapa 4
        Modifique o código da Etapa 3 para utilizar um único socket do tipo
        `socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))`.
        Esse tipo de socket permite enviar e receber pacotes no nível da camada de enlace.
        Note que o socket não dá acesso a todas as informações da camada de enlace, por exemplo o CRC,
        mas apenas ao endereço MAC de destino, endereço MAC de origem e tipo do protocolo que está encapsulado dentro do quadro.

        Utilize como base este código de exemplo. Modifique a função raw_recv para:

        - Verificar se o endereço MAC de destino de cada quadro recebido é o MAC da sua placa de rede (variável src_mac).
        - Verificar se o protocolo encapsulado dentro do quadro recebido é o protocolo IP (ETH_P_IP).
        - Caso ambas as condições acima sejam satisfeitas, repassar o conteúdo encapsulado (datagrama IP) para uma
        função que lide com o processamento na camada de rede, por exemplo a função implementada na Etapa 3.
    """
    frame = fd.recv(12000)
    print('recebido quadro de %d bytes' % len(frame))
    # https://en.wikipedia.org/wiki/Ethernet_frame
    # Layer	Preamble	Start of frame delimiter	MAC destination	MAC source	802.1Q tag (optional)	Ethertype (Ethernet II) or length (IEEE 802.3)	Payload	Frame check sequence (32‑bit CRC)	Interpacket gap
    #         7 octets	1 octet	6 octets	6 octets	(4 octets)	2 octets	46‑1500 octets	4 octets	12 octets
    # Layer 2 Ethernet frame		← 64–1522 octets →
    # Layer 1 Ethernet packet & IPG	← 72–1530 octets →	← 12 octets →
    # dst1, dst2, src1, src2, payloadtype = struct.unpack('!HIHII', frame[:14])

    # Filtro mais rápido (menor). troca de src e dst
    expected = mac_addr_to_bytes(src_mac) + mac_addr_to_bytes(dest_mac) + ETH_P_IP_BIN
    # 0000  0c 84 dc d4 98 0b 5c c9  d3 5b 3e b9 08 00         ......\. .[>...
    if expected != frame[:14]:
        return

    dst = frame[:6]
    src = frame[6:12]
    payloadtype = frame[12:14]
    payload = frame[14:]
    print('Ethernet-->\tdst:', bytes_to_mac_addr(dst), '\tsrc:', bytes_to_mac_addr(src), '\ttype:', payloadtype.hex())

    # Filtro completo
    if bytes_to_mac_addr(dst) == src_mac and bytes_to_mac_addr(src) == dest_mac and payloadtype == ETH_P_IP_BIN:
        print('Repassando para IP', payload[:30].hex())
        # raw_rcv_ip(payload)


if __name__ == '__main__':
    # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    fd.bind((if_name, 0))

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv, fd)
    asyncio.get_event_loop().call_later(1, send_ping, fd)
    loop.run_forever()
