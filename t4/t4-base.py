"""Etapa 4
Modifique o código da Etapa 3 para utilizar um único socket do tipo 
`socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))`.
Esse tipo de socket permite enviar e receber pacotes no nível da camada de enlace. 
Note que o socket não dá acesso a todas as informações da camada de enlace, por exemplo o CRC,
mas apenas ao endereço MAC de destino, endereço MAC de origem e tipo do protocolo que está encapsulado dentro do quadro.

Utilize como base este código de exemplo. Modifique a função raw_recv para:

Verificar se o endereço MAC de destino de cada quadro recebido é o MAC da sua placa de rede (variável src_mac).
Verificar se o protocolo encapsulado dentro do quadro recebido é o protocolo IP (ETH_P_IP).
Caso ambas as condições acima sejam satisfeitas, repassar o conteúdo encapsulado (datagrama IP) para uma
função que lide com o processamento na camada de rede, por exemplo a função implementada na Etapa 3.
"""

import socket
import asyncio
import struct


ETH_P_ALL = 0x0003
ETH_P_IP  = 0x0800


ICMP = 0x01  # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers


# Coloque aqui o endereço de destino para onde você quer mandar o ping
dest_ip = '186.219.82.1'

# Coloque abaixo o endereço IP do seu computador na sua rede local
src_ip = '186.219.82.91'

# Coloque aqui o nome da sua placa de rede
if_name = 'wlan0'

# Coloque aqui o endereço MAC do roteador da sua rede local (arp -a | grep _gateway)
dest_mac = '44:31:92:b8:fa:99'

# Coloque aqui o endereço MAC da sua placa de rede (ip link show dev wlan0)
src_mac = '34:02:86:2e:f9:19'




def ip_addr_to_bytes(addr):
    return bytes(map(int, addr.split('.')))


def mac_addr_to_bytes(addr):
    return bytes(int('0x'+s, 16) for s in addr.split(':'))


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


def raw_recv(fd):
    frame = fd.recv(12000)
    print('recebido quadro de %d bytes' % len(frame))
    print(repr(frame))


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


if __name__ == '__main__':
    # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    fd.bind((if_name, 0))

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv, fd)
    asyncio.get_event_loop().call_later(1, send_ping, fd)
    loop.run_forever()
