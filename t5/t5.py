#!/usr/bin/python3
import asyncio, socket, struct
import http.client, subprocess

FLAGS_FIN = 1<<0
FLAGS_SYN = 1<<1
FLAGS_RST = 1<<2
FLAGS_ACK = 1<<4

def addr2str(addr):
    return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

def str2addr(addr):
    return bytes(int(x) for x in addr.split('.'))

def int_to_bits(x):
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def bits_to_int(x):
    return int.from_bytes(x, byteorder='big')

def hash_conexao(rem_ip, rem_port, loc_ip, loc_port):
    # hash: 8 bytes, => 64bits
    # id: rem_ip 32, rem_port 16, loc_ip 32, loc_port 16 => 96bits
    rem_ip = int_to_bits(rem_ip)
    rem_port = int_to_bits(rem_port)
    loc_ip = int_to_bits(loc_ip)
    hashed = bits_to_int(rem_ip + rem_port + loc_ip[1:4])
    return hashed

class ConexaoTCP:
    LISTEN='LISTEN'
    # (server) represents waiting for a connection request from any remote TCP and port.
    SYN_SENT='SYN_SENT'
    # (client) represents waiting for a matching connection request after having sent a connection request.
    SYN_RECEIVED='SYN_RECEIVED'
    # (server) represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request.
    ESTABLISHED='ESTABLISHED'
    # (both server and client) represents an open connection, data received can be delivered to the user.
    # The normal state for the data transfer phase of the connection.
    FIN_WAIT_1='FIN_WAIT_1'
    # (both server and client) represents waiting for a connection termination request from the remote TCP,
    # or an acknowledgment of the connection termination request previously sent.
    FIN_WAIT_2='FIN_WAIT_2'
    # (both server and client) represents waiting for a connection termination request from the remote TCP.
    CLOSE_WAIT='CLOSE_WAIT'
    # (both server and client) represents waiting for a connection termination request from the local user.
    CLOSING='CLOSING'
    # (both server and client) represents waiting for a connection termination request acknowledgment from the remote TCP.
    LAST_ACK='LAST_ACK'
    # (both server and client) represents waiting for an acknowledgment of the connection termination
    # request previously sent to the remote TCP (which includes an acknowledgment of its connection termination request).
    TIME_WAIT='TIME_WAIT'
    # (either server or client) represents waiting for enough time to pass to be sure the remote TCP received the
    #  acknowledgment of its connection termination request. [According to RFC 793 a connection can stay in TIME-WAIT for
    # a maximum of four minutes known as two MSL (maximum segment lifetime).]
    CLOSED='CLOSED'

    def __init__(self, fd, rem_ip, rem_port, loc_ip, loc_port, seq_no=0, ack_no=0):
        self.status = None
        self.rem_ip = rem_ip
        self.rem_port = rem_port
        self.loc_ip = loc_ip
        self.loc_port = loc_port
        self.id_conexao = (rem_ip, rem_port, loc_ip, loc_port)
        self.fd = fd

        self.seq_no = seq_no
        self.ack_no = ack_no
        self.send_queue = b''

    def recv(self, segment):
        print(segment)

    def syn_ack(self):
        self.send_raw(flags=FLAGS_SYN|FLAGS_ACK, data=b'')
        self.status = ConexaoTCP.SYN_RECEIVED

    def refuse(self):
        print('Conn recusada')
        # Testando fazendo um wget 1.1.1.1:8080 recebi de respota um ACK|RST
        self.send_raw(flags=FLAGS_ACK|FLAGS_RST, data=b'')

    def send_raw(self, flags=FLAGS_SYN|FLAGS_ACK, data=b''):
        segmentTCP = SegmentTCP()
        #
        segmentTCP.src_addr = self.loc_ip
        segmentTCP.dst_addr = self.rem_ip
        segmentTCP.src_port = self.loc_port
        segmentTCP.dst_port = self.rem_port
        segmentTCP.seq = self.seq_no
        segmentTCP.ack = self.ack_no
        segmentTCP.flags = flags
        segmentTCP.data = data
        s1 = bytes(segmentTCP)
        #
        # segment = make_segment(
        #     src_addr=self.loc_ip, dst_addr=self.rem_ip,
        #     src_port=self.loc_port, dst_port=self.rem_port,
        #     seq=self.seq_no, ack=self.ack_no,
        #     flags=flags,
        #     data=data
        # )
        # self.seq_no += 1
        # print('', s1, '\n', segment, '\n', s1 ^ segment)

        ip = addr2str(int_to_bits(self.rem_ip))
        port = self.rem_port
        print(
            'SENT\tTransmission Control Protocol send to', ip, port,
            '\n\tsrc_ip              =>', self.loc_ip, addr2str(int_to_bits(self.loc_ip)),
            '\n\tdst_ip              =>', self.rem_ip, addr2str(int_to_bits(self.rem_ip)),
            '\n\tsrc_port | dst_port =>', self.loc_port, '|', self.rem_port,
            '\n\tseq_no              =>', self.seq_no,
            '\n\tack_no              =>', self.ack_no,
            '\n\tflags | window_size =>', flags, '|', 1024,
            '\n\tchecksum | urg_ptr  =>', segment[16:18], '|', 0
        )
        return self.fd.sendto(segment, (ip, port))

    def send(self, data=b''):
        self.send_queue += data

    def __hash__(self):
        return hash_conexao(self.rem_ip, self.rem_port, self.loc_ip, self.loc_port)
    def __eq__(self, other):
        return (
            self.rem_ip == rem_ip and self.rem_port == rem_port and
            self.loc_ip == loc_ip and self.loc_port == loc_port
        )

conexoes = {}
def raw_recv_tcp(fd):
    packet = fd.recv(12000)
    print(packet.hex())
    segmentTCP = SegmentTCP()
    segmentTCP.from_ip_packet(packet)
    print('RECEIVED\t', segmentTCP, '\n\t', bytes(segmentTCP).hex())

    global conexoes
    hashed = hash_conexao(
        rem_ip=segmentTCP.src_ip, rem_port=segmentTCP.src_port, loc_ip=segmentTCP.dst_ip,
        loc_port=segmentTCP.dst_port
    )
    if id not in conexoes:
        conexoes[hashed] = ConexaoTCP(
            fd=fd, rem_ip=segmentTCP.src_ip, rem_port=segmentTCP.src_port, loc_ip=segmentTCP.dst_ip,
            loc_port=segmentTCP.dst_port
        )
        conexoes[hashed].status = ConexaoTCP.LISTEN
    conexao = conexoes[hashed]

    # recusar conexão
    if segmentTCP.dst_port != 8080:
        conexao.refuse()

    # aceita conexao
    conexao.recv(segmentTCP)
    if conexao.status == ConexaoTCP.LISTEN:
        conexao.syn_ack()
        print('Conn aceita')
        conexao.send(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + 1000 * b"hello pombo\n")

def test():
    hc = http.client.HTTPConnection('localhost', 8080)
    hc.request('GET', '/')
    response = hc.getresponse()
    print('-> test -> response', response.status, response.reason)
    # subprocess.call("curl localhost:8080")

if __name__ == '__main__':
    fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv_tcp, fd)
    # loop.call_later(.001, test)
    # loop.call_later(30, exit)
    try:
        loop.run_forever()
    except Exception as e:
        raise e
        # logging...etc
        loop.call_later(3, exit)
        pass
    except KeyboardInterrupt as e:
        print('KeyboardInterrupt...')
        exit()
