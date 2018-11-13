#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket
from TcpConnectionSock import TcpConnectionSock

class TcpConnection:
    def __init__(self, sock=None):
        self.tcpConnectionSock = TcpConnectionSock(sock)

    def fileno(self):
        return self.tcpConnectionSock.fileno()

    async def recv(self, buffer_size=4096):
        # print('TcpConnection async def recv')
        return await self.tcpConnectionSock.recv(buffer_size)

    async def send(self, data=b''):
        # print('TcpConnection async def send')
        return await self.tcpConnectionSock.send(data)

    async def sendAll(self, data=b''):
        # print('TcpConnection async def sendAll')
        return await self.tcpConnectionSock.sendAll(data)

    def shutdown(self, mode=socket.SHUT_RDWR):
        # print('TcpConnection def shutdown')
        return self.tcpConnectionSock.shutdown(mode)

    def close(self):
        # print('TcpConnection def close')
        return self.tcpConnectionSock.close()

    def setsockopt(self, level=socket.SOL_SOCKET, optname=socket.SO_REUSEADDR, value=1):
        # print('TcpConnection def setsockopt')
        return self.tcpConnectionSock.setsockopt(level, optname, value)

    def setblocking(self, is_blocking=True):
        # print('TcpConnection def setblocking')
        return self.tcpConnectionSock.setblocking(is_blocking)

    def bind(self, host, port):
        # print('TcpConnection def bind')
        return self.tcpConnectionSock.bind(host, port)

    def listen(self, segmets_backlog=5):
        # print('TcpConnection def listen')
        return self.tcpConnectionSock.listen(segmets_backlog)

    def accept(self):
        # print('TcpConnection def accept')
        cli, addr = self.tcpConnectionSock.accept()
        cli = TcpConnection(cli)
        # print('TcpConnection accept', cli, addr)
        return cli, addr

    def connect(self, domain='localhost', port=80):
        # print('TcpConnection def connect')
        return self.tcpConnectionSock.connect(domain, port)

    # low level

    def make_segment(self, src, dst, seq, ack, flags, window_size=1024, chk_sum=0, urg_ptr=0):
        """
        | Len      | Meanig                   |
        |----------|--------------------------|
        | 16 16    | src-port#, dst-port#     |
        | 32       | sq#                      |
        | 32       | ack#                     |
        | 4 6 6 16 | len, empty, flags, Wind  |
        | 16 16    | chk sum, urg ptr         |
        | <var>    | Options                  |
        | <var>    | Data                     |

        Flags = (URG, ACK, PSH, RST, SYN, FIN)
        Options = (MMS, win mgm, RFC 854 1323)
        """
        return struct.pack(
            '!HHIIHHHH',
            src_port,
            dst_port,
            seq,
            ack,
            (5<<12)|flags,
            window_size,
            chk_sum,
            urg_ptr
        )

    def make_synack(self, src_port, dst_port, seq_no, ack_no):
        return make_segment(src_port, dst_port, seq_no, ack_no, FLAGS_ACK|FLAGS_SYN)

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

    def fix_checksum(segment, src_addr, dst_addr):
        pseudohdr = str2addr(src_addr) + str2addr(dst_addr) + \
            struct.pack('!HH', 0x0006, len(segment))
        seg = bytearray(segment)
        seg[16:18] = b'\x00\x00'
        seg[16:18] = struct.pack('!H', calc_checksum(pseudohdr + seg))
        return bytes(seg)
