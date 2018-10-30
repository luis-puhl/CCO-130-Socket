#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket
import asyncio
import select

class TcpConnection:
    def __init__(self, sock=None):
        if not sock:
            # The address family should be AF_INET (the default), AF_INET6, AF_UNIX, AF_CAN, AF_PACKET, or AF_RDS.
            # The socket type should be SOCK_STREAM (the default), SOCK_DGRAM, SOCK_RAW or perhaps one of the other SOCK_ constants.
            self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            self.setsockopt()
        else:
            self.sock = sock

    def fileno(self):
        # print('TcpConnection def fileno')
        return self.sock.fileno()

    async def recv(self, buffer_size=4096):
        print('TcpConnection async def recv')
        read, write, expe = select.select([self.sock], [], [], 0.01)
        for sock in read:
            return sock.recv(buffer_size)

    async def send(self, data=b''):
        print('TcpConnection async def send')
        read, write, expe = select.select([], [self.sock], [], 0.01)
        for sock in write:
            return self.sock.send(data)

    async def sendAll(self, data=b''):
        print('TcpConnection async def sendAll')
        read, write, expe = select.select([], [self.sock], [], 0.01)
        for sock in write:
            return self.sock.sendAll(data)

    def shutdown(self, mode=socket.SHUT_RDWR):
        print('TcpConnection def shutdown')
        return self.sock.shutdown(mode)

    def close(self):
        print('TcpConnection def close')
        return self.sock.close()

    def setsockopt(self, level=socket.SOL_SOCKET, optname=socket.SO_REUSEADDR, value=1):
        print('TcpConnection def setsockopt')
        # setsockopt(level, optname, value: int), Unix manual page setsockopt(2)
        return self.sock.setsockopt(level, optname, value)

    def setblocking(self, is_blocking=True):
        print('TcpConnection def setblocking')
        return self.sock.setblocking(is_blocking)

    def bind(self, host, port):
        print('TcpConnection def bind')
        return self.sock.bind((host, port))

    def listen(self, segmets_backlog=5):
        print('TcpConnection def listen')
        # Enable a server to accept connections.
        # If backlog is specified, it must be at least 0 (if it is lower, it is set to 0);
        # it specifies the number of unaccepted connections that the system will allow before refusing new connections.
        # If not specified, a default reasonable value is chosen.
        return self.sock.listen(segmets_backlog)

    def accept(self):
        print('TcpConnection def accept')
        cli, addr = self.sock.accept()
        cli = TcpConnection(cli)
        print('TcpConnection accept', cli, addr)
        return cli, addr

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
