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


if __name__ == '__main__':
    # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    # Coloque aqui o nome da sua placa de rede
    if_name = 'wlp8s0'
    fd.bind((if_name, 0))

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv_eth, fd)
    asyncio.get_event_loop().call_later(1, send_ping, fd)
    loop.run_forever()
