#!/usr/bin/python3
import asyncio

class FatBirdServerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Data received: {!r}'.format(message))

        print('Send: {!r}'.format(message))
        # self.transport.write(data)
        # com esse tamanho, a respota é enviada em 8 partes com 27 datagramas total
        self.transport.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + 10000 * b"hello pombo\n")

        print('Close the client socket')
        self.transport.close()


async def main():
    # Get a reference to the event loop as we plan to use '''low-level APIs.'''
    loop = asyncio.get_running_loop()

    server = await loop.create_server(lambda: FatBirdServerProtocol(), '', 8080)

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
