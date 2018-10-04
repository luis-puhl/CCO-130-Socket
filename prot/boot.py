import socket
import asyncio
import time
from TcpSock import TcpSock

async def main():
    print('started at', time.strftime('%X'))
    app, test = await asyncio.gather(
        tcp_echo_server(),
        tcp_echo_client('Hello World!'),
    )
    print('finished at', time.strftime('%X'))
    print(app, test)
    return app, test

async def tcp_echo_client(message):
    await asyncio.sleep(1)
    # rsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # rsock.connect(('localhost', 8888))
    rsock = TcpSock()
    rsock.connect('localhost', 8888)
    # reader, writer = await asyncio.open_connection('127.0.0.1', 8888)
    reader, writer = await asyncio.open_connection(sock=rsock)

    print(f'client Send: {message!r}')
    writer.write(message.encode())

    data = await reader.read(100)
    print(f'client Received: {data.decode()!r}')

    print(f'client Close the connection')
    print()
    writer.close()

async def tcp_echo_server():
    print(f'Server started at', time.strftime('%X'))

    server = await asyncio.start_server(handle_echo, '127.0.0.1', 8888)

    addr = server.sockets[0].getsockname()
    print(f'Server Serving on {addr}')

    async with server:
        await server.serve_forever()

    print(f'Server finished at', time.strftime('%X'))

async def handle_echo(reader, writer):
    data = await reader.read(100)
    message = data.decode()
    addr = writer.get_extra_info('peername')

    print(f"Received {message!r} from {addr!r}")

    print(f"Send: {message!r}")
    writer.write(data)
    await writer.drain()

    print("Close the connection")
    writer.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        raise e
        # logging...etc
        pass
    except KeyboardInterrupt as e:
        print('KeyboardInterrupt...')
        # logging...etc
        pass
    finally:
        pass
