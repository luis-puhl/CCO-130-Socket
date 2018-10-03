import asyncio
import time

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
    reader, writer = await asyncio.open_connection('127.0.0.1', 8888)

    print(f'Send: {message!r}')
    writer.write(message.encode())

    data = await reader.read(100)
    print(f'Received: {data.decode()!r}')

    print('Close the connection')
    writer.close()

async def tcp_echo_server():
    print('started at', time.strftime('%X'))

    server = await asyncio.start_server(handle_echo, '127.0.0.1', 8888)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

    print('finished at', time.strftime('%X'))

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
