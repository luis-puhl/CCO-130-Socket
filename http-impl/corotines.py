import asyncio
import time

async def say_after(delay, what):
    await asyncio.sleep(delay)
    print(what)
    return what

async def main():
    print('started at', time.strftime('%X'))
    rest1, rest2 = await asyncio.gather(
        say_after(2, 'world'),
        say_after(1, 'hello'),
    )
    print(rest1)
    print('---')
    print(rest2)

    print('finished at', time.strftime('%X'))

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(e)
        # logging...etc
        pass
    except KeyboardInterrupt as e:
        print('KeyboardInterrupt...')
        # logging...etc
        pass
    finally:
        pass
