#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import asyncio
import time
from App import App
from AppTest import AppTest

async def run_app():
    app = App()
    try:
        await app.listen()
    except KeyboardInterrupt:
        app.shutdown()

async def test_app():
    appTest = AppTest()
    await appTest.run_test()

async def main():
    print('started at', time.strftime('%X'))
    app, test = await asyncio.gather(
        run_app(),
        test_app(),
    )
    print('finished at', time.strftime('%X'))
    print(app, test)
    return app, test

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
