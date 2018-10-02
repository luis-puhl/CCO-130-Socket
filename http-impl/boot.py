#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from App import App
from AppTest import AppTest

def main():
    print('Starting App')
    app = App()
    app.start()
    print('Testing App')
    appTest = AppTest()
    # appTest.daemon = True
    appTest.start()

    # shutdown
    print('Waiting appTest.join(2)')
    appTest.join(2)
    print('Done appTest.join(2)')
    if appTest.is_alive():
        print('killing appTest')
        appTest.cancel()
    print('Test done')

    print('Waiting app.join()')
    try:
        app.join()
    except KeyboardInterrupt:
        print('KeyboardInterrupt, shuting down...')
        app.shutdown(2)
        if app.is_alive():
            print('killing app')
            app.cancel()

if __name__ == "__main__":
    main()
