#!/bin/sh
docker run -it --rm -v /home/puhl/Documents/mestrado/Redes/trabalho/CCO-130-Socket/http-impl:/code -w '/code' -p 8080:8080 python python3 boot.py
