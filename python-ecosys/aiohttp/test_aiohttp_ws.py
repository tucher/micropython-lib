# Test the WebSocket handshake's check of Sec-WebSocket-Accept.
import asyncio
import binascii
import hashlib
import io
import random

from aiohttp.aiohttp_ws import WebSocketClient, WS_GUID


class Reader:
    def __init__(self, data):
        self._data = io.BytesIO(data)

    async def readline(self):
        return self._data.readline()


def answer(accept):
    async def req(method, url, ssl=None, headers=None, is_handshake=False, version=None):
        key = headers["Sec-WebSocket-Key"].encode()
        value = accept(key)
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        )
        if value is not None:
            response += b"Sec-WebSocket-Accept: " + value + b"\r\n"
        return Reader(response + b"\r\n"), None

    return req


def right(key):
    return binascii.b2a_base64(hashlib.sha1(key + WS_GUID).digest())[:-1]


async def handshake(accept):
    ws = WebSocketClient({})
    try:
        await ws.connect("ws://example.com/", handshake_request=answer(accept))
    except ValueError:
        return "refused"
    return "accepted"


async def main():
    random.seed(1)
    assert await handshake(right) == "accepted"
    assert await handshake(lambda key: right(b"another key")) == "refused"
    assert await handshake(lambda key: None) == "refused"
    print("OK")


asyncio.run(main())
