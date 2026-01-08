import asyncio
import websockets
import logging

logging.basicConfig(level=logging.INFO)

async def test():
    uri = "wss://echo.websocket.org"
    print(f"Connecting to {uri}...")
    try:
        async with websockets.connect(uri) as ws:
            print("Connected!")
            await ws.send("Hello")
            resp = await ws.recv()
            print(f"Received: {resp}")
    except Exception as e:
        print(f"Error: {e}")

asyncio.run(test())
