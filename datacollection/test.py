import asyncio
from tapo import ApiClient

async def main():
    dev = await client.p110("192.168.40.125")
    info = await dev.get_device_info()
    print(info)


asyncio.run(main())
