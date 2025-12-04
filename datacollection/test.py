import asyncio
from tapo import ApiClient

PLUG_IP = "192.168.40.104"

async def main():
    print("starting tapo test")

    client = ApiClient("iotlabucl@gmail.com", "IoTlabUCL")

    try:
        print("trying handshake")
        dev = await client.p110(PLUG_IP)
        print("handshake ok")

        print("fetching device info")
        info = await dev.getDeviceInfo()
        print("device info ok")
        print(info)

    except Exception as e:
        print("error during handshake")
        print(type(e), e)

asyncio.run(main())
