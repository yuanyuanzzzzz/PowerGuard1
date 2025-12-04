import asyncio
import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

class KLAPClient:
    def __init__(self, email, password, host):
        self.email = email
        self.password = password
        self.host = host
        self.reader = None
        self.writer = None
        self.key = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, 443)

        # step one handshake
        self.writer.write(b"\x00\x01handshake1")
        await self.writer.drain()
        data = await self.reader.read(1024)

        # derive key
        h = SHA256.new()
        h.update(self.password.encode())
        self.key = h.digest()[:16]

    def _encrypt(self, obj):
        cipher = AES.new(self.key, AES.MODE_ECB)
        raw = json.dumps(obj).encode()
        pad = 16 - len(raw) % 16
        raw = raw + bytes([pad])*pad
        return cipher.encrypt(raw)

    def _decrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        dec = cipher.decrypt(data)
        pad = dec[-1]
        return json.loads(dec[:-pad])

    async def post(self, method, params=None):
        payload = {"method": method, "params": params}
        enc = self._encrypt(payload)
        self.writer.write(enc)
        await self.writer.drain()

        res = await self.reader.read(1024)
        return self._decrypt(res)

    async def get_info(self):
        return await self.post("get_device_info")

    async def get_energy(self):
        return await self.post("get_energy_usage")
