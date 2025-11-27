import base64
import hashlib
import json
import aiohttp
import asyncio
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def _pad(s):
    pad_len = 16 - len(s) % 16
    return s + chr(pad_len) * pad_len


def _unpad(s):
    pad_len = s[-1]
    return s[:-pad_len]


class TapoCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        raw = json.dumps(data)
        enc = cipher.encrypt(_pad(raw).encode())
        return base64.b64encode(iv + enc).decode()

    def decrypt(self, payload):
        raw = base64.b64decode(payload)
        iv = raw[:16]
        enc = raw[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc)
        return json.loads(_unpad(dec))


class ApiClient:
    def __init__(self, email, password):
        self.email = email
        self.password = password

    async def p110(self, ip):
        return P110Device(ip, self.email, self.password)


class P110Device:
    def __init__(self, host, email, password):
        self.host = host
        key = hashlib.sha256((email + password).encode()).digest()[:16]
        self.cipher = TapoCipher(key)

    async def _post(self, data):
        enc = self.cipher.encrypt(data)
        payload = {"method": "securePassthrough", "params": {"request": enc}}

        async with aiohttp.ClientSession() as session:
            async with session.post(f"http://{self.host}/app", json=payload) as resp:
                r = await resp.json()

        resp_data = r["result"]["response"]
        dec = self.cipher.decrypt(resp_data)
        return dec

    async def get_device_info(self):
        return await self._post({"method": "get_device_info"})

    async def get_energy_usage(self):
        res = await self._post({"method": "get_energy_usage"})
        class Energy:
            pass
        e = Energy()
        for k, v in res.items():
            setattr(e, k, v)
        return e

    async def on(self):
        return await self._post({"method": "set_device_info", "params": {"on": True}})

    async def off(self):
        return await self._post({"method": "set_device_info", "params": {"on": False}})
