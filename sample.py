# -*- coding: utf-8 -*-

import asyncio

import aiohttp
import requests

import anticens


def test_requests():
    try:
        r = requests.get('https://www.pixiv.net/')
        print(r.status_code)
        # print(r.text)
    except:
        print('Blocked!')


async def test_aiohttp():
    try:
        async with aiohttp.ClientSession(raise_for_status=True) as session:
            async with session.get('https://www.pixiv.net/') as r:
                print(r.status)
                # print(await r.text())
    except:
        print('Blocked!')


def main():
    loop = asyncio.get_event_loop()

    anticens.add_hosts(['www.pixiv.net'])
    anticens.enable()
    test_requests()
    loop.run_until_complete(test_aiohttp())

    anticens.disable()
    # Pixiv is blocked in China
    test_requests()
    loop.run_until_complete(test_aiohttp())


if __name__ == '__main__':
    main()
