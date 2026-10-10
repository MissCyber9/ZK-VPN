"""Tiny TCP relay so containers on the Docker bridge can reach the environment's
outbound proxy (which only listens on the host's loopback).

usage: proxy_forward.py <listen-ip> <listen-port> <target-host> <target-port>
"""
import asyncio
import sys


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def handle(client_r, client_w, host, port):
    try:
        up_r, up_w = await asyncio.open_connection(host, port)
    except OSError:
        client_w.close()
        return
    await asyncio.gather(pipe(client_r, up_w), pipe(up_r, client_w))


async def main(listen_ip, listen_port, host, port):
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, host, port), listen_ip, int(listen_port))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:5]))
