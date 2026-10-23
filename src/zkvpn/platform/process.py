"""Process lifecycle helpers that behave the same on every OS."""

import asyncio
import signal


async def wait_for_shutdown() -> None:
    """Return when the process is asked to stop (SIGTERM/SIGINT; Ctrl+C / Ctrl+Break on Windows).

    asyncio's ``add_signal_handler`` is unavailable on Windows, so there the classic
    ``signal.signal`` handlers hand the request over to the event loop thread-safely.
    """
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
    except NotImplementedError:
        def request_stop(*_):
            loop.call_soon_threadsafe(stop.set)
        for name in ("SIGINT", "SIGBREAK", "SIGTERM"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), request_stop)
    await stop.wait()
