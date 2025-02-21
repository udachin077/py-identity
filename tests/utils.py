import asyncio


def future_from_result(return_value):
    future = asyncio.Future()
    future.set_result(return_value)
    return future
