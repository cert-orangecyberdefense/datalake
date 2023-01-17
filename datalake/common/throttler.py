import random
from time import sleep, time
from typing import Callable, Dict, List

THROTTLE_QUEUE: Dict[Callable[[], None], List[float]] = {}


def throttle(*, period: int, call_per_period: int):
    """
    Wrapper to throttle the number of time a function can be called

    :param period: time in seconds
    :param call_per_period: number of time the function can be called, if not the wrapper will wait
    """

    def inner_decorator(f):
        def wrapped(*args, **kwargs):
            previous_call = THROTTLE_QUEUE.get(f, [])
            call_time = time()

            # Clear calls made older than the given period
            while previous_call and previous_call[0] + period <= call_time:
                previous_call.pop(0)
            # Check if the number of call for the period don't allow the function to be called
            if len(previous_call) >= call_per_period:
                time_since_first_call = (call_time - previous_call[0])
                sleep(max(period - time_since_first_call, 0.1))  # Wait until a call has been made 'period' ago
                assert previous_call[0] + period <= time()
                previous_call.pop(0)
            previous_call.append(time())
            THROTTLE_QUEUE[f] = previous_call
            response = f(*args, **kwargs)
            return response

        return wrapped

    return inner_decorator


if __name__ == '__main__':
    """Example on how to use the throttle wrapper"""
    random.seed(0)
    PERIOD = 1
    CALL_PER_PERIOD = 2

    @throttle(period=PERIOD, call_per_period=CALL_PER_PERIOD)
    def f():
        sleep(random.randint(0, 2))
        return "hello world"


    start = time()
    total_calls = 10
    for i in range(total_calls):
        print(f'{f()} {i} {time()}')
    assert time() > start + ((total_calls / CALL_PER_PERIOD) - 1) * PERIOD
