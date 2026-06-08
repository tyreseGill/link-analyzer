import sys
import threading
import time
from typing import Callable, Any


def dot_animation(base_message: str, stop_event: threading.Event):
    """
    Loads animation cycle of three dots being generated, removed, regenerated, and so on.

    :param base_message: The portion of a message which is to remain static.
    :param stop_event: The flag that determines when to stop the animation.
    """
    dynamic_message = base_message
    dot_str = " . "
    max_message_length = len(base_message) +  len(dot_str * 3)
    num_dots_to_load = 0

    def edit_line(message: str):
        sys.stdout.write("\r" + message)
        sys.stdout.flush()

    def clear_line():
        sys.stdout.write("\r" + (" " * max_message_length))
        sys.stdout.write("\r")
        sys.stdout.flush()

    # Runs animation until function completes its task
    while not stop_event.is_set():
        # 
        if (num_dots_to_load + 1) % 4 == 0:
            dynamic_message = base_message
            num_dots_to_load = 0
            clear_line()
        else:
            num_dots_to_load += 1
        
        # Adds X number of dots to be loaded to root message
        dynamic_message = base_message + (dot_str * num_dots_to_load)

        edit_line(dynamic_message)
        time.sleep(0.5)

    clear_line()


def display_load_animation(task_func: Callable, message: str, *args: tuple) -> Any:
    """
    Runs a loading animation as some function executes.

    :param task_func: The function to load an animation for as it completes a task.
    :param message: The message to be displayed in loading animation.
    :return: Any expected output from the passed function.
    """
    stop_event = threading.Event()

    loader = threading.Thread(
        target=dot_animation,
        args=(message, stop_event)
    )

    loader.start()  # Starts running load animation

    try:      # Wait for function to return something
        result = task_func(*args)
    finally:  # Stops running load animation
        stop_event.set()
        loader.join()

    return result
