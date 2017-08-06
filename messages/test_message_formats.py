import inspect

from common.messages.message import Message
from common.messages import message_formats


class TestMessageFormats:
    def test_implementation(self):
        """
        Checks if the classes in message_formats are implemented correctly
        """
        for name, cls in inspect.getmembers(message_formats, inspect.isclass):
            if cls is not Message:
                cls._check_class()
