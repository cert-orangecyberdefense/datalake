import os
import warnings


class Warn:
    @staticmethod
    def warning(message):
        if bool(os.environ.get('IGNORE_SIGHTING_BUILDER_WARNING')):
            warnings.warn(message)
