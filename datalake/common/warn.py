import os
import warnings


class Warn:
    @staticmethod
    def warning(message):
        if not os.environ.get('IGNORE_SIGHTING_BUILDER_WARNING', 'False').lower() in ('true', '1', 't'):
            warnings.warn(message)
