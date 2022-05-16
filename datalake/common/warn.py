import os
import warnings


class Warn:
    def check_warning(self):
        if bool(os.environ.get('IGNORE_SIGHTING_BUILDER_WARNING')):
            warnings.filterwarnings('ignore', ".*Some keys aren't allowed for sightings and thus will be removed if you have set them. Check the classes for information on which keys are allowed.*")
