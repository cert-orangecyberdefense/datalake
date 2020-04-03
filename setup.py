import os

from setuptools import find_packages, setup

from src.common.base_script import BaseScripts

here = os.path.abspath(os.path.dirname(__file__))

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='datalake-scripts',
    version='0.1.2',
    author='OCD',
    author_email='datalake-interne.ocd@orange.com',
    description='A collection of scripts to easily use the API of OCD Datalake',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='http://datalake.cert.orangecyberdefense.com/',
    package_dir={
        '': '.',
    },
    packages=find_packages(
        os.path.join(here, '.'),
    ),
    package_data={
        'scripts': [
            'data/*',
        ],
    },
    test_suite='nose.collector',
    entry_points={
        'console_scripts': (
            'get_users = src.scripts.get_users:main',
            'get_threats_by_hashkey = src.scripts.get_threats_by_hashkey:main',
            'add_new_threats = src.scripts.add_new_threats:main',
            'add_new_comment_or_tags = src.scripts.add_new_comment_or_tags:main',
            'edit_score = src.scripts.edit_score:main',
            'get_threats_from_query_hash = src.scripts.get_threats_from_query_hash:main',
            f'{BaseScripts.PACKAGE_NAME} = src.cli:main'
        ),
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
        'Topic :: Security',
        'Natural Language :: English',
        'Development Status :: 4 - Beta',
    ],
    include_package_data=True,
    python_requires=">=3.6",
)
