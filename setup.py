import os

from setuptools import find_packages, setup

from datalake_scripts.cli import Cli

here = os.path.abspath(os.path.dirname(__file__))

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='datalake-scripts',
    version=Cli.VERSION,
    author='OCD',
    author_email='cert-contact.ocd@orange.com',
    description='A collection of scripts to easily use the API of OCD Datalake',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/cert-orangecyberdefense/datalake/',
    package_dir={
        '': '.',
    },
    packages=find_packages(),
    install_requires=[
        "requests",
        "halo"
    ],
    test_suite='nose.collector',
    entry_points={
        'console_scripts': (
            'get_users = datalake_scripts.scripts.get_users:main',
            'get_threats_by_hashkey = datalake_scripts.scripts.get_threats_by_hashkey:main',
            'add_new_threats = datalake_scripts.scripts.add_new_threats:main',
            'add_new_comment_or_tags = datalake_scripts.scripts.add_new_comment_or_tags:main',
            'edit_score = datalake_scripts.scripts.edit_score:main',
            'get_threats_from_query_hash = datalake_scripts.scripts.get_threats_from_query_hash:main',
            f'{Cli.CLI_NAME} = datalake_scripts.cli:main'
        ),
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
        'Topic :: Security',
        'Natural Language :: English',
    ],
    include_package_data=True,
    package_data={
        'datalake': ['config/endpoints.json'],
    },
    python_requires=">=3.6",
)
