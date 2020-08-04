import os

from setuptools import find_packages, setup

from datalake_scripts.common.base_script import BaseScripts

here = os.path.abspath(os.path.dirname(__file__))

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='datalake-scripts',
    version='1.23.0',
    author='OCD',
    author_email='datalake-interne.ocd@orange.com',
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
            f'{BaseScripts.PACKAGE_NAME} = datalake_scripts.cli:main'
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
    package_data={'datalake_scripts': ['config/endpoints.json']},
    python_requires=">=3.6",
)
