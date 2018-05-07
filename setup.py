from __future__ import absolute_import

from setuptools import setup, find_packages

setup(
    name='armrest',
    version='0.1.0',
    description='REST client library that enables command-line interaction and acceptance testing',
    author='George V. Reilly',
    author_email='george@reilly.org',
    license='Apache Software License 2.0',
    url='https://github.com/xBrite/armrest',
    packages=find_packages(exclude='tests'),
    install_requires=[
        'requests',
        'protobuf',
        'six',
    ],
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
        'tox',
        'mock',
    ],
    classifiers=[
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Topic :: Utilities',
    ],
    long_description=open('README.rst').read(),
    keywords="REST client testing CLI",
)
