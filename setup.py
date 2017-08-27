"""
setuptools configuration
"""

from setuptools import setup

setup(
    name='simpleca',
    version='0.1',
    py_modules=['simpleca'],
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        simpleca=simpleca:cli
    ''',
)
