from os import path
from typing import Dict
from functools import partial

from setuptools import setup
from setuptools import find_packages


version_info  = dict()
package_join_ = partial(path.join, path.abspath(path.dirname(__file__)), 'jwt_debugger')
with open(package_join_('__version__.py')) as f:
    exec(f.read(), version_info)


setup(
    name="jwt-debugger",
    version=version_info['__version__'],
    packages=find_packages(),
    install_requires=[
        'click>=7.1.2',
        'rich>=9.0.1',
        'requests>=2.24.0',
        'jwcrypto>=0.8',
    ],
    entry_points={
        'console_scripts': [
            'jwt-debugger=jwt_debugger:cli'
        ]
    }
)
