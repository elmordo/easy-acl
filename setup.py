# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

from setuptools import setup

__copyright__ = "Copyright (c) 2015-2018 Ing. Petr Jindra. All Rights Reserved."


SRC_DIR="src"


def get_version():
    return "0.1"


setup(
    version=get_version(),
    name="easy-acl",
    package_dir={"": SRC_DIR},
    packages=["easy_acl"]
)
