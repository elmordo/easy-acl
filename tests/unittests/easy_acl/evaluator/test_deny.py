# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import mock

import easy_acl.evaluator as evaluator

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_deny():
    assert evaluator.deny(mock.Mock(), mock.Mock(), mock.Mock(), mock.Mock()) is False
