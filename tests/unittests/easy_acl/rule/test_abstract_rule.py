# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import mock
import pytest

import easy_acl.rule as rule

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_init():
    definition = "foo-bar"
    evaluator = mock.Mock()
    instance = rule.AbstractRule(definition, evaluator)

    assert instance.definition == definition
    assert instance.evaluator is evaluator


def test_resolve():
    """Resolving of the permission raises NotImplementedError on this level.

    """
    instance = rule.AbstractRule("fooo", mock.Mock())

    with pytest.raises(NotImplementedError):
        instance.resolve(mock.Mock(), "foo-bar")
