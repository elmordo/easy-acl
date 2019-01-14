# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import mock
import pytest

import easy_acl.rule as rule

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_init():
    evaluator = create_evaluator(False)
    definition = "foo-bar"

    r = rule.Simple(definition, evaluator)

    assert r.definition == definition
    assert r.evaluator is evaluator


def test_resolve_true():
    evaluator = create_evaluator(True)
    definition = "foo-bar"
    role = mock.Mock()
    instance = rule.Simple(definition, evaluator)

    result = instance.resolve(role, definition)

    assert result.is_allowed
    assert result.level == 0


def test_resolve_false():
    evaluator = create_evaluator(False)
    definition = "foo-bar"
    role = mock.Mock()
    instance = rule.Simple(definition, evaluator)
    result = instance.resolve(role, definition)

    assert not result.is_allowed
    assert result.level == 0


def test_resolve_not_matching():
    evaluator = create_evaluator(False)
    definition = "foo-bar"
    not_definition = "bar-foo"
    role = mock.Mock()
    instance = rule.Simple(definition, evaluator)

    with pytest.raises(ValueError):
        instance.resolve(role, not_definition)


def create_evaluator(result):
    evaluator = mock.Mock()
    evaluator.return_value = result
    return evaluator
