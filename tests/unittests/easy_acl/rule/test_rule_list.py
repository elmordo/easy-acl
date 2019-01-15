# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import mock
import pytest

import easy_acl.rule as rule

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_init():
    """Assert initial values of the rule list.

    """
    instance = rule.RuleList()
    assert instance.rules == []


def test_rules_assign():
    """The `rules` property is read only.

    """
    instance = rule.RuleList()

    with pytest.raises(AttributeError):
        instance.rules = []


def test_get_best_result_level_zero():
    role = mock.Mock()
    resource = mock.Mock()

    instance = rule.RuleList()
    instance.rules.append(create_matching_rule(True, 0))
    instance.rules.append(create_matching_rule(True, 1))
    instance.rules.append(create_matching_rule(True, 2))

    result = instance.get_best_result(role, resource)

    assert result.level == 0
    assert result.is_allowed is True


def test_get_best_result_not_matching():
    role = mock.Mock()
    resource = mock.Mock()

    instance = rule.RuleList()
    instance.rules.append(create_not_matching_rule())
    instance.rules.append(create_not_matching_rule())
    instance.rules.append(create_not_matching_rule())

    result = instance.get_best_result(role, resource)
    assert result is None


def test_get_best_result_more_matching():
    role = mock.Mock()
    resource = mock.Mock()

    instance = rule.RuleList()
    instance.rules.append(create_not_matching_rule())
    instance.rules.append(create_not_matching_rule())
    instance.rules.append(create_not_matching_rule())
    instance.rules.append(create_matching_rule(False, 1))
    instance.rules.append(create_matching_rule(True, 1))
    instance.rules.append(create_matching_rule(True, 2))

    result = instance.get_best_result(role, resource)

    assert result is not None
    assert result.is_allowed is False
    assert result.level == 1


def create_matching_rule(is_allowed, level):
    rule_instance = mock.Mock()
    rule_instance.resolve.return_value = rule.Result(is_allowed, level)
    return rule_instance


def create_not_matching_rule():
    rule_instance = mock.Mock()
    rule_instance.resolve.side_effect = ValueError()
    return rule_instance
