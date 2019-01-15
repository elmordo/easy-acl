# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import mock
import pytest

import easy_acl.rule as rule

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_init_without_wildcard():
    definition = "foo.bar.foo-bar"
    parts = ("foo", "bar", "foo-bar")
    evaluator = mock.Mock()

    instance = rule.WildcardEnding(definition, evaluator)

    assert not instance.has_wildcard
    assert instance.definition_parts == parts
    assert instance.evaluator is evaluator


def test_init_with_wildcard():
    definition = "foo.bar.foo-bar.*"
    parts = ("foo", "bar", "foo-bar", "*")
    evaluator = mock.Mock()

    instance = rule.WildcardEnding(definition, evaluator)

    assert instance.has_wildcard
    assert instance.definition_parts == parts
    assert instance.evaluator is evaluator


def test_resolve_matching_without_wildcard():
    definition = "foo.bar.foo-bar"
    role = mock.Mock()
    evaluator = mock.Mock()
    evaluator.return_value = True

    instance = rule.WildcardEnding(definition, evaluator)
    result = instance.resolve(role, definition)

    assert result.level == 0
    assert result.is_allowed == evaluator.return_value


def test_resolve_not_matching_without_wildcard():
    definition = "foo.bar.foo-bar"
    resource = "fooo"
    role = mock.Mock()
    evaluator = mock.Mock()
    evaluator.return_value = True

    instance = rule.WildcardEnding(definition, evaluator)

    with pytest.raises(ValueError):
        instance.resolve(role, resource)


def test_resolve_matching_with_wildcard():
    definition = "foo.bar.foo-bar.*"
    resource = "foo.bar.foo-bar.my.resource"
    expected_level = 2
    role = mock.Mock()
    evaluator = mock.Mock()
    evaluator.return_value = True

    instance = rule.WildcardEnding(definition, evaluator)
    result = instance.resolve(role, resource)

    assert result.level == expected_level
    assert result.is_allowed == evaluator.return_value


def test_resolve_not_matching_with_wildcard():
    definition = "foo.bar.foo-bar.*"
    resource = "bar.foo.bar-foo.not.matching"
    role = mock.Mock()
    evaluator = mock.Mock()
    evaluator.return_value = True

    instance = rule.WildcardEnding(definition, evaluator)

    with pytest.raises(ValueError):
        instance.resolve(role, resource)


def test_resolve_not_matching_with_wildcard_edgecase():
    definition = "foo.bar.foo-bar.*"
    resource = "foo.bar.foo-bar"
    role = mock.Mock()
    evaluator = mock.Mock()
    evaluator.return_value = True

    instance = rule.WildcardEnding(definition, evaluator)

    with pytest.raises(ValueError):
        instance.resolve(role, resource)
