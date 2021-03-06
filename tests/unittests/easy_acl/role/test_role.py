# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import mock
import pytest

import easy_acl.role as role

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_init_simple():
    """Only name is set.

    """
    name = "my_role"
    r = role.Role(name)

    assert r.name == name
    assert r.parents == tuple()
    assert r.default_evaluator is None


def test_init_full_args():
    """All possible arguments by positional method.

    """
    name = "my_role"
    parents = (mock.Mock(), )
    default_evaluator = mock.Mock()

    r = role.Role(name, parents, default_evaluator)
    assert r.name == name
    assert r.parents == parents
    assert r.default_evaluator is default_evaluator


def test_init_full_kwargs():
    """All possible arguments by positional method.

    """
    name = "my_role"
    parents = (mock.Mock(), )
    default_evaluator = mock.Mock()

    r = role.Role(name, parents=parents, default_evaluator=default_evaluator)
    assert r.name == name
    assert r.parents == parents
    assert r.default_evaluator is default_evaluator


def test_readonly_properties():
    """All properties are read only.

    """
    r = role.Role("my_role")

    with pytest.raises(AttributeError):
        r.name = "other_role"

    with pytest.raises(AttributeError):
        r.parents = mock.Mock()

    with pytest.raises(AttributeError):
        r.default_evaluator = mock.Mock()
