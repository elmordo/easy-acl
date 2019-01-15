# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import mock
import pytest

import easy_acl.role as role

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_init():
    """No roles are in manager.

    """
    manager = role.RoleManager()
    assert manager.get_names() == []


def test_add_unique_roles(manager):
    """Add two roles with unique names.

    """
    role_1 = role.Role("foo")
    role_2 = role.Role("bar")

    manager.add_role(role_1)
    manager.add_role(role_2)

    names = manager.get_names()

    assert len(names) == 2
    assert role_1.name in names
    assert role_2.name in names


def test_add_not_unique_roles(manager):
    """Add two roles with unique names.

    """
    role_1 = role.Role("foo")
    role_2 = role.Role("foo")

    manager.add_role(role_1)

    with pytest.raises(AssertionError):
        manager.add_role(role_2)

    names = manager.get_names()
    assert len(names) == 1
    assert role_1.name in names


def test_create_role_simple(manager):
    name = "foo"
    r = manager.create_role(name)

    assert_role(r, name, tuple(), None)

    names = manager.get_names()
    assert len(names) == 1
    assert name in names

    assert manager.get_role(name) is r


def test_create_role_with_args(manager):
    p1 = "foo"
    p2 = "bar"

    manager.create_role(p1)
    manager.create_role(p2)

    parents = (p1, p2)
    default_evaluator = mock.Mock()

    name = "foobar"
    r = manager.create_role(name, parents, default_evaluator)

    assert_role(r, name, parents, default_evaluator)

    names = manager.get_names()
    assert len(names) == 3
    assert name in names

    assert manager.get_role(name) is r


def test_create_role_with_kwargs(manager):
    p1 = "foo"
    p2 = "bar"

    manager.create_role(p1)
    manager.create_role(p2)

    parents = (p1, p2)
    default_evaluator = mock.Mock()

    name = "foobar"
    r = manager.create_role(name, parent_names=parents, default_evaluator=default_evaluator)

    assert_role(r, name, parents, default_evaluator)

    names = manager.get_names()
    assert len(names) == 3
    assert name in names

    assert manager.get_role(name) is r

def test_get_names(manager):
    """All added role names has to be in return value of the `get_names` method.

    """
    names = ["r1", "r2", "r3"]

    for n in names:
        manager.create_role(n)

    stored_names = manager.get_names()

    assert len(names) == len(stored_names)

    for n in names:
        assert n in stored_names


def test_get_existing_role(manager):
    name = "foo"
    r = manager.create_role(name)
    manager.create_role("bar")

    assert manager.get_role(name) is r


def test_get_not_existing_role(manager):
    manager.create_role("foo")

    with pytest.raises(ValueError):
        manager.get_role("bar")


def assert_role(role_instance, name, parents, default_evaluator):
    assert isinstance(role_instance, role.Role)
    assert role_instance.name == name
    assert role_instance.default_evaluator is default_evaluator

    if parents is None:
        assert role_instance is tuple()
    else:
        parent_names = tuple([r.name for r in role_instance.parents])
        assert parent_names == parents



@pytest.fixture
def manager():
    return role.RoleManager()
