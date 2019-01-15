# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import pytest

import easy_acl.acl as acl
import easy_acl.role as roles
import easy_acl.rule as rules
import easy_acl.evaluator as evaluators

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_init():
    """All values are empty and default evaluator is deny

    """
    instance = acl.Acl()

    assert instance.roles.get_names() == []
    assert instance.default_evaluator is evaluators.deny


def test_init_with_evaluator():
    instance = acl.Acl(evaluators.allow)

    assert instance.roles.get_names() == []
    assert instance.default_evaluator is evaluators.allow


def test_is_allowed_simple_allow(instance):
    assert instance.is_allowed("user", "index.index")


def test_is_allowed_global_default(instance):
    assert not instance.is_allowed("user", "default.page")


@pytest.fixture
def instance():
    instance = acl.Acl()
    setup_roles(instance)
    setup_rules(instance)

    return instance


def setup_roles(acl):
    user = roles.Role("user")
    presenter = roles.Role("presenter", default_evaluator=evaluators.allow)
    admin = roles.Role("admin", parents=(user, presenter))

    acl.roles.add_role(user)
    acl.roles.add_role(presenter)
    acl.roles.add_role(admin)


def setup_rules(acl):
    acl.add_rule("user", rules.Simple("index.index", evaluators.allow))
