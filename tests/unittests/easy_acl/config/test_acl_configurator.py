# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import mock
import os

import easy_acl.config as config
import easy_acl.role as roles
import easy_acl.rule as rules
import easy_acl.evaluator as evaluators

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


def test_init():
    """Test instance initialization.

    """
    instance = config.AclConfigurator()

    assert instance.role_klass is roles.Role
    assert instance.roles == []
    assert instance.default_role_evaluators == {}
    assert instance.rules == {}

    assert len(instance.rule_factories) == 2
    assert len(instance.evaluators_lookup) == 2

    assert "simple" in instance.rule_factories
    assert "wildcardending" in instance.rule_factories

    assert "allow" in instance.evaluators_lookup
    assert "deny" in instance.evaluators_lookup

    assert instance.rule_factories["simple"] is rules.Simple
    assert instance.rule_factories["wildcardending"] is rules.WildcardEnding

    assert instance.evaluators_lookup["allow"] is evaluators.allow
    assert instance.evaluators_lookup["deny"] is evaluators.deny


def test_load_data_from_config_file():
    instance = config.AclConfigurator()
    instance.load_data_from_config_file(SAMPLE_CONFIG_PATH)

    assert_config_rule_factories(instance)
    assert_config_evaluators_lookup(instance)
    assert_config_roles(instance)
    assert_config_default_role_evaluators(instance)
    assert_config_rules(instance)


def test_create_new_acl():
    instance = config.AclConfigurator()
    instance.load_data_from_config_file(SAMPLE_CONFIG_PATH)

    acl = instance.create_new_acl()

    assert_acl_roles(acl)


def assert_config_rule_factories(instance):
    factories = instance.rule_factories

    assert len(factories) == 3
    expected_factories = {
        "simple": rules.Simple,
        "wildcardending": rules.WildcardEnding,
        "also_simple": rules.Simple
    }

    for k, f in factories.items():
        assert k in expected_factories
        assert expected_factories[k] is f


def assert_config_evaluators_lookup(instance):
    evaluators_ = instance.evaluators_lookup

    assert len(evaluators_) == 4

    expected_evaluators = {
        "allow": evaluators.allow,
        "deny": evaluators.deny,
        "other_allow": evaluators.allow,
        "other_deny": evaluators.deny,
    }

    for k, e in evaluators_.items():
        assert k in expected_evaluators
        assert expected_evaluators[k] == e


def assert_config_roles(instance):
    assert len(instance.roles) == 4
    found_roles = []

    for rd in instance.roles:
        assert rd.name not in found_roles
        found_roles.append(rd.name)

        if rd.name == "user":
            assert rd.parents == tuple()
        elif rd.name == "presenter":
            assert rd.parents == tuple()
        elif rd.name == "antimulti":
            assert rd.parents == ("presenter",)
        elif rd.name == "admin":
            assert rd.parents == ("user", "presenter")
        else:
            assert False, "Unexpected role '{}'".format(rd.name)


def assert_config_default_role_evaluators(instance):
    ev = instance.default_role_evaluators

    assert len(ev) == 1
    assert "admin" in ev
    assert ev["admin"] == "allow"


def assert_config_rules(instance):
    rs = instance.rules
    expected_rules = {
        "user": [
            ("post.list", "simple", "allow"),
            ("system.*", "wildcardending", "deny"),
            ("system.my-account.*", "wildcardending", "allow"),
        ],
        "presenter": [
            ("post.admin", "simple", "allow")
        ],
        "admin": [
            ("top-secret.*", "wildcardending", "deny")
        ]
    }

    assert len(rs) == len(expected_rules)

    for rn, rl in rs.items():
        assert rn in expected_rules
        assert len(rl) == len(expected_rules[rn])

        for rule_config, expected in zip(rl, expected_rules[rn]):
            assert rule_config.definition == expected[0]
            assert rule_config.rule_type == expected[1]
            assert rule_config.evaluator_type == expected[2]


def assert_acl_roles(acl):
    role_manager = acl.roles
    assert len(role_manager.get_names()) == 4

    names = ["user", "admin", "antimulti", "presenter"]
    lookup = {n: role_manager.get_role(n) for n in names}

    for n in names:
        r = lookup[n]

        if n == "user":
            assert r.default_evaluator is None
            assert r.parents == tuple()
        elif n == "presenter":
            assert r.default_evaluator is None
            assert r.parents == tuple()
        elif n == "antimulti":
            assert r.default_evaluator is None
            assert r.parents == (lookup["presenter"],)
        elif n == "admin":
            assert r.default_evaluator is evaluators.allow
            assert r.parents == (lookup["user"], lookup["presenter"])
        else:
            assert False, "Unknown role '{}'".format(n)



SAMPLE_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "sample_config.conf")
