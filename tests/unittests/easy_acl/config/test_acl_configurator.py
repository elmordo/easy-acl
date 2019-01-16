# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

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
