# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

import collections
import sys

import easy_acl.evaluator as evaluators
import easy_acl.role as roles
import easy_acl.rule as rules

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


class Acl(object):
    """Resolve requests to access permissions.

    Args:
        default_evaluator (Optional[Callable[[Role, str, int,
            easy_acl.rule.AbstractRule], bool]]): Evaluator used if no rule found.
                Default is deny.

    Attributes:
        roles (easy_acl.role.RoleManager): Role manager
        default_evaluator (Callable[[Role, str, int, easy_acl.rule.AbstractRule],
            bool]): Default evaluator.

    """

    def __init__(self, default_evaluator=None):
        if default_evaluator is None:
            default_evaluator = evaluators.deny

        self.__default_evaluator = default_evaluator
        self.__roles = roles.RoleManager()
        self.__rules = collections.defaultdict(rules.RuleList)
        self.__cache = {}

    @property
    def roles(self):
        return self.__roles

    @property
    def default_evaluator(self):
        return self.__default_evaluator

    @property
    def rules(self):
        return dict(self.__rules.items())


    def clear_cache(self):
        """Clear internal cache.

        """
        self.__cache = {}

    def add_rule(self, role_name, rule):
        """Add new rule to the system.

        Args:
            role_name (str): Role name.
            rule (easy_acl.rule.AbstractRule): Rule to add.

        """
        role = self.__roles.get_role(role_name)
        self.__rules[role].rules.append(rule)

    def is_allowed(self, role_name, resource):
        """Test if access to the resource is allowed for role defined by its name.

        Args:
            role_name (str): Role name.
            resource (str): Resource name.

        Returns:
            bool: True if access is granted, False otherwise.

        Raises:
            ValueError: Role with given name was not found.

        """
        role = self.__roles.get_role(role_name)
        key = self._get_cache_key(role, resource)

        try:
            return self.__cache[key]
        except KeyError:
            result = self._get_permission(role, resource)
            self.__cache[key] = result
            return result

    def _get_cache_key(self, role, resource):
        """Create key for the cache.

        Args:
            role (easy_acl.Role): Role instance.
            resource (str): Resource.

        Returns:
            Tuple[str, str]: The key for the cache.

        """
        return (role.name, resource)

    def _get_permission(self, role, resource):
        """Get permission for the resource.

        Args:
            role (easy_acl.role.Role): Role to test.
            resource (str): Resource name.

        Returns:
            bool: True if access is granted, False otherwise.

        """
        result = self._search_for_best_rule_result(role, resource)

        if not result:
            result = self._get_default_permission(role, resource)

        return result.is_allowed

    def _search_for_best_rule_result(self, role, resource):
        """Search for the ACL query result.

        Search is done recursively over role's parents until the exact permission
        is found. This secures the best matching rule is found.

        Args:
            role (easy_acl.role.Role): Role instance.
            resource (str): Resource name.

        Returns:
            Optional[easy_acl.rule.Result]: Result of the query or None if no
                matching rule was found.

        """
        open_list = [role]
        best_result = None

        while len(open_list) > 0:
            current_role = open_list.pop(0)
            open_list += list(current_role.parents)
            rules = self.__rules[current_role]

            current_result = rules.get_best_result(current_role, resource)

            if current_result is not None:
                if current_result.level == 0:
                    return current_result
                elif best_result is None or best_result.level > current_result:
                    best_result = current_result

        return best_result

    def _get_default_permission(self, role, resource):
        """Get default permission for the role.

        This is usualy used when there is no matching rule for the resource and
        the role combination.

        Args:
            role (easy_acl.role.Role): The role instance.
            resource (str): Resource name.

        Returns:
            easy_acl.rule.Result: Simulated rule result.

        """
        evaluator = self._get_default_evaluator(role)
        is_allowed = evaluator(role, resource, 0, None)
        return rules.Result(is_allowed, sys.maxsize)

    def _get_default_evaluator(self, role):
        """Get default permission evaluator.

        If role has not any default evaluator, the role's parents are searched
        recursivey. If no parent has any default evaluator, the global default
        evaluator is returned.

        Args:
            role (easy_acl.role.Role): Role to search the evaluator for.

        Returns:
            Callable[[Role, str, int, easy_acl.rule.AbstractRule], bool]:
                default permission evaluator.

        """
        evaluator = None
        open_list = [role]

        while evaluator is None and len(open_list) > 0:
            current_role = open_list.pop(0)
            evaluator = current_role.default_evaluator
            open_list += list(current_role.parents)

        if evaluator is None:
            evaluator = self.__default_evaluator

        return evaluator
