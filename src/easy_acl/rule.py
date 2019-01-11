# -*- coding: utf-8 -*-
"""Various rules.

Rules are used to match condition and resolve if user (defined by Role) is allowed
or not to access to the resource.

Result of a rule is `Result` instance (named tuple) with two attributes:

1. bool `is_allowed` - True if role is allowed to access the resource, False otherwise
2. int `level` - match level is used as reversed priority (smaller number is more
    importand) when there are more than one matching rule.

"""

from __future__ import absolute_import

import collections

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


Result = collections.namedtuple("Result", ["is_allowed", "level"])


class AbstractRule(object):
    """Abstract base for all rules.

    Args:
        defintion (str): Definition of the rule.
        evaluator (Callable[[easy_acl.role.Role, str, int, AbstractRule], bool]):
            evaluator of the rule.

    Attributes:
        defintion (str): Definition of the rule.
        evaluator (Callable[[easy_acl.role.Role, str, int, AbstractRule], bool]):
            evaluator of the rule.

    """

    def __init__(self, definition, evaluator):
        self.__definition = definition
        self.__evaluator = evaluator

    @property
    def definition(self):
        return self.__definition

    @property
    def evaluator(self):
        return self.__evaluator

    def resolve(self, role, resource):
        """Try to resolve rule against resource.

        Args:
            role (easy_acl.role.Role): Role instance.
            resource (str): Resource.

        Raises:
            ValueError: Resource is not matching to rule.

        """
        match_level = self._match_resource(resource)
        is_allowed = self._evaluate(role, resource, match_level)
        return Result()

    def _match_resource(self, resource):
        """Match resource against the rule.

        Args:
            resource (str): Input resource.

        Returns:
            int: Match level.

        Raises:
            ValueError: Resource is not match.

        """
        raise NotImplementedError()

    def _evaluate(self, role, resource, match_level):
        """Evaluate resource access.

        Args:
            role (easy_acl.role.Role): Role instance.
            resource (str): Tested resource.
            match_level (int): Match level.

        Returns:
            bool: True if resource is allowed, False otherwise.

        """
        return self.__evaluator(role, resource, match_level, self)


class Simple(AbstractRule):
    """Simple rule matches resource strictly against rule defintion by `==`
    operator.

    No wildcards are supported (any wildcard is interpreted as part of the
    resource name). Result of the `_match_resource` method is always 0 (zero)
    or raise ValueError.

    Example:
        ...
        rule = Simple('my-resource', some_evaluator)

        r = rule.resolve(some_role, 'my-resource')
        # the `r` contains result with level=0

        x = rule.resolve(some_role, 'other-resource')
        # raise ValueError

    """

    def _match_resource(self, resource):
        """Match resource to definition by `==` operator.

        Args:
            resource (str): Resource to match.

        Returns:
            int: Always 0 (zero).

        Raises:
            ValueError: Resource does not match to the definition.

        """
        if self.definition == resource:
            return 0
        else:
            raise ValueError()
