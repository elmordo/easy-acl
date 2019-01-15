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
import operator

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


Result = collections.namedtuple("Result", ["is_allowed", "level"])


class RuleList(object):

    def __init__(self):
        self.__rules = []

    @property
    def rules(self):
        return self.__rules

    def get_best_result(self, role, resource):
        """Return the best matching result or None, if no matching result was
        found.

        Args:
            role (easy_acl.role.Role): Role.
            resource (str): Resource to match.

        Returns:
            Optional[Result]: The best matching result or None if no result match.

        """
        matching_results = self._get_matching_result_candidates(role, resource)
        return self._get_best_result(matching_results)

    def _get_matching_result_candidates(self, role, resource):
        """Find candidates for the best result.

        Return list of candidates. If there is some result with level equal to
        zero, list with this item only is returned.

        Args:
            role (easy_acl.role.Role): Role instance.
            resource (str): Resource name to test against.

        Returns:
            List[Result]: List of matching results.

        """
        matching_results = []

        for r in self.__rules:
            try:
                result = r.resolve(role, resource)
            except ValueError:
                # rule does not match
                continue

            if result.level == 0:
                # exact match - return it
                return [result]

            matching_results.append(result)

        return matching_results

    def _get_best_result(self, results):
        """Get the best result.

        Args:
            results (List[Result]): Result list.

        Returns:
            Optional[Result]: Return the best result or None if there is no
                candidate.

        """
        # get the first
        if len(results) > 1:
            results.sort(key=operator.attrgetter("level"))
            return results[0]
        elif len(results) == 1:
            return results[0]
        else:
            return None


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

    RESOURCE_PART_DELIMITER = "."
    WILDCARD = "*"
    ESCAPE = "\\"

    def __init__(self, definition, evaluator):
        self.__definition = definition
        self.__evaluator = evaluator
        self._setup()

    @property
    def definition(self):
        return self.__definition

    @property
    def evaluator(self):
        return self.__evaluator

    @classmethod
    def split_resource_to_parts(cls, resource_name):
        """Split resource name to the parts.

        Args:
            resource_name (str): Resource name to split.

        Returns:
            Tuple[str]: Resource parts.

        """
        return tuple(resource_name.split(cls.RESOURCE_PART_DELIMITER))

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
        return Result(is_allowed, match_level)

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

    def _setup(self):
        """Setup the instance.

        """
        pass


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


class WildcardEnding(Simple):
    """Resource is possible to end with wildcard.

    Attributes:
        has_wildcard (bool): True, if there is wildcard at the end
        definition_parts (Tuple[str]): Parts of the definition.

    """

    @property
    def has_wildcard(self):
        return self.__has_wildcard

    @property
    def definition_parts(self):
        return self.__definition_parts

    def _setup(self):
        self.__definition_parts = self.split_resource_to_parts(self.definition)

        try:
            self.__has_wildcard = self.__definition_parts[-1] == self.WILDCARD
        except IndexError:
            self.__has_wildcard = False

    def _match_resource(self, resource):
        """Match resource to definition by `==` operator.

        Args:
            resource (str): Resource to match.

        Returns:
            int: Match level (0 if wildcard is not used, 1 minimal if there is
                wildcard in definition).

        Raises:
            ValueError: Resource does not match to the definition.

        """
        if self.__has_wildcard:
            parts = self.split_resource_to_parts(resource)

            if len(parts) < len(self.__definition_parts):
                raise ValueError()

            for i, dp in enumerate(self.__definition_parts[:-1]):
                if parts[i] != dp:
                    # not match
                    raise ValueError()

            return len(parts) - len(self.__definition_parts) + 1
        else:
            # no wildcard is set - match same as simple rule
            return super(WildcardEnding, self)._match_resource(resource)
