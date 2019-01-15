# -*- coding: utf-8 -*-
"""Role management.

Role structure and management. The base class `Role` can be derived and extended
by additional properties. All properties of role should be immutable. Each role
can has none, one or more parents. When access permission is evaluated and there
is no specific rule of ACL query, parents are evaluated in order of parents sequence.

If no matching rule is found for ACL query, role can has default evaluator. This
default evaluator is used when no matching rule is found.

The `RoleManager` instance can store multiple roles with unique names. Role list
can be setup by calling `add_role` method (e.g. when custom class of role is used)
or by `create_role` method and common `Role` class is used.

Example
-------

def deny_all(*args, **kwargs):
    return False

manager = RoleManager()

# guest role is injected by `add_role` method
guest = Role("guest", default_evaluator=deny_all)
manager.add_role(guest)

# create user and moderator role
user = manager.create_role("user")
moderator = manager.create_role("moderator")

# create admin role inheriting rules from user and moderator
admin = manager.create_role("admin", parents=[user, moderator])


"""

from __future__ import absolute_import

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


class Role(object):
    """Define one role.

    Args:
        name (str): Role name.
        parents (Optional[Iterable[Role]]): Parent roles.
        default_evaluator (Optional[Callable[[Role, str, int,
            easy_acl.rule.AbstractRule], bool]]): Default permission resolver.

    Attributes:
        name (str): Role name.
        parents (Tuple[Role]): Parent roles.
        default_evaluator (Optional[Callable[[Role, str, int,
            easy_acl.rule.AbstractRule], bool]]): Default permission resolver.

    """

    def __init__(self, name, parents=None, default_evaluator=None):
        if parents is None:
            parents = []

        self.__name = name
        self.__parents = tuple(parents)
        self.__default_evaluator = default_evaluator

    @property
    def name(self):
        return self.__name

    @property
    def parents(self):
        return self.__parents

    @property
    def default_evaluator(self):
        return self.__default_evaluator


class RoleManager(object):
    """Container for roles.

    Each role must have unique name.

    """

    def __init__(self):
        self._roles = []

    def add_role(self, role):
        """Add existing role instance.

        Args:
            role (Role): Role to add.

        Raises:
            AssertionError: Role name is not unique.

        """
        self._assert_name_not_exists(role.name)
        self._roles.append(role)

    def create_role(self, name, parent_names=None, default_evaluator=None):
        """Create new role instance, add it to container and return it

        Args:
            name (str): Name of the role.
            parent_names (Optional[Iterable[str]]): Names of the parent roles.
            default_evaluator (Optional[Callable[[Role, str, int,
                easy_acl.rule.AbstractRule], bool]]): Default permission.

        Returns:
            Role: New role.

        Raises:
            AssertionError: Role name is not unique.
            ValueError: Parent role not found.

        """
        if parent_names is not None:
            parents = [self.get_role(n) for n in parent_names]
        else:
            parents = None

        role = Role(name, parents, default_evaluator)
        self.add_role(role)

        return role

    def get_names(self):
        """Get stored role names.

        Returns:
            List[str]: List of roles.

        """
        return list(map(lambda x: x.name, self._roles))

    def get_role(self, name):
        """Get role by its name.

        Args:
            name (str): Name of the role.

        Returns:
            Role: Role with required name.

        Raises:
            ValueError: Role with name does not exists.

        """
        roles = list(filter(lambda r: r.name == name, self._roles))

        if len(roles) != 1:
            raise ValueError("Role '{}' does not exist".format(name))

        return roles[0]

    def _assert_name_not_exists(self, name):
        """Raise exception if role with name exists.

        Args:
            name (str): Name to assert.

        Raises:
            AssertionError: Role with name exists.

        """
        assert len(list(filter(lambda r: r.name == name, self._roles))) == 0
