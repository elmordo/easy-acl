# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


class Role(object):
    """Define one role.

    Args:
        name (str): Role name.
        parents (Union{Iterable{Role}, None}): Parent roles.
        default_permission (Union{Callable, None}): Default permission resolver.

    Attributes:
        name (str): Role name.
        parents (Tuple{Role}): Parent roles.
        default_permission (Union{Callable, None}): Default permission resolver.

    """

    def __init__(self, name, parents=None, default_permission=None):
        if parents is None:
            parents = []

        self.__name = name
        self.__parents = tuple(parents)
        self.__default_permission = default_permission

    @property
    def name(self):
        return self.__name

    @property
    def parents(self):
        return self.__parents

    @property
    def default_permission(self):
        return self.__default_permission


class RoleManager(object):
    """Container for roles.

    Each role must have unique name.

    """

    def __init__(self):
        self._roles = []

    def add_role(self, role):
        """Add existing role instance.

        Raises:
            AssertionError: Role name is not unique.

        """
        self._assert_name_not_exists(role.name)
        self._roles.append()

    def create_role(self, name, parent_names=None, default_permission=None):
        """Create new role instance, add it to container and return it

        Args:
            name (str): Name of the role.
            parent_names (Union{Iterable{str}, None}): Names of the parent roles.
            default_permission (Union{Callabke, None}): Default permission.

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

        role = Role(name, parents, default_permission)
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
