# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


class Role(object):
    """Define one role.

    Args:
        name (str): Role name.
        parent (Union{Role, None}): Parent role.
        default_permission (Union{Callable, None}): Default permission resolver.

    Attributes:
        name (str): Role name.
        parent (Union{Role, None}): Parent role.
        default_permission (Union{Callable, None}): Default permission resolver.

    """

    def __init__(self, name, parent=None, default_permission=None):
        self.__name = name
        self.__parent = parent
        self.__default_permission = default_permission

    @property
    def name(self):
        return self.__name

    @property
    def parent(self):
        return self.__parent

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

    def create_role(self, name, parent_name=None, default_permission=None):
        """Create new role instance, add it to container and return it

        Args:
            name (str): Name of the role.
            parent_name (Union{str, None}): Name of the parent role.
            default_permission (Union{Callabke, None}): Default permission.

        Returns:
            Role: New role.

        Raises:
            AssertionError: Role name is not unique.
            ValueError: Parent role not found.

        """
        if parent_name is not None:
            parent = self.get_role(parent_name)
        else:
            parent = None

        role = Role(name, parent, default_permission)
        self.add_role(role)

        return role

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
