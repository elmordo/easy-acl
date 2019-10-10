# -*- coding: utf-8 -*-
"""

"""

from __future__ import absolute_import

try:
    import configparser
except ImportError:
    # the python 2 fix
    import ConfigParser as configparser

import collections
import importlib
import re

import easy_acl.acl as acls
import easy_acl.rule as rules
import easy_acl.role as roles
import easy_acl.evaluator as evaluators

__copyright__ = "Copyright (c) 2015-2019 Ing. Petr Jindra. All Rights Reserved."


RoleDefinition = collections.namedtuple("RoleDefinition", "name parents")
RuleDefinition = collections.namedtuple("RuleDefinition", "definition rule_type "
    "evaluator_type")


class AclConfigurator(object):
    """Create and configure Acl instances.

    Attributes:
        role_klass (Type[easy_acl.role.Role]): Role factory
        rule_factories (Dict[str, Type[easy_acl.rule.AbstractRule]]): Lookup for
            the rule factories. Name is identifier and value is type or factory.
        evaluators_lookup (Dict[str, Callable[[easy_acl.role.Role, str, int,
            AbstractRule], bool]]): Lookup for evaluators. The key is evaluator
                name and value is evaluator itself.
        roles (List[RoleDefinition]): List of roles.
        default_role_evaluators (Dict[str, str]): The key is role name and value
            is name of the evaluator.
        rules (Dict[str, List[RuleDefinition]]): Definitions of rules. The key is
            the role name and value is list of the rule definitions.

    """

    SECTION_RULE_TYPES = "rules"
    SECTION_ROLES = "roles"
    SECTION_EVALUDATOR_TYPES = "evaluators"
    SECTION_DEFAULT_ROLE_EVALUATORS = "default_evaluators"
    SECTION_GLOBAL_SETTINGS = "global"

    GLOBAL_EVALUATOR = "evaluator"

    REGEXP_ROLE_RULE_SECTION = re.compile("([a-zA-Z0-9_]+)_rules")

    def __init__(self):
        self.role_klass = roles.Role
        self.rule_factories = self._create_rule_factories()
        self.evaluators_lookup = self._create_evaluator_lookup()
        self.roles = []
        self.default_role_evaluators = {}
        self.rules = collections.defaultdict(list)
        self.raw_config = None

    def create_new_acl(self):
        """Create new Acl instance and setup it.

        Returns:
            easy_acl.acl.Acl: Acl instance.

        Raises:
            ValueError: Config is invalid.
            KeyError: Missig reference to evaluator type or rule type.

        """
        instance = acls.Acl()
        self.setup_instance(instance)
        return instance

    def load_data_from_config_file(self, filename):
        """Load data from config file and setup self by this data.

        Args:
            filename (str): Name of the file.

        """
        config = self._read_config(filename)
        self.raw_config = config
        self.process_dict_like_config(config)

    def process_dict_like_config(self, config):
        """Setup self from a dict like data.

        Args:
            config [Dict[str, Dict[str, str]]]: Config data.

        """
        def try_config(section, method):
            try:
                method(config[section])
            except KeyError:
                pass

        try_config(self.SECTION_RULE_TYPES, self.setup_rule_types)
        try_config(self.SECTION_EVALUDATOR_TYPES, self.setup_evaluators_types)
        try_config(self.SECTION_GLOBAL_SETTINGS, self.setup_global_settings)
        try_config(self.SECTION_ROLES, self.setup_roles)
        try_config(self.SECTION_DEFAULT_ROLE_EVALUATORS, self.setup_role_evaluators)

        self.setup_rules(config)

    def setup_instance(self, instance):
        """Setup existing Acl instance by data from loaded configuration.

        Args:
            instance (easy_acl.acl.Acl): Instance to setup.

        Raises:
            ValueError: Config is invalid.
            KeyError: Missig reference to evaluator type or rule type.

        """
        self._create_roles(instance)
        self._create_rules(instance)

    def setup_rule_types(self, config):
        """Setup rule types from config.

        The key is rule identifier and value is full qualified class name.

        Args:
            config (Dict[str, str]): Configuration data.

        """
        for k, v in config.items():
            self.rule_factories[k] = self._import_factory(v)

    def setup_evaluators_types(self, config):
        """Setup evaluators from config data.

        The key is evaluator identifier and value is full qualified class name.

        Args:
            config (Dict[str, str]): Config data.

        """
        for k, v in config.items():
            self.evaluators_lookup[k] = self._import_factory(v)

    def setup_global_settings(self, config):
        """Setup global ACL settings from the config data.

        Args:
            config (Dict[str, str]): Config data.

        """
        default_evaluator_name = config.get(self.GLOBAL_EVALUATOR)

        if default_evaluator_name is not None:
            self.default_evaluator = self.evaluators_lookup[default_evaluator_name]

    def setup_roles(self, config):
        """Setup role list from the config.

        The key is role name and value is sequence of parents separated by ",".

        Args:
            config (Dict[str, str]): Config data.

        """
        for name, parents in config.items():
            if len(parents):
                parent_names = tuple([p.strip() for p in parents.split(",")])
            else:
                parent_names = tuple()

            self.roles.append(RoleDefinition(name, parent_names))

    def setup_role_evaluators(self, config):
        """Setup roles' default evaluators.

        The key is role name and value is evaluator identifier.

        Args:
            config (Dict[str, str]): Config data.

        """
        for k, v in config.items():
            self.default_role_evaluators[k] = v

    def setup_rules(self, config):
        """Setup rules for all roles.

        Args:
            config (Dict[str, Dict[str, str]]): Config data.

        """
        for k in config.keys():
            match_result = self.REGEXP_ROLE_RULE_SECTION.match(k)

            if not match_result:
                continue

            role_name = match_result.group(1)
            self.setup_role_rules(role_name, config[k])

    def setup_role_rules(self, role_name, config):
        """Setup rules for one role.

        Args:
            role_name (str): Role name to do setup for.
            config (Dict[str, str]): Config data.

        """
        for definition, config in config.items():
            rule_type, eval_type = config.split(",")
            rd = RuleDefinition(definition, rule_type, eval_type)

            self.rules[role_name].append(rd)

    @staticmethod
    def _import_factory(pth):
        """Import factory function from given full qualified name.

        Args:
            pth (str): Name of the factory.

        Returns:
            Type: Factory.

        """
        path_parts = pth.split(".")
        factory_name = path_parts.pop()
        factory_package = ".".join(path_parts)

        package = importlib.import_module(factory_package)
        return getattr(package, factory_name)

    @staticmethod
    def _read_config(filename):
        """Read config from the file.

        Args:
            filename (str): Filename to read config from.

        Returns:
            configparser.ConfigParser: Config.

        """
        parser = configparser.ConfigParser()
        parser.read(filename)
        return parser

    @staticmethod
    def _create_rule_factories():
        """Create default (built-in) rule factories.

        Returns:
            Dict[str, Type[rules.AbstractRule]]: Lookup with default factories.

        """
        return {
            "simple": rules.Simple,
            "wildcardending": rules.WildcardEnding
        }

    @staticmethod
    def _create_evaluator_lookup():
        """Create lookup with built-in evaluators.

        Returns:
            Dict[str, Callable[[easy_acl.role.Role, str, int, AbstractRule],
                bool]]: Lookup with evaluator functions.

        """
        return {
            "allow": evaluators.allow,
            "deny": evaluators.deny
        }

    def _create_roles(self, instance):
        """Create roles and write them into Acl instance.

        Args:
            instance (easy_acl.acl.Acl): Acl instance to update.

        """
        role_lookup = {x.name: x for x in self.roles}
        role_order = self._get_role_order()

        for rn in role_order:
            role_definition = role_lookup[rn]
            role = self._create_role_from_definition(role_definition, instance.roles)
            instance.roles.add_role(role)

    def _create_role_from_definition(self, role_definition, role_manager):
        """Create new role from the definition.

        Type in `self.role_klass` is used as role.

        Args:
            role_definition (RoleDefinition): Role definition.
            role_manager (easy_acl.role.RoleManager): Role manager instance.

        Returns:
            easy_acl.role.Role: Role instance.

        Raises:
            ValueError: Some parent role was not found.

        """
        name = role_definition.name
        parents = [role_manager.get_role(p) for p in role_definition.parents]
        evaluator = self._select_default_role_evaluator(role_definition)

        role = self.role_klass(name, parents, evaluator)
        return role

    def _select_default_role_evaluator(self, role_definition):
        """Select default evaluator for role.

        Args:
            role_definition (RoleDefinition): Role definition.

        Returns:
            Optional[Callable[[easy_acl.role.Role, str, int, AbstractRule],
                bool]]: Default evaluator for role or None if no default evaluator
                    is set.

        Raises:
            KeyError: Invalid default rule identifier.

        """
        try:
            evaluator_name = self.default_role_evaluators[role_definition.name]
        except KeyError:
            evaluator_name = None

        if evaluator_name is None:
            evaluator = None
        else:
            evaluator = self.evaluators_lookup[evaluator_name]

        return evaluator

    def _get_role_order(self):
        """Get role names ordered by their inheritance.

        Returns:
            List[str]: Role names.

        Raises:
            ValueError: Cycle or missing link found in resolving process.

        """
        result = []
        open_list = list(self.roles)
        do_step = True

        while len(open_list) > 0 and do_step:
            result, new_open = self._do_ordering_step(result, open_list)
            do_step = open_list != new_open
            open_list = new_open

        if len(open_list) > 0:
            raise ValueError("Unable to resolve role dependency tree")

        return result

    def _do_ordering_step(self, known_order, open_list):
        """Resolve roles with fulfilled dependencies.

        Role with all parents in known_order list is marked as resolved.

        Args:
            known_order (List[str]): Roles with known order.
            open_list (List[RoleDefinition]): List of role definitions waiting
                to be resolved.

        Returns:
            Tuple[List[str], List[RoleDefinition]]: Items from known_order list
                extended by items resolved in current step and values for next
                step open_list.

        """

        result = list(known_order)
        new_open = []

        for item in open_list:
            if self._is_all_parents_resolved(result, item.parents):
                result.append(item.name)
            else:
                new_open.append(item)

        return result, new_open

    def _is_all_parents_resolved(self, known_order, parents):
        """Test if all roles in parent list are in known_order list.

        Args:
            known_order (List[str]): List of resolved role names.
            parents (Tuple[str]): List of parents.

        Returns:
            bool: True if all parents are in known_order list, False otherwise.

        """
        for p in parents:
            if p not in known_order:
                return False

        return True

    def _create_rules(self, instance):
        """Create rules and write them into instance.

        Args:
            instance (easy_acl.acl.Acl): The Acl instance.

        """
        for role_name, rule_list in self.rules.items():
            self._create_rules_for_role(instance, role_name, rule_list)

    def _create_rules_for_role(self, instance, role_name, rule_list):
        """Create rules for one role and write them into instance.

        Args:
            instance (easy_acl.acl.Acl): The Acl instance.
            role_name (str): Name of the role to create rules for.
            rule_list (List[RuleDefinition]): Definitions of rules.

        Raises:
            KeyError: Rule factory or evaluator was not found.

        """
        for rule_definition in rule_list:
            rule = self._create_rule_from_definition(rule_definition)
            instance.add_rule(role_name, rule)

    def _create_rule_from_definition(self, rule_definition):
        """Create one rule from definition.

        Args:
            rule_definition (RuleDefinitio): Definition of the rule.

        Returns:
            easy_acl.rule.AbstractRule: Rule instance.

        Raises:
            KeyError: Rule factory or evaluator was not found.

        """
        rule_factory = self.rule_factories[rule_definition.rule_type]
        evaluator = self.evaluators_lookup[rule_definition.evaluator_type]
        return rule_factory(rule_definition.definition, evaluator)
