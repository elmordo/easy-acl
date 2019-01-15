About
=====

The `easy-acl` library provides simple ACL based control of access to resources.

Configuration file
------------------

The configuration file has several types of section:

* global setttings in the the `global` section
* custom evaluator section `evaluators`
* custom rules section `rules`
* role list seciton `roles`
* default evaluators `default_evaluators`
* role specific rule settings in sections `<role_name>_rules`

### Global settings

Only key is possible in the section `global`:

* `evaluator` - the fallback evaluator settings

### Custom evaluators settings

In the `evaluators` settings, custom evaluators can be defined. The key of the
pair is evaluator identifier and value is a path to the custom evaluator.

Existing evaluators can be overriden by custom implementation by this section.

### Custom rules settings

Rule types can be extended by the `rules` section. A syntax is same as `evaluators`
section. The key is rule type name and value is path to the custom rule.

### Roles

In the `roles` section is list of roles. The key of the key-value pair is a role
name and the value is list of parent role names. Items of the list are separated
by the comma. If role has no parent, leave the value empty.

### Default role evaluators

Each role can has custom default evaluator. Those evaluators are defined in
`default_evaluators` section. The key is role name and value is identifier of the
evaluator.

### Rules

Rules are grouped in sections by roles where belongs to. Name if the section has
to be in format `<role_name>_rules`.

Entries in the section are in format `resource_definition=rule_type,evaluator_type`.
See example below for more information.

```
[global]
evaluator=allow

[rules]
simple=easy_acl.rule.Simple

[evaluators]
allow=easy_acl.evaluator.allow
deny=easy_acl.evaluator.deny

[roles]
user=
presenter=
antimulti=presenter
admin=user,presenter

[default_evaluators]
admin=allow

[user_rules]
post.list=simple,allow
system.*=wildcardending,deny
system.my-account.*=simple,allow

[presenter_rules]

[admin_rules]


```
