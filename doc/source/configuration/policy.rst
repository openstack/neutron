.. _Policy Reference:

================
Policy Reference
================

.. warning::

   JSON formatted policy file is deprecated since Neutron 18.0.0 (Wallaby).
   This `oslopolicy-convert-json-to-yaml`__ tool will migrate your existing
   JSON-formatted policy file to YAML in a backward-compatible way.

.. __: https://docs.openstack.org/oslo.policy/latest/cli/oslopolicy-convert-json-to-yaml.html

Neutron, like most OpenStack projects, uses a policy language to restrict
permissions on REST API actions. Policy defaults are defined in the codebase
and can be overridden in a ``policy.yaml`` file.

Each policy entry in the reference below contains three important fields:

**Default**
  The check string (``check_str``) evaluated at runtime. Operators can override
  this value in ``policy.yaml``.

**Scope Types**
  The Keystone token scope required to call the API. This value is defined in
  code and cannot be overridden in ``policy.yaml``.

**Description**
  A short summary of what the policy protects.

Scope
-----

OpenStack Keystone supports different authorization scopes in tokens: ``system``,
``domain``, and ``project``. These are described in the `Keystone tokens
overview
<https://docs.openstack.org/keystone/latest/admin/tokens-overview.html#authorization-scopes>`_.

Policy ``scope_types`` represent the scope that a token must carry in order to
invoke an API. Token scope is the **authorization layer**; it is not the same
thing as restricting access to a particular project or resource.

.. note::

   **Scope Types** tells you what kind of token is required (for example, a
   project-scoped token). It does **not** mean that the caller is limited to
   the project that owns the resource. Resource-level restrictions are
   expressed in the **Default** check string.

Neutron policies currently define ``scope_types`` as ``project`` for all API
rules. This means that requests made with ``system``- or ``domain``-scoped
tokens, or with unscoped tokens, are rejected before the **Default** rule is
evaluated.

For example, consider ``POST /ports/{port_id}/bindings/``:

.. code-block:: text

   create_port_binding
       Default: rule:service_api
       Scope Types: project

Here, ``project`` means the caller must present a **project-scoped** token.
The **Default** value ``rule:service_api`` resolves to ``role:service`` and does
not include a ``project_id:%(project_id)s`` check. A service user with a
project-scoped token from any project can call this API.

Compare that with ``POST /networks``:

.. code-block:: text

   create_network
       Default: rule:admin_or_project_member
       Scope Types: project

Again, ``project`` requires a project-scoped token. The **Default** value
additionally requires the caller to be a cloud administrator or a ``member`` of
the project that owns the network (``role:member and
project_id:%(project_id)s``).

Policy configuration options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Scope enforcement (``[oslo_policy] enforce_scope``) is always active; the
option is deprecated for removal and its default value is ``True``. Neutron
requires a token whose scope matches the policy ``scope_types``. Requests
with a mismatching scope are rejected with ``403 Forbidden``.

The :oslo.config:option:`oslo_policy.enforce_new_defaults` option (default
``True`` since oslo.policy 4.4.0 / OpenStack 2024.2) controls whether legacy
deprecated check strings are considered during policy evaluation:

* When ``True``, only the new default check strings documented in the
  **Default** column below are evaluated.
* When ``False``, legacy deprecated check strings are logically OR'd with the
  new defaults, allowing deployments that still rely on old policy rules to
  operate during a gradual migration.

This option is **not deprecated**. It remains the supported way to fall back
to legacy policy behavior. Neutron still contains deprecated policy check
strings for backward compatibility; once those are removed from the codebase,
setting this option to ``False`` will no longer change enforcement behavior.

Operators who need to temporarily restore legacy policy behavior can set the
option in ``neutron.conf``:

.. code-block:: ini

   [oslo_policy]
   enforce_new_defaults = false

Roles
-----

Keystone provides ``admin``, ``manager``, ``member``, and ``reader`` roles by
default. Refer to the `Keystone service API protection documentation
<https://docs.openstack.org/keystone/latest/admin/service-api-protection.html>`_
for details about these roles.

Neutron defines reusable check strings in ``neutron/conf/policies/base.py``.
The most common ones are listed below.

Base roles
~~~~~~~~~~

``admin`` (``rule:admin_only`` / ``rule:context_is_admin``)
  Cloud administrator. Can perform administrative operations regardless of
  project ownership.

``service`` (``rule:service_api``)
  Internal service-to-service communication. Assigned to service users (for
  example, the user configured for Nova or Neutron in other services' config
  files). Must not be granted to human accounts.

``manager`` (``PROJECT_MANAGER``)
  ``role:manager and project_id:%(project_id)s``. Project-level management
  operations within the caller's project.

``member`` (``PROJECT_MEMBER``)
  ``role:member and project_id:%(project_id)s``. Typical end-user operations
  on project-owned resources (for example, creating ports or routers).

``reader`` (``PROJECT_READER``)
  ``role:reader and project_id:%(project_id)s``. Read-only access to
  project-owned resources.

Composite rules
~~~~~~~~~~~~~~~

The following composite check strings combine the base roles above. They are
the **Default** values for most Neutron API policies:

``rule:admin_or_project_manager``
  Administrator, or ``manager`` in the resource's project.

``rule:admin_or_project_member``
  Administrator, or ``member`` in the resource's project.

``rule:admin_or_project_reader``
  Administrator, or ``reader`` in the resource's project.

``rule:admin_or_service``
  Administrator, or a service user with the ``service`` role.

Owner-based rules
~~~~~~~~~~~~~~~~~

Some resources do not carry their own ``project_id`` (for example, QoS rules
or floating IP port-forwarding entries). For those, Neutron uses owner checks
against a parent or related resource:

``rule:admin_or_parent_owner_member`` / ``rule:admin_or_parent_owner_reader``
  Administrator, or ``member`` / ``reader`` in the parent resource's project.

``rule:admin_or_net_owner_member`` / ``rule:admin_or_net_owner_reader``
  Administrator, or ``member`` / ``reader`` in the network owner's project.

``rule:admin_or_sg_owner_member`` / ``rule:admin_or_sg_owner_reader``
  Administrator, or ``member`` / ``reader`` in the security group's project.

Legacy rules
~~~~~~~~~~~~

The following rules are retained for backward compatibility:

``rule:admin_or_owner``
  Administrator, or the project that owns the resource.

``rule:owner``
  ``project_id:%(project_id)s``.

``rule:context_is_advsvc`` (``role:advsvc``)
  Deprecated since 2024.1 in favour of the ``service`` role.

Neutron supported scope and roles
---------------------------------

Neutron supports the following scope and role combinations. Roles can be
overridden in ``policy.yaml``, but ``scope_types`` cannot.

#. **ADMIN**: ``admin`` role on a ``project``-scoped token. Administrative
   read and write operations (for example, creating shared or external
   networks).

#. **PROJECT_MANAGER**: ``manager`` role on a ``project``-scoped token.
   Project-level management operations within the caller's project.

#. **PROJECT_MEMBER**: ``member`` role on a ``project``-scoped token.
   Resource owner write operations within the caller's project (for example,
   creating a port or router).

#. **PROJECT_READER**: ``reader`` role on a ``project``-scoped token.
   Read-only operations within the caller's project (for example, listing
   networks).

#. **ADMIN_OR_PROJECT_MANAGER**: ``admin`` or ``manager`` on a
   ``project``-scoped token. Default for project management APIs.

#. **ADMIN_OR_PROJECT_MEMBER**: ``admin`` or ``member`` on a
   ``project``-scoped token. Default for most owner-level write APIs.

#. **ADMIN_OR_PROJECT_READER**: ``admin`` or ``reader`` on a
   ``project``-scoped token. Default for most read-only APIs.

#. **SERVICE** (internal): ``service`` role on a ``project``-scoped token.
   Default for service-to-service APIs (for example, port bindings).

For more information about how policies are enforced in the API layer, refer to
:doc:`/contributor/internals/policy`. For using custom roles beyond the
defaults, refer to :doc:`custom_policy_roles`.

Policy rules
------------

The following is a complete reference of all available policies in Neutron.

.. only:: html

   For a sample policy file, refer to :doc:`/configuration/policy-sample`.

   .. toctree::
      :hidden:

      policy-sample

.. show-policy::
      :config-file: etc/oslo-policy-generator/policy.conf
