..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Authorization Policy Enforcement
================================

As most OpenStack projects, Neutron leverages oslo_policy [#]_. However, since
Neutron loves to be special and complicate every developer's life, it also
"augments" oslo_policy capabilities by:

* A wrapper module with its own API: neutron.policy;
* The ability of adding fine-grained checks on attributes for resources in
  request bodies;
* The ability of using the policy engine to filter out attributes in responses;
* Adding some custom rule checks beyond those defined in oslo_policy;

This document discusses Neutron-specific aspects of policy enforcement, and in
particular how the enforcement logic is wired into API processing.
For any other information please refer to the developer documentation for
oslo_policy [#]_.

Authorization workflow
----------------------

The Neutron API controllers perform policy checks in two phases during the
processing of an API request:

* Request authorization, immediately before dispatching the request to the
  plugin layer for ``POST``, ``PUT``, and ``DELETE``, and immediately after
  returning from the plugin layer for ``GET`` requests;
* Response filtering, when building the response to be returned to the API
  consumer.

Request authorization
~~~~~~~~~~~~~~~~~~~~~

The aim of this step is to authorize processing for a request or reject it
with an error status code.
This step uses the ``neutron.policy.enforce`` routine. This routine raises
``oslo_policy.PolicyNotAuthorized`` when policy enforcement fails. The Neutron
REST API controllers catch this exception and return:

* A 403 response code on a ``POST`` request or an ``PUT`` request for an
  object owned by the project submitting the request;
* A 403 response for failures while authorizing API actions such as
  ``add_router_interface``;
* A 404 response for ``DELETE``, ``GET`` and all other ``PUT`` requests.

For ``DELETE`` operations the resource must first be fetched. This is done
invoking the same ``_item`` [#]_ method used for processing ``GET`` requests.
This is also true for ``PUT`` operations, since the Neutron API implements
``PATCH`` semantics for ``PUTs``.
The criteria to evaluate are built in the ``_build_match_rule`` [#]_ routine.
This routine takes in input the following parameters:

* The action to be performed, in the ``<operation>_<resource>`` form,
  ``e.g.: create_network``
* The data to use for performing checks. For ``POST`` operations this could
  be a partial specification of the object, whereas it is always a full
  specification for ``GET``, ``PUT``, and ``DELETE`` requests, as resource
  data are retrieved before dispatching the call to the plugin layer.
* The collection name for the resource specified in the previous parameter;
  for instance, for a network it would be the "networks".

The ``_build_match_rule`` routine returns a ``oslo_policy.RuleCheck`` instance
built in the following way:

* Always add a check for the action being performed. This will match
  a policy like create_network in ``policy.yaml``;
* Return for ``GET`` operations; more detailed checks will be performed anyway
  when building the response;
* For each attribute which has been explicitly specified in the request
  create a rule matching policy names in the form
  ``<operation>_<resource>:<attribute>`` rule, and link it with the
  previous rule with an 'And' relationship (using ``oslo_policy.AndCheck``);
  this step will be performed only if the ``enforce_policy`` flag is set to
  ``True`` in the resource attribute descriptor (usually found in a data
  structure called ``RESOURCE_ATTRIBUTE_MAP``);
* If the attribute is a composite one then further rules will be created;
  These will match policy names in the form
  ``<operation>_<resource>:<attribute>:<sub_attribute>``.
  An 'And' relationship will be used in this case too.

As all the rules to verify are linked by 'And' relationships, all the policy
checks should succeed in order for a request to be authorized. Rule
verification is performed by ``oslo_policy`` with no "customization" from the
Neutron side.

.. _response_filtering:

Response Filtering
~~~~~~~~~~~~~~~~~~

Some Neutron extensions, like the provider networks one, add some attribute
to resources which are however not meant to be consumed by all clients. This
might be because these attributes contain implementation details, or are
meant only to be used when exchanging information between services, such
as Nova and Neutron;

For this reason the policy engine is invoked again when building API
responses. This is achieved by the ``_exclude_attributes_by_policy`` [#]_
method in ``neutron.api.v2.base.Controller``;

This method, for each attribute in the response returned by the plugin layer,
first checks if the ``is_visible`` flag is True. In that case it proceeds to
checking policies for the attribute; if the policy check fails the attribute
is added to a list of attributes that should be removed from the response
before returning it to the API client.

The neutron.policy API
----------------------

The ``neutron.policy`` module exposes a simple API whose main goal if to allow the
REST API controllers to implement the authorization workflow discussed in this
document. It is a bad practice to call the policy engine from within the plugin
layer, as this would make request authorization dependent on configured
plugins, and therefore make API behaviour dependent on the plugin itself, which
defies Neutron tenet of being backend agnostic.

The neutron.policy API exposes the following routines:

* ``init``
  Initializes the policy engine loading rules from the json policy (files).
  This method can safely be called several times.
* ``reset``
  Clears all the rules currently configured in the policy engine. It is
  called in unit tests and at the end of the initialization of core API
  router [#]_ in order to ensure rules are loaded after all the extensions
  are loaded.
* ``refresh``
  Combines init and reset. Called when a SIGHUP signal is sent to an API
  worker.
* ``set_rules``
  Explicitly set policy engine's rules. Used only in unit tests.
* ``check``
  Perform a check using the policy engine. Builds match rules as described
  in this document, and then evaluates the resulting rule using oslo_policy's
  policy engine. Returns True if the checks succeeds, false otherwise.
* ``enforce``
  Operates like the check routine but raises if the check in oslo_policy
  fails.
* ``check_is_admin``
  Enforce the predefined context_is_admin rule; used to determine the is_admin
  property for a neutron context.
* ``check_is_advsvc``
  Enforce the predefined context_is_advsvc rule; used to determine the
  is_advsvc property for a neutron context.

Neutron specific policy rules
-----------------------------

Neutron provides two additional policy rule classes in order to support the
"augmented" authorization capabilities it provides. They both extend
``oslo_policy.RuleCheck`` and are registered using the
``oslo_policy.register`` decorator.

OwnerCheck: Extended Checks for Resource Ownership
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This class is registered for rules matching the ``tenant_id`` keyword and
overrides the generic check performed by oslo_policy in this case.
It uses for those cases where neutron needs to check whether the project
submitting a request for a new resource owns the parent resource of the one
being created. Current usages of ``OwnerCheck`` include, for instance,
creating and updating a subnet. This class supports the extension parent
resources owner check which the parent resource introduced by
service plugins. Such as router and floatingip owner check for ``router``
service plugin. Developers can register the extension resource name and service
plugin name which were registered in neutron-lib into
``EXT_PARENT_RESOURCE_MAPPING`` which is located in
``neutron_lib.services.constants``.

The check, performed in the ``__call__`` method, works as follows:

* verify if the target field is already in the target data. If yes, then
  simply verify whether the value for the target field in target data
  is equal to value for the same field in credentials, just like
  ``oslo_policy.GenericCheck`` would do. This is also the most frequent case
  as the target field is usually ``tenant_id``;
* if the previous check failed, extract a parent resource type and a
  parent field name from the target field. For instance
  ``networks:tenant_id`` identifies the ``tenant_id`` attribute of the
  ``network`` resource. For extension parent resource case,
  ``ext_parent:tenant_id`` identifies the ``tenant_id`` attribute of the
  registered extension resource in ``EXT_PARENT_RESOURCE_MAPPING``;
* if no parent resource or target field could be identified raise a
  ``PolicyCheckError`` exception;
* Retrieve a 'parent foreign key' from the ``_RESOURCE_FOREIGN_KEYS`` data
  structure in ``neutron.policy``. This foreign key is simply the
  attribute acting as a primary key in the parent resource. A
  ``PolicyCheckError`` exception will be raised if such 'parent foreign key'
  cannot be retrieved;
* Using the core plugin, retrieve an instance of the resource having
  'parent foreign key' as an identifier;
* Finally, verify whether the target field in this resource matches the
  one in the initial request data. For instance, for a port create request,
  verify whether the ``tenant_id`` of the port data structure matches the
  ``tenant_id`` of the network where this port is being created.


FieldCheck: Verify Resource Attributes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This class is registered with the policy engine for rules matching the 'field'
keyword, and provides a way to perform fine grained checks on resource
attributes. For instance, using this class of rules it is possible to specify
a rule for granting every project read access to shared resources.

In policy.yaml, a FieldCheck rules is specified in the following way::

> field: <resource>:<field>=<value>

This will result in the initialization of a FieldCheck that will check for
``<field>`` in the target resource data, and return ``True`` if it is equal
to ``<value>`` or return ``False`` is the ``<field>`` either is not equal to
``<value>`` or does not exist at all.


Guidance for Neutron API developers
-----------------------------------

When developing REST APIs for Neutron it is important to be aware of how the
policy engine will authorize these requests. This is true both for APIs
served by Neutron "core" and for the APIs served by the various Neutron
"stadium" services.

* If an attribute of a resource might be subject to authorization checks
  then the ``enforce_policy`` attribute should be set to ``True``. While
  setting this flag to ``True`` for each attribute is a viable strategy,
  it is worth noting that this will require a call to the policy engine
  for each attribute, thus consistently increasing the time required to
  complete policy checks for a resource. This could result in a scalability
  issue, especially in the case of list operations retrieving a large
  number of resources;
* Some resource attributes, even if not directly used in policy checks
  might still be required by the policy engine. This is for instance the
  case of the ``tenant_id`` attribute. For these attributes the
  ``required_by_policy`` attribute should always set to ``True``. This will
  ensure that the attribute is included in the resource data sent to the
  policy engine for evaluation;
* The ``tenant_id`` attribute is a fundamental one in Neutron API request
  authorization. The default policy, ``admin_or_owner``, uses it to validate
  if a project owns the resource it is trying to operate on. To this aim,
  if a resource without a tenant_id is created, it is important to ensure
  that ad-hoc authZ policies are specified for this resource.
* There is still only one check which is hardcoded in Neutron's API layer:
  the check to verify that a project owns the network on which it is creating
  a port. This check is hardcoded and is always executed when creating a
  port, unless the network is shared. Unfortunately a solution for performing
  this check in an efficient way through the policy engine has not yet been
  found. Due to its nature, there is no way to override this check using the
  policy engine.
* It is strongly advised to not perform policy checks in the plugin or in
  the database management classes. This might lead to divergent API
  behaviours across plugins. Also, it might leave the Neutron DB in an
  inconsistent state if a request is not authorized after it has already
  been dispatched to the backend.

Notes
~~~~~

* No authorization checks are performed for requests coming from the RPC over
  AMQP channel. For all these requests a neutron admin context is built, and
  the plugins will process them as such.
* For ``PUT`` and ``DELETE`` requests a 404 error is returned on request
  authorization failures rather than a 403, unless the project submitting the
  request own the resource to update or delete. This is to avoid conditions
  in which an API client might try and find out other projects' resource
  identifiers by sending out ``PUT`` and ``DELETE`` requests for random
  resource identifiers.
* There is no way at the moment to specify an ``OR`` relationship between two
  attributes of a given resource (eg.: ``port.name == 'meh' or
  port.status == 'DOWN'``), unless the rule with the or condition is explicitly
  added to the policy.yaml file.
* ``OwnerCheck`` performs a plugin access; this will likely require a database
  access, but since the behaviour is implementation specific it might also
  imply a round-trip to the backend. This class of checks, when involving
  retrieving attributes for 'parent' resources should be used very sparingly.
* In order for ``OwnerCheck`` rules to work, parent resources should have an
  entry in ``neutron.policy._RESOURCE_FOREIGN_KEYS``; moreover the
  resource must be managed by the 'core' plugin (ie: the one defined in the
  core_plugin configuration variable)

Policy-in-Code support
----------------------

Guideline on defining in-code policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following is the guideline of policy definitions.

Ideally we should define all available policies, but in the neutron policy
enforcement it is not practical to define all policies because we check
all attributes of a target resource in the :ref:`response_filtering`.
Considering this, we have the special guidelines for "get" operation.

* All policies of ``<action>_<resource>`` must be defined
  for all types of operations.
  Valid actions are ``create``, ``update``, ``delete`` and ``get``.

* ``get_<resourceS>`` (get plural) is unnecessary.
  The neutron API layer use a single form policy ``get_<resource>``
  when listing resources [#]_ [#]_.

* Member actions for individual resources must be defined.
  For example, ``add_router_interface`` of ``router`` resource.

* All policies with attributes on "create", "update" and "delete" actions must
  be defined. ``<action>_<resource>:<attribute>(:<sub_attribute>)`` policy is
  required for attributes with ``enforce_policy`` in the API definitions.
  Note that it is recommended to define even if a rule is same as for
  ``<action>_<resource>`` from the documentation perspective.

* For a policy with attributes of "get" actions like
  ``get_<resource>:<attribute>(:<sub_attribute>)``,
  the following guideline is applied:

  * A policy with an attribute must be defined if the policy is different from
    the policy for ``get_<resource>`` (without attributes).
  * If a policy with an attribute is same as for ``get_<resource>``, there is
    no need to define it explicitly.
    This is for simplicity. We check all attributes of a target resource
    in the process of :ref:`response_filtering` so it leads to a long long
    policy definitions for "get" actions in our documentation.
    It is not happy for operators either.
  * If an attribute is marked as ``enforce_policy``, it is recommended to
    define the corresponding policy with the attribute.
    This is for clarification. If an attribute is marked as ``enforce_policy``
    in the API definitions, for example, the neutron API limits to set such
    attribute only to admin users but allows to retrieve a value for regular
    users. If policies for the attribute are different across the types of
    operations, it is better to define all of them explicitly.

Registering policies in neutron related projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Policy-in-code support in neutron is a bit different from other projects
because the neutron server needs to load policies in code from multiple
projects. Each neutron related project should register the following two entry
points ``oslo.policy.policies`` and ``neutron.policies`` in ``setup.cfg`` like
below:

.. code-block:: none

   oslo.policy.policies =
       neutron = neutron.conf.policies:list_rules
   neutron.policies =
       neutron = neutron.conf.policies:list_rules

The above two entries are same, but they have different purposes.

* The first entry point is a normal entry point defined by oslo.policy and it
  is used to generate a sample policy file [#]_ [#]_.
* The second one is specific to neutron. It is used by ``neutron.policy``
  module to load policies of neutron related projects.

``oslo.policy.policies`` entry point is used by all projects which adopt
oslo.policy, so we cannot determine which projects are neutron related
projects, so the second entry point is required.

The recommended entry point name is a repository name: For example,
'neutron-fwaas' for FWaaS and 'networking-sfc' for SFC:

.. code-block:: none

   oslo.policy.policies =
       neutron-fwaas = neutron_fwaas.policies:list_rules
   neutron.policies =
       neutron-fwaas = neutron_fwaas.policies:list_rules

Except registering the ``neutron.policies`` entry point, other steps to be done
in each neutron related project for policy-in-code support are same for all
OpenStack projects.

References
----------

.. [#] `Oslo policy module <http://opendev.org/openstack/oslo.policy/>`_
.. [#] `Oslo policy developer <https://docs.openstack.org/oslo.policy/latest/>`_
.. [#] API controller item_ method

.. _item: http://opendev.org/openstack/neutron/src/tag/2015.1.1/neutron/api/v2/base.py#L282

.. [#] Policy engine's build_match_rule_ method

.. _build_match_rule: http://opendev.org/openstack/neutron/src/tag/2015.1.1/neutron/policy.py#L187

.. [#] exclude_attributes_by_policy_ method

.. _exclude_attributes_by_policy: http://opendev.org/openstack/neutron/src/tag/2015.1.1/neutron/api/v2/base.py#L132

.. [#] Policy reset_ in neutron.api.v2.router

.. _reset: http://opendev.org/openstack/neutron/src/tag/2015.1.1/neutron/api/v2/router.py#L122

.. [#] https://github.com/openstack/neutron/blob/051b6b40f3921b9db4f152a54f402c402cbf138c/neutron/pecan_wsgi/hooks/policy_enforcement.py#L173
.. [#] https://github.com/openstack/neutron/blob/051b6b40f3921b9db4f152a54f402c402cbf138c/neutron/pecan_wsgi/hooks/policy_enforcement.py#L143

.. [#] https://docs.openstack.org/oslo.policy/latest/user/usage.html#sample-file-generation
.. [#] https://docs.openstack.org/oslo.policy/latest/cli/index.html#oslopolicy-sample-generator
