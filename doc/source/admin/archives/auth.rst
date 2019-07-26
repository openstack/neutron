.. _Authentication and authorization:

================================
Authentication and authorization
================================

Networking uses the Identity service as the default authentication
service. When the Identity service is enabled, users who submit requests
to the Networking service must provide an authentication token in
``X-Auth-Token`` request header. Users obtain this token by
authenticating with the Identity service endpoint. For more information
about authentication with the Identity service, see `OpenStack Identity
service API v3
Reference <https://docs.openstack.org/api-ref/identity/v3/>`__.
When the Identity service is enabled, it is not mandatory to specify the
project ID for resources in create requests because the project ID is
derived from the authentication token.

The default authorization settings only allow administrative users
to create resources on behalf of a different project. Networking uses
information received from Identity to authorize user requests.
Networking handles two kind of authorization policies:

-  **Operation-based** policies specify access criteria for specific
   operations, possibly with fine-grained control over specific
   attributes.

-  **Resource-based** policies specify whether access to specific
   resource is granted or not according to the permissions configured
   for the resource (currently available only for the network resource).
   The actual authorization policies enforced in Networking might vary
   from deployment to deployment.

The policy engine reads entries from the ``policy.json`` file. The
actual location of this file might vary from distribution to
distribution. Entries can be updated while the system is running, and no
service restart is required. Every time the policy file is updated, the
policies are automatically reloaded. Currently the only way of updating
such policies is to edit the policy file. In this section, the terms
*policy* and *rule* refer to objects that are specified in the same way
in the policy file. There are no syntax differences between a rule and a
policy. A policy is something that is matched directly from the
Networking policy engine. A rule is an element in a policy, which is
evaluated. For instance in ``"create_subnet":
"rule:admin_or_network_owner"``, *create_subnet* is a
policy, and *admin_or_network_owner* is a rule.

Policies are triggered by the Networking policy engine whenever one of
them matches a Networking API operation or a specific attribute being
used in a given operation. For instance the ``create_subnet`` policy is
triggered every time a ``POST /v2.0/subnets`` request is sent to the
Networking server; on the other hand ``create_network:shared`` is
triggered every time the *shared* attribute is explicitly specified (and
set to a value different from its default) in a ``POST /v2.0/networks``
request. It is also worth mentioning that policies can also be related
to specific API extensions; for instance
``extension:provider_network:set`` is triggered if the attributes
defined by the Provider Network extensions are specified in an API
request.

An authorization policy can be composed by one or more rules. If more
rules are specified then the evaluation policy succeeds if any of the
rules evaluates successfully; if an API operation matches multiple
policies, then all the policies must evaluate successfully. Also,
authorization rules are recursive. Once a rule is matched, the rule(s)
can be resolved to another rule, until a terminal rule is reached.

The Networking policy engine currently defines the following kinds of
terminal rules:

-  **Role-based rules** evaluate successfully if the user who submits
   the request has the specified role. For instance ``"role:admin"`` is
   successful if the user who submits the request is an administrator.

-  **Field-based rules** evaluate successfully if a field of the
   resource specified in the current request matches a specific value.
   For instance ``"field:networks:shared=True"`` is successful if the
   ``shared`` attribute of the ``network`` resource is set to true.

-  **Generic rules** compare an attribute in the resource with an
   attribute extracted from the user's security credentials and
   evaluates successfully if the comparison is successful. For instance
   ``"tenant_id:%(tenant_id)s"`` is successful if the project identifier
   in the resource is equal to the project identifier of the user
   submitting the request.

This extract is from the default ``policy.json`` file:

-  A rule that evaluates successfully if the current user is an
   administrator or the owner of the resource specified in the request
   (project identifier is equal).

   .. code-block:: none

      {
       "admin_or_owner": "role:admin",
       "tenant_id:%(tenant_id)s",
       "admin_or_network_owner": "role:admin",
       "tenant_id:%(network_tenant_id)s",
       "admin_only": "role:admin",
       "regular_user": "",
       "shared":"field:networks:shared=True",
       "default":

-  The default policy that is always evaluated if an API operation does
   not match any of the policies in ``policy.json``.

   .. code-block:: none

        "rule:admin_or_owner",
        "create_subnet": "rule:admin_or_network_owner",
        "get_subnet": "rule:admin_or_owner",
        "rule:shared",
        "update_subnet": "rule:admin_or_network_owner",
        "delete_subnet": "rule:admin_or_network_owner",
        "create_network": "",
        "get_network": "rule:admin_or_owner",

-  This policy evaluates successfully if either *admin_or_owner*, or
   *shared* evaluates successfully.

   .. code-block:: none

         "rule:shared",
         "create_network:shared": "rule:admin_only"

-  This policy restricts the ability to manipulate the *shared*
   attribute for a network to administrators only.

   .. code-block:: none

         ,
         "update_network": "rule:admin_or_owner",
        "delete_network": "rule:admin_or_owner",
        "create_port": "",
        "create_port:mac_address": "rule:admin_or_network_owner",
        "create_port:fixed_ips":

-  This policy restricts the ability to manipulate the *mac_address*
   attribute for a port only to administrators and the owner of the
   network where the port is attached.

   .. code-block:: none

         "rule:admin_or_network_owner",
        "get_port": "rule:admin_or_owner",
        "update_port": "rule:admin_or_owner",
         "delete_port": "rule:admin_or_owner"
       }

In some cases, some operations are restricted to administrators only.
This example shows you how to modify a policy file to permit project to
define networks, see their resources, and permit administrative users to
perform all other operations:

.. code-block:: none

    {
            "admin_or_owner": "role:admin", "tenant_id:%(tenant_id)s",
            "admin_only": "role:admin", "regular_user": "",
            "default": "rule:admin_only",
            "create_subnet": "rule:admin_only",
            "get_subnet": "rule:admin_or_owner",
            "update_subnet": "rule:admin_only",
            "delete_subnet": "rule:admin_only",
            "create_network": "",
            "get_network": "rule:admin_or_owner",
            "create_network:shared": "rule:admin_only",
            "update_network": "rule:admin_or_owner",
            "delete_network": "rule:admin_or_owner",
            "create_port": "rule:admin_only",
            "get_port": "rule:admin_or_owner",
            "update_port": "rule:admin_only",
            "delete_port": "rule:admin_only"
    }
