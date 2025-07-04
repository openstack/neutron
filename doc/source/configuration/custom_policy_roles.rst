.. _Custom Policy Roles:

===================
Custom Policy Roles
===================

Besides the :ref:`default policy roles <Policy Reference>`, Neutron also
supports using custom roles.  Using custom roles with for example read only
access to all of the resources requires to configure the policy rule which
allows ``global access`` to the resources.

To grant the ``auditor`` role access to fetch all of the resources from the
database, following rule should be added to the ``policy.yaml`` file:

.. code-block:: yaml

    "context_with_global_access": "role:auditor"


This will make all SQL queries made by neutron with the ``auditor`` role in the
context to not be scoped by the project ID.
This however don't grant the ``auditor`` role to receive all of the resources
from the Neutron API yet. To grant such permissions for example for the
``get_network`` action, following rule should be added to the ``policy.yaml``
file:

.. code-block:: yaml

    "get_network": "role:admin_only or (role:reader and project_id:%(project_id)s) or rule:shared or rule:external or rule:context_is_advsvc or role:auditor"


With those 2 rules in place, the ``auditor`` role will be able to fetch all of
the networks from the Neutron API.
