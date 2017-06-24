.. _ops-resource-purge:

==============
Resource purge
==============

The Networking service provides a purge mechanism to delete the
following network resources for a project:

* Networks
* Subnets
* Ports
* Router interfaces
* Routers
* Floating IP addresses
* Security groups

Typically, one uses this mechanism to delete networking resources
for a defunct project regardless of its existence in the Identity
service.

Usage
~~~~~

#. Source the necessary project credentials. The administrative project
   can delete resources for all other projects. A regular project can
   delete its own network resources and those belonging to other projects
   for which it has sufficient access.

#. Delete the network resources for a particular project.

   .. code-block:: console

      $ neutron purge PROJECT_ID

   Replace ``PROJECT_ID`` with the project ID.

The command provides output that includes a completion percentage and
the quantity of successful or unsuccessful network resource deletions.
An unsuccessful deletion usually indicates sharing of a resource with
one or more additional projects.

.. code-block:: console

   Purging resources: 100% complete.
   Deleted 1 security_group, 2 ports, 1 router, 1 floatingip, 2 networks.
   The following resources could not be deleted: 1 network.

The command also indicates if a project lacks network resources.

.. code-block:: console

   Tenant has no supported resources.
