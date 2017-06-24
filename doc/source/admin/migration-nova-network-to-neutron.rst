.. _migration-nova-to-neutron:

=====================================================
Legacy nova-network to OpenStack Networking (neutron)
=====================================================

Two networking models exist in OpenStack. The first is called legacy
networking (nova-network) and it is a sub-process embedded in
the Compute project (nova). This model has some limitations, such as
creating complex network topologies, extending its back-end implementation
to vendor-specific technologies, and providing project-specific networking
elements. These limitations are the main reasons the OpenStack
Networking (neutron) model was created.

This section describes the process of migrating clouds based on the
legacy networking model to the OpenStack Networking model. This
process requires additional changes to both compute and networking to
support the migration. This document describes the overall process and
the features required in both Networking and Compute.

The current process as designed is a minimally viable migration with
the goal of deprecating and then removing legacy networking. Both the
Compute and Networking teams agree that a one-button migration
process from legacy networking to OpenStack Networking (neutron) is
not an essential requirement for the deprecation and removal of the
legacy networking at a future date. This section includes a process
and tools which are designed to solve a simple use case migration.

Users are encouraged to take these tools, test them, provide feedback,
and then expand on the feature set to suit their own deployments;
deployers that refrain from participating in this process intending to
wait for a path that better suits their use case are likely to be
disappointed.

Impact and limitations
~~~~~~~~~~~~~~~~~~~~~~

The migration process from the legacy nova-network networking service
to OpenStack Networking (neutron) has some limitations and impacts on
the operational state of the cloud. It is critical to understand them
in order to decide whether or not this process is acceptable for your
cloud and all users.

Management impact
-----------------

The Networking REST API is publicly read-only until after the
migration is complete. During the migration, Networking REST API is
read-write only to nova-api, and changes to Networking are only
allowed via nova-api.

The Compute REST API is available throughout the entire process,
although there is a brief period where it is made read-only during a
database migration. The Networking REST API will need to expose (to
nova-api) all details necessary for reconstructing the information
previously held in the legacy networking database.

Compute needs a per-hypervisor "has_transitioned" boolean change in
the data model to be used during the migration process. This flag is
no longer required once the process is complete.

Operations impact
-----------------

In order to support a wide range of deployment options, the migration
process described here requires a rolling restart of hypervisors. The
rate and timing of specific hypervisor restarts is under the control
of the operator.

The migration may be paused, even for an extended period of time (for
example, while testing or investigating issues) with some hypervisors
on legacy networking and some on Networking, and Compute API remains
fully functional. Individual hypervisors may be rolled back to legacy
networking during this stage of the migration, although this requires
an additional restart.

In order to support the widest range of deployer needs, the process
described here is easy to automate but is not already automated.
Deployers should expect to perform multiple manual steps or write some
simple scripts in order to perform this migration.

Performance impact
------------------

During the migration, nova-network API calls will go through an
additional internal conversion to Networking calls. This will have
different and likely poorer performance characteristics compared with
either the pre-migration or post-migration APIs.

Migration process overview
~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Start neutron-server in intended final config, except with REST API
   restricted to read-write only by nova-api.
#. Make the Compute REST API read-only.
#. Run a DB dump/restore tool that creates Networking data structures
   representing current legacy networking config.
#. Enable a nova-api proxy that recreates internal Compute objects
   from Networking information
   (via the Networking REST API).
#. Make Compute REST API read-write again. This means legacy
   networking DB is now unused, new changes are now stored in the
   Networking DB, and no rollback is possible from here without losing
   those new changes.

.. note::

   At this moment the Networking DB is the source of truth, but
   nova-api is the only public read-write API.

Next, you'll need to migrate each hypervisor.  To do that, follow these steps:

#. Disable the hypervisor. This would be a good time to live migrate
   or evacuate the compute node, if supported.
#. Disable nova-compute.
#. Enable the Networking agent.
#. Set the "has_transitioned" flag in the Compute hypervisor database/config.
#. Reboot the hypervisor (or run "smart" live transition tool if available).
#. Re-enable the hypervisor.

At this point, all compute nodes have been migrated, but they are
still using the nova-api API and Compute gateways. Finally, enable
OpenStack Networking by following these steps:

#. Bring up the Networking (l3) nodes. The new routers will have
   identical MAC+IPs as old Compute gateways so some sort of immediate
   cutover is possible, except for stateful connections issues such as
   NAT.
#. Make the Networking API read-write and disable legacy networking.

Migration Completed!
