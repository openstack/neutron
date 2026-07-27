.. This file is manually generated, unlike many of the other chapters.

=======================================
neutron-remove-duplicated-port-bindings
=======================================

The :command:`neutron-remove-duplicated-port-bindings` tool removes stale
port binding records left in the Neutron database after a failed live
migration. During a live migration, an INACTIVE ``PortBinding`` is created
on the destination host. If the migration fails, the INACTIVE binding and
its associated ``PortBindingLevel`` records may not be cleaned up, which
prevents the port from being migrated again.

This script scans the ``ml2_port_bindings`` table, identifies port IDs with
more than one binding record (or a specific port, if ``--port`` is given),
and deletes the INACTIVE binding together with the corresponding
``PortBindingLevel`` entries.

For background on how these stale records arise, see
:ref:`live_mig_error_recovery`.

.. _remove_dup_pb_usage:

Usage
-----

.. code-block:: console

   neutron-remove-duplicated-port-bindings [--config-file PATH]
                                           [--port PORT_ID]

The script requires access to the Neutron database. Provide the database
connection string through the standard ``neutron.conf`` configuration file
or via the ``--config-file`` option.

Options
-------

``--config-file PATH``
  Path to a Neutron configuration file containing, at minimum, the
  ``[database] connection`` option. Multiple ``--config-file`` arguments can
  be supplied; values in later files take precedence.

``--port PORT_ID``
  Restrict the cleanup to a single port by passing its UUID. When omitted,
  the script scans all ports for duplicated bindings.

``[cli_script] dry_run``
  Boolean option (set in the configuration file under the ``[cli_script]``
  group). When ``True``, the script lists the duplicated bindings it would
  remove without actually deleting them. Defaults to ``False``.

Examples
--------

**Dry-run — list duplicated bindings without deleting them:**

.. code-block:: console

   neutron-remove-duplicated-port-bindings \
       --config-file /etc/neutron/neutron.conf \
       --config-file /etc/neutron/plugins/ml2/ml2_conf.ini

With the ``dry_run`` option enabled in the configuration file:

.. code-block:: ini

   [cli_script]
   dry_run = True

The script will print the port IDs that have duplicated INACTIVE bindings
but will not modify the database.

**Remove duplicated bindings for all ports:**

.. code-block:: console

   neutron-remove-duplicated-port-bindings \
       --config-file /etc/neutron/neutron.conf

**Remove duplicated bindings for a specific port:**

.. code-block:: console

   neutron-remove-duplicated-port-bindings \
       --config-file /etc/neutron/neutron.conf \
       --port 12345678-abcd-efgh-ijkl-123456789abc

Warnings
--------

.. warning::

   Do **not** run this script while a live migration or cross-cell cold
   migration is in progress. The script will delete the INACTIVE port
   binding that the migration process depends on, breaking the operation.

.. warning::

   Always verify the affected ports with a dry-run first, especially when
   running without the ``--port`` filter, to avoid accidentally removing
   bindings that are part of an ongoing operation.

See Also
--------

* :doc:`/contributor/internals/live_migration` — Neutron live-migration
  internals, including the error-recovery scenario that motivates this
  script.
* `LP#1979072 <https://bugs.launchpad.net/neutron/+bug/1979072>`_ —
  Original bug report for duplicated port bindings after failed live
  migration.
