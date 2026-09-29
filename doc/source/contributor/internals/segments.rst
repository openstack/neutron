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


Segments Extension
==================

Neutron has an extension that allows CRUD operations on the ``/segments``
resource in the API, that corresponds to the ``NetworkSegment`` entity in the
DB layer. The extension is implemented as a service plug-in.

Details about the DB models, API extension, and use cases can be found here: `routed networks spec <https://specs.openstack.org/openstack/neutron-specs/specs/newton/routed-networks.html>`_

.. note:: The ``segments`` service plug-in is not configured by default. To
   configure it, add ``segments`` to the ``service_plugins`` parameter in
   ``neutron.conf``

Core plug-ins can coordinate with the ``segments`` service plug-in by
subscribing callbacks to events associated to the ``SEGMENT`` resource.
Currently, the segments plug-in notifies subscribers of the following events:

* ``PRECOMMIT_CREATE``
* ``AFTER_CREATE``
* ``BEFORE_DELETE``
* ``PRECOMMIT_DELETE``
* ``AFTER_DELETE``

As of this writing, ``ML2`` and ``OVN`` register callbacks to receive events
from the ``segments`` service plug-in. The ``ML2`` plug-in defines the
callback ``_handle_segment_change`` to process all the relevant segments
events.

Segments extension relevant modules
-----------------------------------

* ``neutron/extensions/segment.py`` defines the extension
* ``neutron/db/models/segment.py`` defines the DB models for segments and for
  the segment host mapping, that is used in the implementation of routed
  networks.
* ``neutron/db/segments_db.py`` has functions to add, retrieve and delete
  segments from the DB.
* ``neutron/services/segments/db.py`` defines a mixin class with the methods
  that perform API CRUD operations for the ``segments`` plug-in. It also has a
  set of functions to create and maintain the mapping of segments to hosts,
  which is necessary in the implementation of routed networks.
* ``neutron/services/segments/plugin.py`` defines the ``segments`` service
  plug-in.

Networksegments table constraints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``networksegments`` table stores network segment records. Two unique
constraints are enforced at the database level:

1. **Per-network uniqueness** (added in 2023.1/Antelope, via review
   `841459 <https://review.opendev.org/c/openstack/neutron/+/841459>`_):
   The combination ``(network_id, network_type, physical_network,
   segment_index)`` must be unique. This prevents two segments within the
   same network from sharing the same index and physical network. The
   ``segment_index`` is a non-negative integer (default ``0``) that
   defines the ordering of segments within a network; it is auto-incremented
   when new segments are added.

2. **Cross-network segmentation ID uniqueness** (added in 2027.1/Indri, via
   review `1007844 <https://review.opendev.org/c/openstack/neutron/+/1007844>`_):
   The combination ``(network_type, physical_network, segmentation_id)``
   must be unique across all networks. This prevents two networks from
   using the same segmentation ID on the same physical network or tunnel
   type, which would cause ambiguity at the dataplane level.

Tunnel ``physical_network`` migration (``d4b7e5f2a1c3``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Revision ``d4b7e5f2a1c3`` (2027.1/Indri) sets ``physical_network`` to ``''``
for every row where it is currently ``NULL``. Tunnel and other overlay
segment types store an unset provider physical network as ``NULL``; flat
and VLAN segments normally already have a non-NULL value. The change lets
the constraints above apply to tunnel segments the same way they apply to
other segment types.

SQL unique indexes treat each ``NULL`` as distinct from other ``NULL``
values. Multiple tunnel segments in the same network could therefore share
the same ``segment_index`` while ``physical_network`` stayed ``NULL``,
without violating the per-network constraint **1**. Representing “no
physical network” as ``''`` makes those rows comparable and lets that
uniqueness rule catch duplicates.

The ``UPDATE`` fails if distinct rows would become identical under the
per-network constraint—for example, two tunnel segments on one network with
the same ``network_type`` and ``segment_index`` while ``physical_network``
is still ``NULL``.

Before upgrading, run ``neutron-status upgrade check``. The
``networksegments_unique_constraint_check`` check counts groups of rows
that would violate either constraint after this migration; resolve those
duplicates manually before applying the expand migration.

.. note::

   ``segment_index`` is an internal ordering field, not exposed in the API.
   It defaults to ``0`` and is auto-incremented by the segments plug-in when
   new segments are added to a network.
