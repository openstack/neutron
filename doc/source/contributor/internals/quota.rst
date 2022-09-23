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


Quota Management and Enforcement
================================

Most resources exposed by the Neutron API are subject to quota limits.
The Neutron API exposes an extension for managing such quotas. Quota limits are
enforced at the API layer, before the request is dispatched to the plugin.

Default values for quota limits are specified in neutron.conf. Admin users
can override those defaults values on a per-project basis. Limits are stored
in the Neutron database; if no limit is found for a given resource and project,
then the default value for such resource is used.
Configuration-based quota management, where every project gets the same quota
limit specified in the configuration file, has been deprecated as of the
Liberty release.

Please note that Neutron does not support both specification of quota limits
per user and quota management for hierarchical multitenancy (as a matter of
fact Neutron does not support hierarchical multitenancy at all). Also, quota
limits are currently not enforced on RPC interfaces listening on the AMQP
bus.

Plugin and ML2 drivers are not supposed to enforce quotas for resources they
manage. However, the ``subnet_allocation`` [1]_ extension is an exception and will
be discussed below.

The quota management and enforcement mechanisms discussed here apply to every
resource which has been registered with the Quota engine, regardless of
whether such resource belongs to the core Neutron API or one of its extensions.

High Level View
---------------

There are two main components in the Neutron quota system:

* The Quota API extensions.
* The Quota Engine.

Both components rely on a quota driver. The neutron codebase currently defines
three quota drivers:

* ``neutron.db.quota.driver.DbQuotaDriver``
* ``neutron.db.quota.driver_nolock.DbQuotaNoLockDriver`` (default)

The ``DbQuotaNoLockDriver`` is the default quota driver, defined in the
configuration option ``quota_driver``.

The Quota API extension handles quota management, whereas the Quota Engine
component handles quota enforcement. This API extension is loaded like any
other extension. For this reason plugins must explicitly support it by including
"quotas" in the supported_extension_aliases attribute.

In the Quota API simple CRUD operations are used for managing project quotas.
Please note that the current behaviour when deleting a project quota is to reset
quota limits for that project to configuration defaults. The API
extension does not validate the project identifier with the identity service.

In addition, the Quota Detail API extension complements the Quota API extension
by allowing users (typically admins) the ability to retrieve details about
quotas per project. Quota details include the used/limit/reserved
count for the project's resources (networks, ports, etc.).

Performing quota enforcement is the responsibility of the Quota Engine.
RESTful API controllers, before sending a request to the plugin, try to obtain
a reservation from the quota engine for the resources specified in the client
request. If the reservation is successful, then it proceeds to dispatch the
operation to the plugin.

For a reservation to be successful, the total amount of resources requested,
plus the total amount of resources reserved, plus the total amount of resources
already stored in the database should not exceed the project's quota limit.

Finally, both quota management and enforcement rely on a "quota driver" [2]_,
whose task is basically to perform database operations.

Quota Management
----------------

The quota management component is fairly straightforward.

However, unlike the vast majority of Neutron extensions, it uses it own
controller class [3]_.
This class does not implement the POST operation. List, get, update, and
delete operations are implemented by the usual index, show, update and
delete methods. These method simply call into the quota driver for either
fetching project quotas or updating them.

The ``_update_attributes`` method is called only once in the controller lifetime.
This method dynamically updates Neutron's resource attribute map [4]_ so that
an attribute is added for every resource managed by the quota engine.
Request authorisation is performed in this controller, and only 'admin' users
are allowed to modify quotas for projects. As the neutron policy engine is not
used, it is not possible to configure which users should be allowed to manage
quotas using ``policy.yaml``.

The driver operations dealing with quota management are:

* ``delete_tenant_quota``, which simply removes all entries from the 'quotas'
  table for a given project identifier;
* ``update_quota_limit``, which adds or updates an entry in the 'quotas' project
  for a given project identifier and a given resource name;
* ``_get_quotas``, which fetches limits for a set of resource and a given project
  identifier
* ``_get_all_quotas``, which behaves like ``_get_quotas``, but for all projects.


Resource Usage Info
-------------------

Neutron has two ways of tracking resource usage info:

* ``CountableResource``, where resource usage is calculated every time quotas
  limits are enforced by counting rows in the resource table or resources
  tables and reservations for that resource.
* ``TrackedResource``, depends on the selected driver:

  * ``DbQuotaDriver``: the resource usage relies on a specific table tracking
    usage data, and performs explicitly counting only when the data in this
    table are not in sync with actual used and reserved resources.
  * ``DbQuotaNoLockDriver``: the resource usage is counted directly from the
    database table associated to the resource. In this new driver,
    ``CountableResource`` and ``TrackedResource`` could look similar but
    ``TrackedResource`` depends on one single database model (table) and the
    resource count is done directly on this table only.

Another difference between ``CountableResource`` and ``TrackedResource`` is that the
former invokes a plugin method to count resources. ``CountableResource`` should be
therefore employed for plugins which do not leverage the Neutron database.
The actual class that the Neutron quota engine will use is determined by the
``track_quota_usage`` variable in the quota configuration section. If ``True``,
``TrackedResource`` instances will be created, otherwise the quota engine will
use ``CountableResource`` instances.
Resource creation is performed by the ``create_resource_instance`` factory method
in the ``neutron.quota.resource`` module.

DbQuotaDriver description
-------------------------

From a performance perspective, having a table tracking resource usage
has some advantages, albeit not fundamental. Indeed the time required for
executing queries to explicitly count objects will increase with the number of
records in the table. On the other hand, using ``TrackedResource`` will fetch a
single record, but has the drawback of having to execute an UPDATE statement
once the operation is completed.
Nevertheless, ``CountableResource`` instances do not simply perform a SELECT query
on the relevant table for a resource, but invoke a plugin method, which might
execute several statements and sometimes even interacts with the backend
before returning.
Resource usage tracking also becomes important for operational correctness
when coupled with the concept of resource reservation, discussed in another
section of this chapter.

Tracking quota usage is not as simple as updating a counter every time
resources are created or deleted.
Indeed a quota-limited resource in Neutron can be created in several ways.
While a RESTful API request is the most common one, resources can be created
by RPC handlers listing on the AMQP bus, such as those which create DHCP
ports, or by plugin operations, such as those which create router ports.

To this aim, ``TrackedResource`` instances are initialised with a reference to
the model class for the resource for which they track usage data. During
object initialisation, SqlAlchemy event handlers are installed for this class.
The event handler is executed after a record is inserted or deleted.
As result usage data for that resource and will be marked as 'dirty' once
the operation completes, so that the next time usage data is requested,
it will be synchronised counting resource usage from the database.
Even if this solution has some drawbacks, listed in the 'exceptions and
caveats' section, it is more reliable than solutions such as:

* Updating the usage counters with the new 'correct' value every time an
  operation completes.
* Having a periodic task synchronising quota usage data with actual data in
  the Neutron DB.


DbQuotaNoLockDriver description
-------------------------------

The strategy of this quota driver is the opposite to ``DbQuotaDriver``.
Instead of tracking the usage quota of each resource in a specific table,
this driver retrieves the used resources directly form the database.
Each ``TrackedResource`` is linked to a database table that stores the tracked
resources. This driver claims that a trivial query on the resource table,
filtering by project ID, is faster than attending to the DB events and tracking
the quota usage in an independent table.

This driver relays on the database engine transactionality isolation. Each
time a new resource is requested, the quota driver opens a database transaction
to:

* Clean up the expired reservations. The amount of expired reservations is
  always limited because of the short timeout set (2 minutes).
* Retrieve the used resources for a specific project. This query retrieves
  only the "project_id" column of the resource to avoid backref requests; that
  limits the scope of the query and speeds up it.
* Retrieve the reserved resources, created by other concurrent operations.
* If there is enough quota, create a new reservation register.

Those operations, executed in the same transaction, are fast enough to avoid
another concurrent resource reservation, exceeding the available quota. At the
same time, this driver does not create a lock per resource and project ID,
allowing concurrent requests that won't be blocked by the resource lock.
Because the quota reservation process, described before, is a fast operation,
the chances of overcommiting resources over the quota limits are low. Neutron
does not enforce quota in such way that a quota limit violation could never
occur [5]_.

Regardless of whether ``CountableResource`` or ``TrackedResource`` is used, the quota
engine always invokes its ``count()`` method to retrieve resource usage.
Therefore, from the perspective of the Quota engine there is absolutely no
difference between ``CountableResource`` and ``TrackedResource``.

Quota Enforcement in DbQuotaDriver
----------------------------------

Before dispatching a request to the plugin, the Neutron 'base' controller [6]_
attempts to make a reservation for requested resource(s).
Reservations are made by calling the ``make_reservation`` method in
``neutron.quota.QuotaEngine``.
The process of making a reservation is fairly straightforward:

* Get current resource usages. This is achieved by invoking the count method
  on every requested resource, and then retrieving the amount of reserved
  resources.
* Fetch current quota limits for requested resources, by invoking the
  ``_get_project_quotas`` method.
* Fetch expired reservations for selected resources. This amount will be
  subtracted from resource usage. As in most cases there won't be any
  expired reservation, this approach actually requires less DB operations than
  doing a sum of non-expired, reserved resources for each request.
* For each resource calculate its headroom, and verify the requested
  amount of resource is less than the headroom.
* If the above is true for all resource, the reservation is saved in the DB,
  otherwise an ``OverQuotaLimit`` exception is raised.

The quota engine is able to make a reservation for multiple resources.
However, it is worth noting that because of the current structure of the
Neutron API layer, there will not be any practical case in which a reservation
for multiple resources is made. For this reason performance optimisation
avoiding repeating queries for every resource are not part of the current
implementation.

In order to ensure correct operations, a row-level lock is acquired in
the transaction which creates the reservation. The lock is acquired when
reading usage data. In case of write-set certification failures,
which can occur in active/active clusters such as MySQL galera, the decorator
``neutron_lib.db.api.retry_db_errors`` will retry the transaction if a DBDeadLock
exception is raised.
While non-locking approaches are possible, it has been found out that, since
a non-locking algorithms increases the chances of collision, the cost of
handling a ``DBDeadlock`` is still lower than the cost of retrying the operation
when a collision is detected. A study in this direction was conducted for
IP allocation operations, but the same principles apply here as well [7]_.
Nevertheless, moving away for DB-level locks is something that must happen
for quota enforcement in the future.

Committing and cancelling a reservation is as simple as deleting the
reservation itself. When a reservation is committed, the resources which
were committed are now stored in the database, so the reservation itself
should be deleted. The Neutron quota engine simply removes the record when
cancelling a reservation (i.e. the request failed to complete), and also
marks quota usage info as dirty when the reservation is committed (i.e.
the request completed correctly).
Reservations are committed or cancelled by respectively calling the
``commit_reservation`` and ``cancel_reservation`` methods in
``neutron.quota.QuotaEngine``.

Reservations are not perennial. Eternal reservation would eventually exhaust
projects' quotas because they would never be removed when an API worker crashes
whilst in the middle of an operation.
Reservation expiration is currently set to 120 seconds, and is not
configurable, not yet at least. Expired reservations are not counted when
calculating resource usage. While creating a reservation, if any expired
reservation is found, all expired reservation for that project and resource
will be removed from the database, thus avoiding build-up of expired
reservations.

Setting up Resource Tracking for a Plugin
------------------------------------------

By default plugins do not leverage resource tracking. Having the plugin
explicitly declare which resources should be tracked is a precise design
choice aimed at limiting as much as possible the chance of introducing
errors in existing plugins.

For this reason a plugin must declare which resource it intends to track.
This can be achieved using the tracked_resources decorator available in the
neutron.quota.resource_registry module.
The decorator should ideally be applied to the plugin's __init__ method.

The decorator accepts in input a list of keyword arguments. The name of the
argument must be a resource name, and the value of the argument must be
a DB model class. For example:

::

  @resource_registry.tracked_resources(network=models_v2.Network,
                                      port=models_v2.Port,
                                      subnet=models_v2.Subnet,
                                      subnetpool=models_v2.SubnetPool)

Will ensure network, port, subnet and subnetpool resources are tracked.
In theory, it is possible to use this decorator multiple times, and not
exclusively to ``__init__`` methods. However, this would eventually lead to
code readability and maintainability problems, so developers are strongly
encourage to apply this decorator exclusively to the plugin's ``__init__``
method (or any other method which is called by the plugin only once
during its initialization).

Notes for Implementors of RPC Interfaces and RESTful Controllers
-------------------------------------------------------------------------------

Neutron unfortunately does not have a layer which is called before dispatching
the operation from the plugin which can be leveraged both from RESTful and
RPC over AMQP APIs. In particular the RPC handlers call straight into the
plugin, without doing any request authorisation or quota enforcement.

Therefore RPC handlers must explicitly indicate if they are going to call the
plugin to create or delete any sort of resources. This is achieved in a simple
way, by ensuring modified resources are marked as dirty after the RPC handler
execution terminates. To this aim developers can use the mark_resources_dirty
decorator available in the module neutron.quota.resource_registry.

The decorator would scan the whole list of registered resources, and store
the dirty status for their usage trackers in the database for those resources
for which items have been created or destroyed during the plugin operation.

Exceptions and Caveats
-----------------------

Please be aware of the following limitations of the quota enforcement engine:

* Subnet allocation from subnet pools, in particularly shared pools, is also
  subject to quota limit checks. However this checks are not enforced by the
  quota engine, but trough a mechanism implemented in the
  ``neutron.ipam.subnetalloc`` module. This is because the quota engine is not
  able to satisfy the requirements for quotas on subnet allocation.
* The quota engine also provides a ``limit_check`` routine which enforces quota
  checks without creating reservations. This way of doing quota enforcement
  is extremely unreliable and superseded by the reservation mechanism. It
  has not been removed to ensure off-tree plugins and extensions which leverage
  are not broken.
* SqlAlchemy events might not be the most reliable way for detecting changes
  in resource usage. Since the event mechanism monitors the data model class,
  it is paramount for a correct quota enforcement, that resources are always
  created and deleted using object relational mappings. For instance, deleting
  a resource with a ``query.delete`` call will not trigger the event. SQLAlchemy
  events should be considered as a temporary measure adopted as Neutron lacks
  persistent API objects.
* As ``CountableResource`` instance do not track usage data, when making a
  reservation no write-intent lock is acquired. Therefore the quota engine
  with ``CountableResource`` is not concurrency-safe.
* The mechanism for specifying for which resources enable usage tracking
  relies on the fact that the plugin is loaded before quota-limited resources
  are registered. For this reason it is not possible to validate whether a
  resource actually exists or not when enabling tracking for it. Developers
  should pay particular attention into ensuring resource names are correctly
  specified.
* The code assumes usage trackers are a trusted source of truth: if they
  report a usage counter and the dirty bit is not set, that counter is
  correct. If it's dirty than surely that counter is out of sync.
  This is not very robust, as there might be issues upon restart when toggling
  the use_tracked_resources configuration variable, as stale counters might be
  trusted upon for making reservations. Also, the same situation might occur
  if a server crashes after the API operation is completed but before the
  reservation is committed, as the actual resource usage is changed but
  the corresponding usage tracker is not marked as dirty.

References
----------

.. [1] Subnet allocation extension: http://opendev.org/openstack/neutron/src/neutron/extensions/subnetallocation.py
.. [2] DB Quota driver class: http://opendev.org/openstack/neutron/src/neutron/db/quota/driver.py#L30
.. [3] Quota API extension controller: https://opendev.org/openstack/neutron/src/tag/19.0.0/neutron/extensions/quotasv2.py#L56
.. [4] Neutron resource attribute map: https://opendev.org/openstack/neutron-lib/src/tag/2.17.0/neutron_lib/api/attributes.py#L299
.. [5] Quota limit exceeded: https://bugs.launchpad.net/neutron/+bug/1862050/
.. [6] Base controller class: https://opendev.org/openstack/neutron/src/tag/19.0.0/neutron/api/v2/base.py#L44
.. [7] http://lists.openstack.org/pipermail/openstack-dev/2015-February/057534.html
