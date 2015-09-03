================================
Quota Management and Enforcement
================================

Most resources exposed by the Neutron API are subject to quota limits.
The Neutron API exposes an extension for managing such quotas. Quota limits are
enforced at the API layer, before the request is dispatched to the plugin.

Default values for quota limits are specified in neutron.conf. Admin users
can override those defaults values on a per-tenant basis. Limits are stored
in the Neutron database; if no limit is found for a given resource and tenant,
then the default value for such resource is used.
Configuration-based quota management, where every tenant gets the same quota
limit specified in the configuration file, has been deprecated as of the
Liberty release.

Please note that Neutron does not support both specification of quota limits
per user and quota management for hierarchical multitenancy (as a matter of
fact Neutron does not support hierarchical multitenancy at all). Also, quota
limits are currently not enforced on RPC interfaces listening on the AMQP
bus.

Plugin and ML2 drivers are not supposed to enforce quotas for resources they
manage. However, the subnet_allocation [#]_ extension is an exception and will
be discussed below.

The quota management and enforcement mechanisms discussed here apply to every
resource which has been registered with the Quota engine, regardless of
whether such resource belongs to the core Neutron API or one of its extensions.

High Level View
---------------

There are two main components in the Neutron quota system:

 * The Quota API extension;
 * The Quota Engine.

Both components rely on a quota driver. The neutron codebase currently defines
two quota drivers:

 * neutron.db.quota.driver.DbQuotaDriver
 * neutron.quota.ConfDriver

The latter driver is however deprecated.

The Quota API extension handles quota management, whereas the Quota Engine
component handles quota enforcement. This API extension is loaded like any
other extension. For this reason plugins must explicitly support it by including
"quotas" in the support_extension_aliases attribute.

In the Quota API simple CRUD operations are used for managing tenant quotas.
Please note that the current behaviour when deleting a tenant quota is to reset
quota limits for that tenant to configuration defaults. The API
extension does not validate the tenant identifier with the identity service.

Performing quota enforcement is the responsibility of the Quota Engine.
RESTful API controllers, before sending a request to the plugin, try to obtain
a reservation from the quota engine for the resources specified in the client
request. If the reservation is successful, then it proceeds to dispatch the
operation to the plugin.

For a reservation to be successful, the total amount of resources requested,
plus the total amount of resources reserved, plus the total amount of resources
already stored in the database should not exceed the tenant's quota limit.

Finally, both quota management and enforcement rely on a "quota driver" [#]_,
whose task is basically to perform database operations.

Quota Management
----------------

The quota management component is fairly straightforward.

However, unlike the vast majority of Neutron extensions, it uses it own
controller class [#]_.
This class does not implement the POST operation. List, get, update, and
delete operations are implemented by the usual index, show, update and
delete methods. These method simply call into the quota driver for either
fetching tenant quotas or updating them.

The _update_attributes method is called only once in the controller lifetime.
This method dynamically updates Neutron's resource attribute map [#]_ so that
an attribute is added for every resource managed by the quota engine.
Request authorisation is performed in this controller, and only 'admin' users
are allowed to modify quotas for tenants. As the neutron policy engine is not
used, it is not possible to configure which users should be allowed to manage
quotas using policy.json.

The driver operations dealing with quota management are:

 * delete_tenant_quota, which simply removes all entries from the 'quotas'
   table for a given tenant identifier;
 * update_quota_limit, which adds or updates an entry in the 'quotas' tenant for
   a given tenant identifier and a given resource name;
 * _get_quotas, which fetches limits for a set of resource and a given tenant
   identifier
 * _get_all_quotas, which behaves like _get_quotas, but for all tenants.


Resource Usage Info
-------------------

Neutron has two ways of tracking resource usage info:

 * CountableResource, where resource usage is calculated every time quotas
   limits are enforced by counting rows in the resource table and reservations
   for that resource.
 * TrackedResource, which instead relies on a specific table tracking usage
   data, and performs explicitly counting only when the data in this table are
   not in sync with actual used and reserved resources.

Another difference between CountableResource and TrackedResource is that the
former invokes a plugin method to count resources. CountableResource should be
therefore employed for plugins which do not leverage the Neutron database.
The actual class that the Neutron quota engine will use is determined by the
track_quota_usage variable in the quota configuration section. If True,
TrackedResource instances will be created, otherwise the quota engine will
use CountableResource instances.
Resource creation is performed by the create_resource_instance factory method
in the neutron.quota.resource module.

From a performance perspective, having a table tracking resource usage
has some advantages, albeit not fundamental. Indeed the time required for
executing queries to explicitly count objects will increase with the number of
records in the table. On the other hand, using TrackedResource will fetch a
single record, but has the drawback of having to execute an UPDATE statement
once the operation is completed.
Nevertheless, CountableResource instances do not simply perform a SELECT query
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

To this aim, TrackedResource instances are initialised with a reference to
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

Finally, regardless of whether CountableResource or TrackedResource is used,
the quota engine always invokes its count() method to retrieve resource usage.
Therefore, from the perspective of the Quota engine there is absolutely no
difference between CountableResource and TrackedResource.

Quota Enforcement
-----------------

**NOTE: The reservation engine is currently not wired into the API controller
as issues have been discovered with multiple workers. For more information
see _bug1468134**

.. _bug1468134: https://bugs.launchpad.net/neutron/+bug/1486134

Before dispatching a request to the plugin, the Neutron 'base' controller [#]_
attempts to make a reservation for requested resource(s).
Reservations are made by calling the make_reservation method in
neutron.quota.QuotaEngine.
The process of making a reservation is fairly straightforward:

 * Get current resource usages. This is achieved by invoking the count method
   on every requested resource, and then retrieving the amount of reserved
   resources.
 * Fetch current quota limits for requested resources, by invoking the
   _get_tenant_quotas method.
 * Fetch expired reservations for selected resources. This amount will be
   subtracted from resource usage. As in most cases there won't be any
   expired reservation, this approach actually requires less DB operations than
   doing a sum of non-expired, reserved resources for each request.
 * For each resource calculate its headroom, and verify the requested
   amount of resource is less than the headroom.
 * If the above is true for all resource, the reservation is saved in the DB,
   otherwise an OverQuotaLimit exception is raised.

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
oslo_db.api.wrap_db_retry will retry the transaction if a DBDeadLock
exception is raised.
While non-locking approaches are possible, it has been found out that, since
a non-locking algorithms increases the chances of collision, the cost of
handling a DBDeadlock is still lower than the cost of retrying the operation
when a collision is detected. A study in this direction was conducted for
IP allocation operations, but the same principles apply here as well [#]_.
Nevertheless, moving away for DB-level locks is something that must happen
for quota enforcement in the future.

Committing and cancelling a reservation is as simple as deleting the
reservation itself. When a reservation is committed, the resources which
were committed are now stored in the database, so the reservation itself
should be deleted. The Neutron quota engine simply removes the record when
cancelling a reservation (ie: the request failed to complete), and also
marks quota usage info as dirty when the reservation is committed (ie:
the request completed correctly).
Reservations are committed or cancelled by respectively calling the
commit_reservation and cancel_reservation methods in neutron.quota.QuotaEngine.

Reservations are not perennial. Eternal reservation would eventually exhaust
tenants' quotas because they would never be removed when an API worker crashes
whilst in the middle of an operation.
Reservation expiration is currently set to 120 seconds, and is not
configurable, not yet at least. Expired reservations are not counted when
calculating resource usage. While creating a reservation, if any expired
reservation is found, all expired reservation for that tenant and resource
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
exclusively to __init__ methods. However, this would eventually lead to
code readability and maintainability problems, so developers are strongly
encourage to apply this decorator exclusively to the plugin's __init__
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
   neutron.ipam.subnetalloc module. This is because the Quota engine is not
   able to satisfy the requirements for quotas on subnet allocation.
 * The quota engine also provides a limit_check routine which enforces quota
   checks without creating reservations. This way of doing quota enforcement
   is extremely unreliable and superseded by the reservation mechanism. It
   has not been removed to ensure off-tree plugins and extensions which leverage
   are not broken.
 * SqlAlchemy events might not be the most reliable way for detecting changes
   in resource usage. Since the event mechanism monitors the data model class,
   it is paramount for a correct quota enforcement, that resources are always
   created and deleted using object relational mappings. For instance, deleting
   a resource with a query.delete call, will not trigger the event. SQLAlchemy
   events should be considered as a temporary measure adopted as Neutron lacks
   persistent API objects.
 * As CountableResource instance do not track usage data, when making a
   reservation no write-intent lock is acquired. Therefore the quota engine
   with CountableResource is not concurrency-safe.
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

.. [#] Subnet allocation extension: http://git.openstack.org/cgit/openstack/neutron/tree/neutron/extensions/subnetallocation.py
.. [#] DB Quota driver class: http://git.openstack.org/cgit/openstack/neutron/tree/neutron/db/quota_db.py#n33
.. [#] Quota API extension controller: http://git.openstack.org/cgit/openstack/neutron/tree/neutron/extensions/quotasv2.py#n40
.. [#] Neutron resource attribute map: http://git.openstack.org/cgit/openstack/neutron/tree/neutron/api/v2/attributes.py#n639
.. [#] Base controller class: http://git.openstack.org/cgit/openstack/neutron/tree/neutron/api/v2/base.py#n50
.. [#] http://lists.openstack.org/pipermail/openstack-dev/2015-February/057534.html
