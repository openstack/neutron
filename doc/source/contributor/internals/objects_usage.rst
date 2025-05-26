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


      Convention for heading levels in neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Objects
=======

Object versioning is a key concept in achieving rolling upgrades. Since its
initial implementation by the nova community, a versioned object model has been
pushed to an oslo library so that its benefits can be shared across projects.

`Oslo VersionedObjects`_ (aka OVO) is a database facade, where you define the
middle layer between software and the database schema. In this layer, a
versioned object per database resource is created with a strict data definition
and version number. With OVO, when you change the database schema, the version
of the object also changes and a backward compatible translation is provided.
This allows different versions of software to communicate with one another (via
RPC).

OVO is also commonly used for RPC payload versioning. OVO creates versioned
dictionary messages by defining a strict structure and keeping strong typing.
Because of it, you can be sure of what is sent and how to use the data on the
receiving end.

.. _Oslo VersionedObjects: https://docs.openstack.org/oslo.versionedobjects/latest/

Usage of objects
----------------

CRUD operations
~~~~~~~~~~~~~~~
Objects support CRUD operations: :code:`create()`, :code:`get_object()` and
:code:`get_objects()` (equivalent of :code:`read`), :code:`update()`,
:code:`delete()`, :code:`update_objects()`, and :code:`delete_objects()`. The
nature of OVO is, when any change is applied, OVO tracks it. After calling
:code:`create()` or :code:`update()`, OVO detects this and changed fields are
saved in the database. Please take a look at simple object usage scenarios
using example of DNSNameServer:

.. code-block:: Python

    # to create an object, you can pass the attributes in constructor:
    dns = DNSNameServer(context, address='asd', subnet_id='xxx', order=1)
    dns.create()

    # or you can create a dict and pass it as kwargs:
    dns_data = {'address': 'asd', 'subnet_id': 'xxx', 'order': 1}
    dns = DNSNameServer(context, **dns_data)
    dns.create()

    # for fetching multiple objects:
    dnses = DNSNameServer.get_objects(context)
    # will return list of all dns name servers from DB

    # for fetching objects with substrings in a string field:
    from neutron_lib.objects import utils as obj_utils
    dnses = DNSNameServer.get_objects(context, address=obj_utils.StringContains('10.0.0'))
    # will return list of all dns name servers from DB that has '10.0.0' in their addresses

    # to update fields:
    dns = DNSNameServer.get_object(context, address='asd', subnet_id='xxx')
    dns.order = 2
    dns.update()

    # if you don't care about keeping the object, you can execute the update
    # without fetch of the object state from the underlying persistent layer
    count = DNSNameServer.update_objects(
        context, {'order': 3}, address='asd', subnet_id='xxx')

    # to remove object with filter arguments:
    filters = {'address': 'asd', 'subnet_id': 'xxx'}
    DNSNameServer.delete_objects(context, **filters)


Filter, sort and paginate
~~~~~~~~~~~~~~~~~~~~~~~~~
The :code:`NeutronDbObject` class has strict validation on which field sorting
and filtering can happen. When calling :code:`get_objects()`, :code:`count()`,
:code:`update_objects()`, :code:`delete_objects()` and :code:`objects_exist()`,
:code:`validate_filters()` is invoked, to see if it's a supported filter
criterion (which is by default non-synthetic fields only). Additional filters
can be defined using :code:`register_filter_hook_on_model()`. This will add the
requested string to valid filter names in object implementation. It is
optional.

In order to disable filter validation, :code:`validate_filters=False` needs to
be passed as an argument in aforementioned methods. It was added because the
default behaviour of the neutron API is to accept everything at API level
and filter it out at DB layer. This can be used by out of tree extensions.

:code:`register_filter_hook_on_model()` is a complementary implementation in
the :code:`NeutronDbObject` layer to DB layer's
:code:`neutron_lib.db.model_query.register_hook()`, which adds support for
extra filtering during construction of SQL query. When extension defines
extra query hook, it needs to be registered using the objects
:code:`register_filter_hook_on_model()`, if it is not already included in the
objects :code:`fields`.

To limit or paginate results, :code:`Pager` object can be used. It accepts
:code:`sorts` (list of :code:`(key, direction)` tuples), :code:`limit`,
:code:`page_reverse` and :code:`marker` keywords.


.. code-block:: Python

    # filtering

    # to get an object based on primary key filter
    dns = DNSNameServer.get_object(context, address='asd', subnet_id='xxx')

    # to get multiple objects
    dnses = DNSNameServer.get_objects(context, subnet_id='xxx')

    filters = {'subnet_id': ['xxx', 'yyy']}
    dnses = DNSNameServer.get_objects(context, **filters)

    # do not validate filters
    dnses = DNSNameServer.get_objects(context, validate_filters=False,
                                      fake_filter='xxx')

    # count the dns servers for given subnet
    dns_count = DNSNameServer.count(context, subnet_id='xxx')

    # sorting
    # direction True == ASC, False == DESC
    direction = False
    pager = Pager(sorts=[('order', direction)])
    dnses = DNSNameServer.get_objects(context, _pager=pager, subnet_id='xxx')


Defining your own object
------------------------

In order to add a new object in neutron, you have to:

#. Create an object derived from :code:`NeutronDbObject` (aka base object)
#. Add/reuse data model
#. Define fields

It is mandatory to define data model using :code:`db_model` attribute from
:code:`NeutronDbObject`.

Fields should be defined using :code:`oslo_versionobjects.fields` exposed
types. If there is a special need to create a new type of field, you can use
:code:`common_types.py` in the :code:`neutron.objects` directory.
Example::

    fields = {
        'id': common_types.UUIDField(),
        'name': obj_fields.StringField(),
        'subnetpool_id': common_types.UUIDField(nullable=True),
        'ip_version': common_types.IPVersionEnumField()
    }

:code:`VERSION` is mandatory and defines the version of the object. Initially,
set the :code:`VERSION` field to 1.0.
Change :code:`VERSION` if fields or their types are modified. When you change
the version of objects being exposed via RPC, add method
:code:`obj_make_compatible(self, primitive, target_version)`. For example, if
a new version introduces a new parameter, it needs to be removed for previous
versions::

    from oslo_utils import versionutils

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):  # version 1.1 introduces "new_parameter"
            primitive.pop('new_parameter', None)

In the following example the object has changed an attribute definition. For
example, in version 1.1 :code:`description` is allowed to be :code:`None` but
not in version 1.0::

    from oslo_utils import versionutils
    from oslo_versionedobjects import exception

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):  # version 1.1 changes "description"
            if primitive['description'] is None:
                # "description" was not nullable before
                raise exception.IncompatibleObjectVersion(
                    objver=target_version, objname='OVOName')

Using the first example as reference, this is how the unit test can be
implemented::

    def test_object_version_degradation_1_1_to_1_0(self):
        OVO_obj_1_1 = self._method_to_create_this_OVO()
        OVO_obj_1_0 = OVO_obj_1_1.obj_to_primitive(target_version='1.0')

        self.assertNotIn('new_parameter', OVO_obj_1_0['versioned_object.data'])

.. note::
   Standard Attributes are automatically added to OVO fields in base class.
   Attributes [#]_ like :code:`description`, :code:`created_at`,
   :code:`updated_at` and :code:`revision_number` are added in [#]_.

:code:`primary_keys` is used to define the list of fields that uniquely
identify the object. In case of database backed objects, it's usually mapped
onto SQL primary keys. For immutable object fields that cannot be changed,
there is a :code:`fields_no_update` list, that contains
:code:`primary_keys` by default.

If there is a situation where a field needs to be named differently in an
object than in the database schema, you can use
:code:`fields_need_translation`. This dictionary contains the name of the field
in the object definition (the key) and the name of the field in the database
(the value). This allows to have a different object layer representation for
database persisted data.
For example in IP allocation pools::

    fields_need_translation = {
        'start': 'first_ip',  # field_ovo: field_db
        'end': 'last_ip'
    }


The above dictionary is used in :code:`modify_fields_from_db()` and in
:code:`modify_fields_to_db()` methods which are implemented in base class and
will translate the software layer to database schema naming, and vice versa. It
can also be used to rename :code:`orm.relationship` backed object-type fields.

Most object fields are usually directly mapped to database model attributes.
Sometimes it's useful to expose attributes that are not defined in the model
table itself, like relationships and such. In this case,
:code:`synthetic_fields` may become handy. This object property can define a
list of object fields that don't belong to the object database model and that
are hence instead to be implemented in some custom way. Some of those fields
map to :code:`orm.relationships` defined on models, while others are completely
untangled from the database layer.

When exposing existing :code:`orm.relationships` as an ObjectField-typed field,
you can use the :code:`foreign_keys` object property that defines a link
between two object types. When used, it allows objects framework to
automatically instantiate child objects, and fill the relevant parent fields,
based on :code:`orm.relationships` defined on parent models. In order to
automatically populate the :code:`synthetic_fields`, the :code:`foreign_keys`
property is introduced. :code:`load_synthetic_db_fields()` [#]_ method from
NeutronDbObject uses :code:`foreign_keys` to match the foreign key in related
object and local field that the foreign key is referring to. See simplified
examples:

.. code-block:: Python

    class DNSNameServerSqlModel(model_base.BASEV2):
        address = sa.Column(sa.String(128), nullable=False, primary_key=True)
        subnet_id = sa.Column(sa.String(36),
                              sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                              primary_key=True)

    class SubnetSqlModel(model_base.BASEV2, HasId, HasProject):
        name = sa.Column(sa.String(attr.NAME_MAX_LEN))
        allocation_pools = orm.relationship(IPAllocationPoolSqlModel)
        dns_nameservers = orm.relationship(DNSNameServerSqlModel,
                                           backref='subnet',
                                           cascade='all, delete, delete-orphan',
                                           lazy='subquery')

    class IPAllocationPoolSqlModel(model_base.BASEV2, HasId):
        subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'))

    @obj_base.VersionedObjectRegistry.register
    class DNSNameServerOVO(base.NeutronDbObject):
        VERSION = '1.0'
        db_model = DNSNameServerSqlModel

        # Created based on primary_key=True in model definition.
        # The object is uniquely identified by the pair of address and
        # subnet_id fields. Override the default 'id' 1-tuple.
        primary_keys = ['address', 'subnet_id']

        # Allow to link DNSNameServerOVO child objects into SubnetOVO parent
        # object fields via subnet_id child database model attribute.
        # Used during loading synthetic fields in SubnetOVO get_objects.
        foreign_keys = {'SubnetOVO': {'subnet_id': 'id'}}

        fields = {
            'address': obj_fields.StringField(),
            'subnet_id': common_types.UUIDField(),
        }

    @obj_base.VersionedObjectRegistry.register
    class SubnetOVO(base.NeutronDbObject):
        VERSION = '1.0'
        db_model =  SubnetSqlModel

        fields = {
            'id': common_types.UUIDField(),  # HasId from model class
            'project_id': obj_fields.StringField(nullable=True),  # HasProject from model class
            'subnet_name': obj_fields.StringField(nullable=True),
            'dns_nameservers': obj_fields.ListOfObjectsField('DNSNameServer',
                                                             nullable=True),
            'allocation_pools': obj_fields.ListOfObjectsField('IPAllocationPoolOVO',
                                                              nullable=True)
        }

        # Claim dns_nameservers field as not directly mapped into the object
        # database model table.
        synthetic_fields = ['allocation_pools', 'dns_nameservers']

        # Rename in-database subnet_name attribute into name object field
        fields_need_translation = {
            'name': 'subnet_name'
        }


    @obj_base.VersionedObjectRegistry.register
    class IPAllocationPoolOVO(base.NeutronDbObject):
        VERSION = '1.0'
        db_model = IPAllocationPoolSqlModel

        fields = {
            'subnet_id': common_types.UUIDField()
        }

        foreign_keys = {'SubnetOVO': {'subnet_id': 'id'}}

The :code:`foreign_keys` is used in :code:`SubnetOVO` to populate the
:code:`allocation_pools` [#]_ synthetic field using the
:code:`IPAllocationPoolOVO` class. Single object type may be linked to multiple
parent object types, hence :code:`foreign_keys` property may have multiple keys
in the dictionary.

.. note::
   :code:`foreign_keys` is declared in related object
   :code:`IPAllocationPoolOVO`, the same way as it's done in the SQL model
   :code:`IPAllocationPoolSqlModel`: :code:`sa.ForeignKey('subnets.id')`

.. note::
   Only single foreign key is allowed (usually parent ID), you cannot link
   through multiple model attributes.

It is important to remember about the nullable parameter. In the SQLAlchemy
model, the nullable parameter is by default :code:`True`, while for OVO fields,
the nullable is set to :code:`False`. Make sure you correctly map database
column nullability properties to relevant object fields.

Synthetic fields
----------------
:code:`synthetic_fields` is a list of fields, that are not directly backed by
corresponding object SQL table attributes. Synthetic fields are not limited in
types that can be used to implement them.

.. code-block:: Python

    fields = {
        'dhcp_agents': obj_fields.ObjectField('NetworkDhcpAgentBinding',
                                              nullable=True), # field that contains another single NeutronDbObject of NetworkDhcpAgentBinding type
        'shared': obj_fields.BooleanField(default=False),
        'subnets': obj_fields.ListOfObjectsField('Subnet', nullable=True)
    }

    # All three fields do not belong to corresponding SQL table, and will be
    # implemented in some object-specific way.
    synthetic_fields = ['dhcp_agents', 'shared', 'subnets']

:code:`ObjectField` and :code:`ListOfObjectsField`  take the name of object
class as an argument.


Implementing custom synthetic fields
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Sometimes you may want to expose a field on an object that is not mapped into a
corresponding database model attribute, or its :code:`orm.relationship`; or may
want to expose a :code:`orm.relationship` data in a format that is not directly
mapped onto a child object type. In this case, here is what you need to do to
implement custom getters and setters for the custom field.
The custom method to load the synthetic fields can be helpful if the field is
not directly defined in the database, OVO class is not suitable to load the
data or the related object contains only the ID and property of the parent
object, for example :code:`subnet_id` and property of it: :code:`is_external`.

In order to implement the custom method to load the synthetic field, you need
to provide loading method in the OVO class and override the base class method
:code:`from_db_object()` and :code:`obj_load_attr()`. The first one is
responsible for loading the fields to object attributes when calling
:code:`get_object()` and :code:`get_objects()`, :code:`create()` and
:code:`update()`. The second is responsible for loading attribute when it is
not set in object. Also, when you need to create related object with attributes
passed in constructor, :code:`create()` and :code:`update()` methods need to be
overwritten. Additionally :code:`is_external` attribute can be exposed as a
boolean, instead of as an object-typed field. When field is changed, but it
doesn't need to be saved into database, :code:`obj_reset_changes()` can be
called, to tell OVO library to ignore that. Let's see an example:


.. code-block:: Python

    @obj_base.VersionedObjectRegistry.register
    class ExternalSubnet(base.NeutronDbObject):
        VERSION = '1.0'
        fields = {'subnet_id': common_types.UUIDField(),
                  'is_external': obj_fields.BooleanField()}
        primary_keys = ['subnet_id']
        foreign_keys = {'Subnet': {'subnet_id': 'id'}}


    @obj_base.VersionedObjectRegistry.register
    class Subnet(base.NeutronDbObject):
        VERSION = '1.0'
        fields = {'external': obj_fields.BooleanField(nullable=True),}
        synthetic_fields = ['external']

        # support new custom 'external=' filter for get_objects family of
        # objects API
        def __init__(self, context=None, **kwargs):
            super(Subnet, self).__init__(context, **kwargs)
            self.add_extra_filter_name('external')

        def create(self):
            fields = self.get_changes()
            with db_api.context_manager.writer.using(context):
                if 'external' in fields:
                    ExternalSubnet(context, subnet_id=self.id,
                        is_external=fields['external']).create()
                # Call to super() to create the SQL record for the object, and
                # reload its fields from the database, if needed.
                super(Subnet, self).create()

        def update(self):
            fields = self.get_changes()
            with db_api.context_manager.writer.using(context):
                if 'external' in fields:
                    # delete the old ExternalSubnet record, if present
                    obj_db_api.delete_objects(
                        self.obj_context, ExternalSubnet.db_model,
                        subnet_id=self.id)
                    # create the new intended ExternalSubnet object
                    ExternalSubnet(context, subnet_id=self.id,
                        is_external=fields['external']).create()
                # calling super().update() will reload the synthetic fields
                # and also will update any changed non-synthetic fields, if any
                super(Subnet, self).update()

        # this method is called when user of an object accesses the attribute
        # and requested attribute is not set.
        def obj_load_attr(self, attrname):
            if attrname == 'external':
                return self._load_external()
            # it is important to call super if attrname does not match
            # because the base implementation is handling the nullable case
            super(Subnet, self).obj_load_attr(attrname)

        def _load_external(self, db_obj=None):
            # do the loading here
            if db_obj:
                # use DB model to fetch the data that may be side-loaded
                external = db_obj.external.is_external if db_obj.external else None
            else:
                # perform extra operation to fetch the data from DB
                external_obj = ExternalSubnet.get_object(context,
                    subnet_id=self.id)
                external = external_obj.is_external if external_obj else None

            # it is important to set the attribute and call obj_reset_changes
            setattr(self, 'external', external)
            self.obj_reset_changes(['external'])

        # this is defined in NeutronDbObject and is invoked during get_object(s)
        # and create/update.
        def from_db_object(self, obj):
            super(Subnet, self).from_db_object(obj)
            self._load_external(obj)

In the above example, the :code:`get_object(s)` methods do not have to be
overwritten, because :code:`from_db_object()` takes care of loading the
synthetic fields in custom way.


Standard attributes
-------------------
The standard attributes are added automatically in metaclass
:code:`DeclarativeObject`. If adding standard attribute, it has to be added in
``neutron/objects/extensions/standardattributes.py``. It will be added
to all relevant objects that use the :code:`standardattributes` model.
Be careful when adding something to the above, because it could trigger a
change in the object's :code:`VERSION`.
For more on how standard attributes work, check [#]_.

RBAC handling in objects
------------------------
The RBAC is implemented currently for resources like: Subnet(*), Network and
QosPolicy. Subnet is a special case, because access control of Subnet depends
on Network RBAC entries.

The RBAC support for objects is defined in ``neutron/objects/rbac_db.py``. It
defines new base class :code:`NeutronRbacObject`. The new class wraps standard
:code:`NeutronDbObject` methods like :code:`create()`, :code:`update()` and
:code:`to_dict()`. It checks if the :code:`shared` attribute is defined in the
:code:`fields` dictionary and adds it to :code:`synthetic_fields`. Also,
:code:`rbac_db_model` is required to be defined in Network and QosPolicy
classes.

:code:`NeutronRbacObject` is a common place to handle all operations on the
RBAC entries, like getting the info if resource is shared or not, creation and
updates of them. By wrapping the :code:`NeutronDbObject` methods, it is
manipulating the 'shared' attribute while :code:`create()` and :code:`update()`
methods are called.

The example of defining the Network OVO:

.. code-block:: Python

    class Network(standard_attr.HasStandardAttributes, model_base.BASEV2,
              model_base.HasId, model_base.HasProject):
        """Represents a v2 neutron network."""
        name = sa.Column(sa.String(attr.NAME_MAX_LEN))
        rbac_entries = orm.relationship(rbac_db_models.NetworkRBAC,
                                        backref='network', lazy='joined',
                                        cascade='all, delete, delete-orphan')


    # Note the base class for Network OVO:
    @obj_base.VersionedObjectRegistry.register
    class Network(rbac_db.NeutronRbacObject):
        # Version 1.0: Initial version
        VERSION = '1.0'

        # rbac_db_model is required to be added here
        rbac_db_model = rbac_db_models.NetworkRBAC
        db_model = models_v2.Network

        fields = {
            'id': common_types.UUIDField(),
            'project_id': obj_fields.StringField(nullable=True),
            'name': obj_fields.StringField(nullable=True),
            # share is required to be added to fields
            'shared': obj_fields.BooleanField(default=False),
        }

.. note::
   The :code:`shared` field is not added to the :code:`synthetic_fields`,
   because :code:`NeutronRbacObject` requires to add it by itself, otherwise
   :code:`ObjectActionError` is raised. [#]_

Extensions to neutron resources
-------------------------------
One of the methods to extend neutron resources is to add an arbitrary value to
dictionary representing the data by providing
:code:`extend_(subnet|port|network)_dict()` function and defining loading
method.

From DB perspective, all the data will be loaded, including all declared fields
from DB relationships. Current implementation for core resources (Port, Subnet,
Network etc.) is that DB result is parsed by :code:`make_<resource>_dict()` and
:code:`extend_<resource>_dict()`. When extension is enabled,
:code:`extend_<resource>_dict()` takes the DB results and declares new fields
in resulting dict. When extension is not enabled, data will be fetched, but
will not be populated into resulting dict, because
:code:`extend_<resource>_dict()` will not be called.

Plugins can still use objects for some work, but then convert them to dicts and
work as they please, extending the dict as they wish.

For example:

.. code-block:: Python

    class TestSubnetExtension(model_base.BASEV2):
        subnet_id = sa.Column(sa.String(36),
                              sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                              primary_key=True)
        value = sa.Column(sa.String(64))
        subnet = orm.relationship(
            models_v2.Subnet,
            # here is the definition of loading the extension with Subnet model:
            backref=orm.backref('extension', cascade='delete', uselist=False))


    @oslo_obj_base.VersionedObjectRegistry.register_if(False)
    class TestSubnetExtensionObject(obj_base.NeutronDbObject):
        # Version 1.0: Initial version
        VERSION = '1.0'

        db_model = TestSubnetExtension

        fields = {
            'subnet_id': common_types.UUIDField(),
            'value': obj_fields.StringField(nullable=True)
        }

        primary_keys = ['subnet_id']
        foreign_keys = {'Subnet': {'subnet_id': 'id'}}


    @obj_base.VersionedObjectRegistry.register
    class Subnet(base.NeutronDbObject):
        # Version 1.0: Initial version
        VERSION = '1.0'

        fields = {
            'id': common_types.UUIDField(),
            'extension': obj_fields.ObjectField(TestSubnetExtensionObject.__name__,
                                                nullable=True),
        }

        synthetic_fields = ['extension']


    # when defining the extend_subnet_dict function:
    def extend_subnet_dict(self, session, subnet_ovo, result):
        value = subnet_ovo.extension.value if subnet_ovo.extension else ''
        result['subnet_extension'] = value

The above example is the ideal situation, where all extensions have objects
adopted and enabled in core neutron resources.

By introducing the OVO work in tree, interface between base plugin code and
registered extension functions hasn't been changed. Those still receive a
SQLAlchemy model, not an object. This is achieved by capturing the
corresponding database model on :code:`get_***/create/update`, and exposing it
via :code:`<object>.db_obj`

Removal of downgrade checks over time
-------------------------------------
While the code to check object versions is meant to remain for a long period of
time, in the interest of not accruing too much cruft over time, they are not
intended to be permanent.  OVO downgrade code should account for code that is
within the upgrade window of any major OpenStack distribution.  The longest
currently known is for Ubuntu Cloud Archive which is to upgrade four versions,
meaning during the upgrade the control nodes would be running a release that is
four releases newer than what is running on the computes.

Known fast forward upgrade windows are:

* Red Hat OpenStack Platform (RHOSP): X -> X+3 [#]_
* Ubuntu Cloud Archive: X -> X+4 [#]_

Therefore removal of OVO version downgrade code should be removed in the fifth
cycle after the code was introduced.  For example, if an object version was
introduced in Ocata then it can be removed in Train.

Backward compatibility for tenant_id
------------------------------------
All objects can support :code:`tenant_id` and :code:`project_id` filters and
fields at the same time; it is automatically enabled for all objects that have
a :code:`project_id` field. The base :code:`NeutronDbObject` class has support
for exposing :code:`tenant_id` in dictionary access to the object fields
(:code:`subnet['tenant_id']`) and in :code:`to_dict()` method. There is a
:code:`tenant_id` read-only property for every object that has
:code:`project_id` in :code:`fields`. It is not exposed in
:code:`obj_to_primitive()` method, so it means that :code:`tenant_id` will not
be sent over RPC callback wire. When talking about filtering/sorting by
:code:`tenant_id`, the filters should be converted to expose :code:`project_id`
field. This means that for the long run, the API layer should translate it, but
as temporary workaround it can be done at DB layer before passing filters to
objects :code:`get_objects()` method, for example:

.. code-block:: Python

    def convert_filters(result):
        if 'tenant_id' in result:
            result['project_id'] = result.pop('tenant_id')
        return result

    def get_subnets(context, filters):
        filters = convert_filters(**filters)
        return subnet_obj.Subnet.get_objects(context, **filters)

The :code:`convert_filters` method is available in
``neutron_lib.objects.utils`` [#]_.

References
----------
.. [#] https://opendev.org/openstack/neutron/src/tag/ocata-eol/neutron/objects/base.py#L258
.. [#] https://opendev.org/openstack/neutron/src/tag/ocata-eol/neutron/db/standard_attr.py
.. [#] https://opendev.org/openstack/neutron/src/tag/ocata-eol/neutron/objects/base.py#L516
.. [#] https://opendev.org/openstack/neutron/src/tag/ocata-eol/neutron/objects/base.py#L542
.. [#] https://docs.openstack.org/neutron/latest/contributor/internals/db_layer.html#the-standard-attribute-table
.. [#] https://opendev.org/openstack/neutron/src/tag/ocata-eol/neutron/objects/rbac_db.py#L291
.. [#] https://access.redhat.com/support/policy/updates/openstack/platform/
.. [#] https://www.ubuntu.com/about/release-cycle
.. [#] https://opendev.org/openstack/neutron-lib/src/neutron_lib/objects/utils.py
