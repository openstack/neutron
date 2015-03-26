Blueprints and Specs
====================

The Neutron team uses the `neutron-specs <http://git.openstack.org/cgit/openstack/neutron-specs>`_
repository for it's specification reviews. Detailed information can be found
`here <https://wiki.openstack.org/wiki/Blueprints#Neutron>`_. Please also find additional
information in the reviews.rst file.

Neutron BP and Spec Notes
-------------------------

There are occasions when a spec will be approved and the code will not land in the cycle it was targeted at. For these cases,
the workflow to get the spec into the next release is as follows:

* The PTL will create a <release>-backlog directory during the RC window and move all specs which didn't make the <release> there.
* Anyone can propose a patch to neutron-specs which moves a spec from the previous release into the new release directory.

The specs which are moved in this way can be fast-tracked into the next release. Please note that it is required to re-propose
the spec for the new release however.
