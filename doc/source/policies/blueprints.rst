Blueprints and Specs
====================

The Neutron team uses the `neutron-specs
<http://git.openstack.org/cgit/openstack/neutron-specs>`_ repository for it's
specification reviews. Detailed information can be found `here
<https://wiki.openstack.org/wiki/Blueprints#Neutron>`_. Please also find
additional information in the reviews.rst file.

The Neutron team does not enforce deadlines for specs and blueprints. These
can be submitted throughout the release cycle. The drivers team will review
this on a regular basis throughout the release, and based on the load for the
milestones, will assign these into milestones or move them to the backlog
for selection into a future release.

Please note that we use a `template
<http://git.openstack.org/cgit/openstack/neutron-specs/tree/specs/template.rst>`_
for spec submissions. It is not required to fill out all sections in the
template. Review of the spec may require filling in information left out by
the submitter.

Neutron BP and Spec Notes
-------------------------

There are occasions when a spec will be approved and the code will not land in
the cycle it was targeted at. For these cases, the work flow to get the spec
into the next release is as follows:

* The PTL will create a <release>-backlog directory during the RC window and
  move all specs which didn't make the <release> there.
* Anyone can propose a patch to neutron-specs which moves a spec from the
  previous release into the new release directory.

The specs which are moved in this way can be fast-tracked into the next
release. Please note that it is required to re-propose the spec for the new
release however.

Neutron Feature Requests
------------------------

We are introducing the concept of feature requests. Feature requests are
tracked as Launchpad bugs, tagged with the new 'rfe' tag, and allow for
the submission and review of these feature requests before code is submitted.
This allows the team to verify the validity of a feature request before the
process of submitting a neutron-spec is undertaken, or code is written.  It
also allows the community to express interest in a feature by subscribing to
the bug and posting a comment in Launchpad. Note the temptation to game the
system exists, but given the history in Neutron for this type of activity, it
will not be tolerated and will be called out as such in public on the mailing
list.

RFEs can be submitted by anyone and by having the community vote on them in
Launchpad, we can gauge interest in features. The drivers team will evaluate
these on a weekly basis along with the specs. RFEs will be evaluated in the
current cycle against existing project priorities and available resources.

The process for moving work from RFEs into the code involves someone assigning
themselves the RFE bug and filing a matching spec using the slimmed down
template in the neutron-specs repository. The spec will then be reviewed by the
community and approved by the drivers team before landing in a release. This is
the same process as before RFEs existed in Neutron.

The workflow for the life an RFE in Launchpad is as follows:

* The bug is submitted and will by default land in the "New" state.
* As soon as a member of the neutron-drivers team acknowledges the bug, it will
  be moved into the "Confirmed" state. No priority, assignee, or milestone is
  set at this time.
* The bug goes into the "Triaged" state once a discussion around the RFE has
  taken place.
* The neutron-drivers team will evaluate the RFE and may advise the submitter
  to file a spec in neutron-specs to elaborate on the feature request.
* The PTL will work with the Lieutenant for the area being identified by the
  RFE to evaluate resources against the current workload.
* In either case (a spec being required or not), once discussion has happened
  the bug will get an assignee, priority and milestone.
* Once a patchset targeting the bug is submitted the bug will move into the
  "In Progress" state.
* When all patches targeting the bug are merged or abandoned, the bug will be
  moved to the "Completed" state.

Cutover to RFEs From Pure Specs
-------------------------------

Prior to the Liberty release, Neutron relied purely on a waterfall model for
handling specs. During Liberty, the goal is to move to the above referenced
RFE process. This will allow for the separation of the "What" from the "How",
and ideally allow for better scheduling of work by the PTL and Lieutenants.
However, given the fact we have a backlog of specs already and new specs
proposed, we need a path forward to not create extra work for everyone.

For Liberty-1, we will allow the old specs to be reviewed as-is. The drivers
team will ensure all specs submitted a week before the Liberty-1 deadline are
given a review and approved or rejected. After Liberty-1, people will not be
required to convert their specs over to RFE bugs during Liberty-1. Once
Liberty-1 passes, all old specs will be moved to a "liberty-backlog" directory
and anything new will follow the new RFE process fully.

RFE Submission Guidelines
-------------------------

#TODO(marun)
