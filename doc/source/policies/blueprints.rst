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

Neutron Request for Feature Enhancements
----------------------------------------

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

Before we dive into the guidelines for writing a good RFE, it is worth mentioning
that depending on your level of engagement with the Neutron project and your role
(user, developer, deployer, operator, etc.), you are more than welcome to have
a preliminary discussion of a potential RFE by reaching out to other people involved
in the project. This usually happens by posting mails on the relevant mailing
lists (e.g. `openstack-dev <http://lists.openstack.org>`_ - include [neutron] in
the subject) or on #openstack-neutron IRC channel on Freenode. If current ongoing
code reviews are related to your feature, posting comments/questions on gerrit
may also be a way to engage. Some amount of interaction with Neutron developers
will give you an idea of the plausibility and form of your RFE before you submit
it. That said, this is not mandatory.

When you submit a bug report on https://bugs.launchpad.net/neutron/+filebug,
there are two fields that must be filled: 'summary' and 'further information'.
The 'summary' must be brief enough to fit in one line: if you can't describe it
in a few words it may mean that you are either trying to capture more than one
RFE at once, or that you are having a hard time defining what you are trying to
solve at all.

The 'further information' section must be a description of what you would like
to see implemented in Neutron. The description should provide enough details for
a knowledgeable developer to understand what is the existing problem in the
current platform that needs to be addressed, or what is the enhancement that
would make the platform more capable, both for a functional and a non-functional
standpoint. To this aim it is important to describe 'why' you believe the RFE
should be accepted, and motivate the reason why without it Neutron is a poorer
platform. The description should be self contained, and no external references
should be necessary to further explain the RFE.

In other words, when you write an RFE you should ask yourself the following
questions:

* What is that I (specify what user - a user can be a human or another system)
  cannot do today when interacting with Neutron? On the other hand, is there a
  Neutron component X that is unable to accomplish something?
* Is there something that you would like Neutron handle better, ie. in a more
  scalable, or in a more reliable way?
* What is that I would like to see happen after the RFE is accepted and
  implemented?
* Why do you think it is important?

Once you are happy with what you wrote, add 'rfe' as tag, and submit. Do not
worry, we are here to help you get it right! Happy hacking.
