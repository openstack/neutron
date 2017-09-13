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


Effective Neutron: 100 specific ways to improve your Neutron contributions
==========================================================================

There are a number of skills that make a great Neutron developer: writing good
code, reviewing effectively, listening to peer feedback, etc. The objective of
this document is to describe, by means of examples, the pitfalls, the good and
bad practices that 'we' as project encounter on a daily basis and that make us
either go slower or accelerate while contributing to Neutron.

By reading and collaboratively contributing to such a knowledge base, your
development and review cycle becomes shorter, because you will learn (and teach
to others after you) what to watch out for, and how to be proactive in order
to prevent negative feedback, minimize programming errors, writing better
tests, and so on and so forth...in a nutshell, how to become an effective Neutron
developer.

The notes below are meant to be free-form and brief by design. They are not meant
to replace or duplicate `OpenStack documentation <http://docs.openstack.org>`_,
or any project-wide documentation initiative like `peer-review notes <http://docs.openstack.org/infra/manual/developers.html#peer-review>`_
or the `team guide <http://docs.openstack.org/project-team-guide/>`_. For this
reason, references are acceptable and should be favored, if the shortcut is
deemed useful to expand on the distilled information.
We will try to keep these notes tidy by breaking them down into sections if it
makes sense. Feel free to add, adjust, remove as you see fit. Please do so,
taking into consideration yourself and other Neutron developers as readers.
Capture your experience during development and review and add any comment that
you believe will make your life and others' easier.

Happy hacking!

Developing better software
--------------------------

Plugin development
~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done during plugin development.

* Use mixin classes as last resort. They can be a powerful tool to add behavior
  but their strength is also a weakness, as they can introduce `unpredictable <https://review.openstack.org/#/c/121290/>`_
  behavior to the `MRO <https://www.python.org/download/releases/2.3/mro/>`_,
  amongst other issues.
* In lieu of mixins, if you need to add behavior that is relevant for ML2,
  consider using the `extension manager <http://specs.openstack.org/openstack/neutron-specs/specs/juno/neutron-ml2-mechanismdriver-extensions.html>`_.
* If you make changes to the DB class methods, like calling methods that can
  be inherited, think about what effect that may have to plugins that have
  controller `backends <https://review.openstack.org/#/c/116924/>`_.
* If you make changes to the ML2 plugin or components used by the ML2 plugin,
  think about the `effect <http://lists.openstack.org/pipermail/openstack-dev/2015-October/076134.html>`_
  that may have to other plugins.
* When adding behavior to the L2 and L3 db base classes, do not assume that
  there is an agent on the other side of the message broker that interacts
  with the server. Plugins may not rely on `agents <https://review.openstack.org/#/c/174020/>`_ at all.
* Be mindful of required capabilities when you develop plugin extensions. The
  `Extension description <https://github.com/openstack/neutron/blob/b14c06b5/neutron/api/extensions.py#L122>`_ provides the ability to specify the list of required capabilities
  for the extension you are developing. By declaring this list, the server will
  not start up if the requirements are not met, thus avoiding leading the system
  to experience undetermined behavior at runtime.

Database interaction
~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done during database development.

* `first() <http://docs.sqlalchemy.org/en/rel_1_0/orm/query.html#sqlalchemy.orm.query.Query.first>`_
  does not raise an exception.
* Do not use `delete() <http://docs.sqlalchemy.org/en/rel_1_0/orm/query.html#sqlalchemy.orm.query.Query.delete>`_
  to remove objects. A delete query does not load the object so no sqlalchemy events
  can be triggered that would do things like recalculate quotas or update revision
  numbers of parent objects. For more details on all of the things that can go wrong
  using bulk delete operations, see the "Warning" sections in the link above.
* For PostgreSQL if you're using GROUP BY everything in the SELECT list must be
  an aggregate SUM(...), COUNT(...), etc or used in the GROUP BY.

  The incorrect variant:

  .. code:: python

     q = query(Object.id, Object.name,
               func.count(Object.number)).group_by(Object.name)

  The correct variant:

  .. code:: python

     q = query(Object.id, Object.name,
               func.count(Object.number)).group_by(Object.id, Object.name)
* Beware of the `InvalidRequestError <http://docs.sqlalchemy.org/en/latest/faq/sessions.html#this-session-s-transaction-has-been-rolled-back-due-to-a-previous-exception-during-flush-or-similar>`_ exception.
  There is even a `Neutron bug <https://bugs.launchpad.net/neutron/+bug/1409774>`_
  registered for it. Bear in mind that this error may also occur when nesting
  transaction blocks, and the innermost block raises an error without proper
  rollback. Consider if `savepoints <http://docs.sqlalchemy.org/en/rel_1_0/orm/session_transaction.html#using-savepoint>`_
  can fit your use case.
* When designing data models that are related to each other, be careful to how
  you model the relationships' loading `strategy <http://docs.sqlalchemy.org/en/latest/orm/loading_relationships.html#using-loader-strategies-lazy-loading-eager-loading>`_. For instance a joined relationship can
  be very efficient over others (some examples include `router gateways <https://review.openstack.org/#/c/88665/>`_
  or `network availability zones <https://review.openstack.org/#/c/257086/>`_).
* If you add a relationship to a Neutron object that will be referenced in the
  majority of cases where the object is retrieved, be sure to use the
  lazy='joined' parameter to the relationship so the related objects are loaded
  as part of the same query. Otherwise, the default method is 'select', which
  emits a new DB query to retrieve each related object adversely impacting
  performance. For example, see `patch 88665 <https://review.openstack.org/#/c/88665/>`_
  which resulted in a significant improvement since router retrieval functions
  always include the gateway interface.
* Conversely, do not use lazy='joined' if the relationship is only used in
  corner cases because the JOIN statement comes at a cost that may be
  significant if the relationship contains many objects. For example, see
  `patch 168214 <https://review.openstack.org/#/c/168214/>`_ which reduced a
  subnet retrieval by ~90% by avoiding a join to the IP allocation table.
* When writing extensions to existing objects (e.g. Networks), ensure that
  they are written in a way that the data on the object can be calculated
  without additional DB lookup. If that's not possible, ensure the DB lookup
  is performed once in bulk during a list operation. Otherwise a list call
  for a 1000 objects will change from a constant small number of DB queries
  to 1000 DB queries. For example, see
  `patch 257086 <https://review.openstack.org/#/c/257086/>`_ which changed the
  availability zone code from the incorrect style to a database friendly one.

* Sometimes in code we use the following structures:

  .. code:: python

     def create():
        with context.session.begin(subtransactions=True):
            create_something()
            try:
                _do_other_thing_with_created_object()
            except Exception:
                with excutils.save_and_reraise_exception():
                    delete_something()

     def _do_other_thing_with_created_object():
        with context.session.begin(subtransactions=True):
            ....

  The problem is that when exception is raised in ``_do_other_thing_with_created_object``
  it is caught in except block, but the object cannot be deleted in except
  section because internal transaction from ``_do_other_thing_with_created_object``
  has been rolled back. To avoid this nested transactions should be used.
  For such cases help function ``safe_creation`` has been created in
  ``neutron/db/_utils.py``.
  So, the example above should be replaced with:

  .. code:: python

     _safe_creation(context, create_something, delete_something,
                    _do_other_thing_with_created_object)

  Where nested transaction is used in _do_other_thing_with_created_object
  function.

  The ``_safe_creation function can also be passed the ``transaction=False``
  argument to prevent any transaction from being created just to leverage
  the automatic deletion on exception logic.

* Beware of ResultProxy.inserted_primary_key which returns a list of last
  inserted primary keys not the last inserted primary key:

  .. code:: python

     result = session.execute(mymodel.insert().values(**values))
     # result.inserted_primary_key is a list even if we inserted a unique row!

* Beware of pymysql which can silently unwrap a list with an element (and hide
  a wrong use of ResultProxy.inserted_primary_key for example):

  .. code:: python

     e.execute("create table if not exists foo (bar integer)")
     e.execute(foo.insert().values(bar=1))
     e.execute(foo.insert().values(bar=[2]))

  The 2nd insert should crash (list provided, integer expected). It crashes at
  least with mysql and postgresql backends, but succeeds with pymysql because
  it transforms them into:

  .. code:: sql

     INSERT INTO foo (bar) VALUES (1)
     INSERT INTO foo (bar) VALUES ((2))


System development
~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when invoking system commands
and interacting with linux utils.

* When a patch requires a new platform tool or a new feature in an existing
  tool, check if common platforms ship packages with the aforementioned
  feature. Also, tag such a patch with ``UpgradeImpact`` to raise its
  visibility (as these patches are brought up to the attention of the core team
  during team meetings).
  More details in :ref:`review guidelines <spec-review-practices>`.
* When a patch or the code depends on a new feature in the kernel or in any platform tools
  (dnsmasq, ip, Open vSwitch etc.), consider introducing a new sanity check to
  validate deployments for the expected features. Note that sanity checks *must
  not* check for version numbers of underlying platform tools because
  distributions may decide to backport needed features into older versions.
  Instead, sanity checks should validate actual features by attempting to use them.

Eventlet concurrent model
~~~~~~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when using eventlet and monkey
patching.

* Do not use with_lockmode('update') on SQL queries without protecting the operation
  with a lockutils semaphore. For some SQLAlchemy database drivers that operators may
  choose (e.g. MySQLdb) it may result in a temporary deadlock by yielding to another
  coroutine while holding the DB lock. The following wiki provides more details:
  https://wiki.openstack.org/wiki/OpenStack_and_SQLAlchemy#MySQLdb_.2B_eventlet_.3D_sad

Mocking and testing
~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing tests, any test.
For anything more elaborate, please visit the testing section.

* Preferring low level testing versus full path testing (e.g. not testing database
  via client calls). The former is to be favored in unit testing, whereas the latter
  is to be favored in functional testing.
* Prefer specific assertions (assert(Not)In, assert(Not)IsInstance, assert(Not)IsNone,
  etc) over generic ones (assertTrue/False, assertEqual) because they raise more
  meaningful errors:

  .. code:: python

     def test_specific(self):
         self.assertIn(3, [1, 2])
         # raise meaningful error: "MismatchError: 3 not in [1, 2]"

     def test_generic(self):
         self.assertTrue(3 in [1, 2])
         # raise meaningless error: "AssertionError: False is not true"

* Use the pattern "self.assertEqual(expected, observed)" not the opposite, it helps
  reviewers to understand which one is the expected/observed value in non-trivial
  assertions. The expected and observed values are also labeled in the output when
  the assertion fails.
* Prefer specific assertions (assertTrue, assertFalse) over assertEqual(True/False, observed).
* Don't write tests that don't test the intended code. This might seem silly but
  it's easy to do with a lot of mocks in place. Ensure that your tests break as
  expected before your code change.
* Avoid heavy use of the mock library to test your code. If your code requires more
  than one mock to ensure that it does the correct thing, it needs to be refactored
  into smaller, testable units. Otherwise we depend on fullstack/tempest/api tests
  to test all of the real behavior and we end up with code containing way too many
  hidden dependencies and side effects.
* All behavior changes to fix bugs should include a test that prevents a
  regression. If you made a change and it didn't break a test, it means the
  code was not adequately tested in the first place, it's not an excuse to leave
  it untested.
* Test the failure cases. Use a mock side effect to throw the necessary
  exceptions to test your 'except' clauses.
* Don't mimic existing tests that violate these guidelines. We are attempting to
  replace all of these so more tests like them create more work. If you need help
  writing a test, reach out to the testing lieutenants and the team on IRC.
* Mocking open() is a dangerous practice because it can lead to unexpected
  bugs like `bug 1503847 <https://bugs.launchpad.net/neutron/+bug/1503847>`_.
  In fact, when the built-in open method is mocked during tests, some
  utilities (like debtcollector) may still rely on the real thing, and may
  end up using the mock rather what they are really looking for. If you must,
  consider using `OpenFixture <https://review.openstack.org/#/c/232716/>`_, but
  it is better not to mock open() at all.

Documentation
~~~~~~~~~~~~~

The documenation for Neutron that exists in this repository is broken
down into the following directories based on content:

* doc/source/admin/ - feature-specific configuration documentation aimed
  at operators.
* doc/source/configuration - stubs for auto-generated configuration files.
  Only needs updating if new config files are added.
* doc/source/contributor/internals - developer documentation for lower-level
  technical details.
* doc/source/contributor/policies - neutron team policies and best practices.
* doc/source/install - install-specific documentation for standing-up
  network-enabled nodes.

Additional documentation resides in the neutron-lib repository:

* api-ref - API reference documentation for Neutron resource and API extensions.

Backward compatibility
~~~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when extending the RPC Interfaces.

* Make yourself familiar with :ref:`Upgrade review guidelines <upgrade_review_guidelines>`.

Deprecation
+++++++++++

Sometimes we want to refactor things in a non-backward compatible way. In most
cases you can use `debtcollector
<http://docs.openstack.org/debtcollector/latest/>`_ to mark things for
deprecation. Config items have `deprecation options supported by oslo.config
<https://docs.openstack.org/oslo.config/latest/reference/opts.html>`_.

The deprecation process must follow the `standard deprecation requirements
<http://governance.openstack.org/reference/tags/assert_follows-standard-deprecation.html#requirements>`_.
In terms of neutron development, this means:

* A launchpad bug to track the deprecation.
* A patch to mark the deprecated items. If the deprecation affects
  users (config items, API changes) then a `release note
  <https://docs.openstack.org/reno/latest/user/usage.html>`_ must be
  included.
* Wait at least one cycle and at least three months linear time.
* A patch that removes the deprecated items. Make sure to refer to the
  original launchpad bug in the commit message of this patch.


Scalability issues
~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing code that needs to process
a lot of data.

Translation and logging
~~~~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when instrumenting your code.

* Make yourself familiar with `OpenStack logging guidelines <http://specs.openstack.org/openstack/openstack-specs/specs/log-guidelines.html#definition-of-log-levels>`_
  to avoid littering the logs with traces logged at inappropriate levels.
* The logger should only be passed unicode values. For example, do not pass it
  exceptions or other objects directly (LOG.error(exc), LOG.error(port), etc.).
  See https://docs.openstack.org/oslo.log/latest/user/migration.html#no-more-implicit-conversion-to-unicode-str
  for more details.
* Don't pass exceptions into LOG.exception: it is already implicitly included
  in the log message by Python logging module.
* Don't use LOG.exception when there is no exception registered in current
  thread context: Python 3.x versions before 3.5 are known to fail on it.

Project interfaces
~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing code that is used
to interface with other projects, like Keystone or Nova.

Documenting your code
~~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing docstrings.

Landing patches more rapidly
----------------------------

Scoping your patch appropriately
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Do not make multiple changes in one patch unless absolutely necessary.
  Cleaning up nearby functions or fixing a small bug you noticed while working
  on something else makes the patch very difficult to review. It also makes
  cherry-picking and reverting very difficult.  Even apparently minor changes
  such as reformatting whitespace around your change can burden reviewers and
  cause merge conflicts.
* If a fix or feature requires code refactoring, submit the refactoring as a
  separate patch than the one that changes the logic. Otherwise
  it's difficult for a reviewer to tell the difference between mistakes
  in the refactor and changes required for the fix/feature. If it's a bug fix,
  try to implement the fix before the refactor to avoid making cherry-picks to
  stable branches difficult.
* Consider your reviewers' time before submitting your patch. A patch that
  requires many hours or days to review will sit in the "todo" list until
  someone has many hours or days free (which may never happen.) If you can
  deliver your patch in small but incrementally understandable and testable
  pieces you will be more likely to attract reviewers.

Nits and pedantic comments
~~~~~~~~~~~~~~~~~~~~~~~~~~

Document common nits and pedantic comments to watch out for.

* Make sure you spell correctly, the best you can, no-one wants rebase generators at
  the end of the release cycle!
* The odd pep8 error may cause an entire CI run to be wasted. Consider running
  validation (pep8 and/or tests) before submitting your patch. If you keep forgetting
  consider installing a git `hook <https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks>`_
  so that Git will do it for you.
* Sometimes, new contributors want to dip their toes with trivial patches, but we
  at OpenStack *love* bike shedding and their patches may sometime stall. In
  some extreme cases, the more trivial the patch, the higher the chances it fails
  to merge. To ensure we as a team provide/have a frustration-free experience
  new contributors should be redirected to fixing `low-hanging-fruit bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=low-hanging-fruit>`_
  that have a tangible positive impact to the codebase. Spelling mistakes, and
  docstring are fine, but there is a lot more that is relatively easy to fix
  and has a direct impact to Neutron users.

Reviewer comments
~~~~~~~~~~~~~~~~~

* Acknowledge them one by one by either clicking 'Done' or by replying extensively.
  If you do not, the reviewer won't know whether you thought it was not important,
  or you simply forgot. If the reply satisfies the reviewer, consider capturing the
  input in the code/document itself so that it's for reviewers of newer patchsets to
  see (and other developers when the patch merges).
* Watch for the feedback on your patches. Acknowledge it promptly and act on it
  quickly, so that the reviewer remains engaged. If you disappear for a week after
  you posted a patchset, it is very likely that the patch will end up being
  neglected.
* Do not take negative feedback personally. Neutron is a large project with lots
  of contributors with different opinions on how things should be done. Many come
  from widely varying cultures and languages so the English, text-only feedback
  can unintentionally come across as harsh. Getting a -1 means reviewers are
  trying to help get the patch into a state that can be merged, it doesn't just
  mean they are trying to block it. It's very rare to get a patch merged on the
  first iteration that makes everyone happy.

Code Review
~~~~~~~~~~~

* You should visit `OpenStack How To Review wiki <https://wiki.openstack.org/wiki/How_To_Contribute#Reviewing>`_
* Stay focussed and review what matters for the release. Please check out the Neutron
  section for the `Gerrit dashboard <http://status.openstack.org/reviews/>`_. The output
  is generated by this `tool <https://github.com/openstack-infra/reviewday/blob/master/bin/neutron>`_.

IRC
~~~~

* IRC is a place where you can speak with many of the Neutron developers and core
  reviewers. For more information you should visit
  `OpenStack IRC wiki <http://wiki.openstack.org/wiki/IRC>`_
  Neutron IRC channel is #openstack-neutron
* There are weekly IRC meetings related to many different projects/teams
  in Neutron.
  A full list of these meetings and their date/time can be found in
  `OpenStack IRC Meetings <http://eavesdrop.openstack.org>`_.
  It is important to attend these meetings in the area of your contribution
  and possibly mention your work and patches.
* When you have questions regarding an idea or a specific patch of yours, it
  can be helpful to find a relevant person in IRC and speak with them about
  it.
  You can find a user's IRC nickname in their launchpad account.
* Being available on IRC is useful, since reviewers can contact
  you directly to quickly clarify a review issue. This speeds
  up the feedback loop.
* Each area of Neutron or sub-project of Neutron has a specific lieutenant
  in charge of it.
  You can most likely find these lieutenants on IRC, it is advised however to try
  and send public questions to the channel rather then to a specific person if possible.
  (This increase the chances of getting faster answers to your questions).
  A list of the areas and lieutenants nicknames can be found at
  :doc:`Core Reviewers <policies/neutron-teams>`.

Commit messages
~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing commit messages.
For more details see `Git commit message best practices <https://wiki.openstack.org/wiki/GitCommitMessages>`_.
This is the TL;DR version with the important points for committing to Neutron.


* One liners are bad, unless the change is trivial.
* Use ``UpgradeImpact`` when the change could cause issues during the upgrade
  from one version to the next.
* ``APIImpact`` should be used when the api-ref in neutron-lib must be updated
  to reflect the change, and only as a last resort. Rather, the ideal workflow
  includes submitting a corresponding neutron-lib api-ref change along with
  the implementation, thereby removing the need to use ``APIImpact``.
* Make sure the commit message doesn't have any spelling/grammar errors. This
  is the first thing reviewers read and they can be distracting enough to
  invite -1's.
* Describe what the change accomplishes. If it's a bug fix, explain how this
  code will fix the problem. If it's part of a feature implementation, explain
  what component of the feature the patch implements. Do not just describe the
  bug, that's what launchpad is for.
* Use the "Closes-Bug: #BUG-NUMBER" tag if the patch addresses a bug. Submitting
  a bugfix without a launchpad bug reference is unacceptable, even if it's
  trivial. Launchpad is how bugs are tracked so fixes without a launchpad bug are
  a nightmare when users report the bug from an older version and the Neutron team
  can't tell if/why/how it's been fixed. Launchpad is also how backports are
  identified and tracked so patches without a bug report cannot be picked to stable
  branches.
* Use the "Implements: blueprint NAME-OF-BLUEPRINT" or "Partially-Implements:
  blueprint NAME-OF-BLUEPRINT" for features so reviewers can determine if the
  code matches the spec that was agreed upon. This also updates the blueprint
  on launchpad so it's easy to see all patches that are related to a feature.
* If it's not immediately obvious, explain what the previous code was doing
  that was incorrect. (e.g. code assumed it would never get 'None' from
  a function call)
* Be specific in your commit message about what the patch does and why it does
  this. For example, "Fixes incorrect logic in security groups" is not helpful
  because the code diff already shows that you are modifying security groups.
  The message should be specific enough that a reviewer looking at the code can
  tell if the patch does what the commit says in the most appropriate manner.
  If the reviewer has to guess why you did something, lots of your time will be
  wasted explaining why certain changes were made.


Dealing with Zuul
~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when dealing with OpenStack CI.

* When you submit a patch, consider checking its `status <http://status.openstack.org/zuul/>`_
  in the queue. If you see a job failures, you might as well save time and try to figure out
  in advance why it is failing.
* Excessive use of 'recheck' to get test to pass is discouraged. Please examine the logs for
  the failing test(s) and make sure your change has not tickled anything that might be causing
  a new failure or race condition. Getting your change in could make it even harder to debug
  what is actually broken later on.
