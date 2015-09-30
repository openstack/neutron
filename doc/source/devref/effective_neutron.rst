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

Database interaction
~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done during database development.

* `first() <http://docs.sqlalchemy.org/en/rel_1_0/orm/query.html#sqlalchemy.orm.query.Query.first>`_
  does not raise an exception.
* Do not get an object to delete it. If you can `delete() <http://docs.sqlalchemy.org/en/rel_1_0/orm/query.html#sqlalchemy.orm.query.Query.delete>`_
  on the query object. Read the warnings for more details about in-python cascades.
* ...

System development
~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when invoking system commands
and interacting with linux utils.

Eventlet concurrent model
~~~~~~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when using eventlet and monkey
patching.

Mocking and testing
~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing tests, any test.
For anything more elaborate, please visit the testing section.

* Preferring low level testing versus full path testing (e.g. not testing database
  via client calls). The former is to be favored in unit testing, whereas the latter
  is to be favored in functional testing.

Backward compatibility
~~~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when extending the RPC Interfaces.

Scalability issues
~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing code that needs to process
a lot of data.

Translation and logging
~~~~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when instrumenting your code.

Project interfaces
~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing code that is used
to interface with other projects, like Keystone or Nova.

Documenting your code
~~~~~~~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing docstrings.

Landing patches more rapidly
----------------------------

Nits and pedantic comments
~~~~~~~~~~~~~~~~~~~~~~~~~~

Document common nits and pedantic comments to watch out for.

* Make sure you spell correctly, the best you can, no-one wants rebase generators at
  the end of the release cycle!
* Being available on IRC is useful, since reviewers can contact directly to quickly
  clarify a review issue. This speeds up the feeback loop.
* The odd pep8 error may cause an entire CI run to be wasted. Consider running
  validation (pep8 and/or tests) before submitting your patch. If you keep forgetting
  consider installing a git `hook <https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks>`_
  so that Git will do it for you.

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

Commit messages
~~~~~~~~~~~~~~~

Document common pitfalls as well as good practices done when writing commit messages.
For more details see `Git commit message best practices <https://wiki.openstack.org/wiki/GitCommitMessages>`_.

* One liners are bad, unless the change is trivial.
* Remember to use DocImpact, APIImpact, UpgradeImpact appropriately.

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
