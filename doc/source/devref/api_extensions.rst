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


API Extensions
==============

API extensions is the standard way of introducing new functionality
to the Neutron project, it allows plugins to
determine if they wish to support the functionality or not.

Examples
--------

The easiest way to demonstrate how an API extension is written, is
by studying an existing API extension and explaining the different layers.

.. toctree::
   :maxdepth: 1

   security_group_api
