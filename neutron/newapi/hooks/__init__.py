# Copyright (c) 2015 Mirantis, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.newapi.hooks import attribute_population
from neutron.newapi.hooks import context
from neutron.newapi.hooks import ownership_validation
from neutron.newapi.hooks import policy_enforcement
from neutron.newapi.hooks import quota_enforcement
from neutron.newapi.hooks import resource_identifier
from neutron.newapi.hooks import translation


ExceptionTranslationHook = translation.ExceptionTranslationHook
ContextHook = context.ContextHook
ResourceIdentifierHook = resource_identifier.ResourceIdentifierHook
AttributePopulationHook = attribute_population.AttributePopulationHook
OwnershipValidationHook = ownership_validation.OwnershipValidationHook
PolicyHook = policy_enforcement.PolicyHook
QuotaEnforcementHook = quota_enforcement.QuotaEnforcementHook
