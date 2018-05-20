# Copyright (c) 2013-2014 OpenStack Foundation
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

#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#

import six

from neutron_lib import exceptions as exc
from oslo_log import log as logging

from neutron.db import api as db_api
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import type_flat
from neutron.plugins.wrs.drivers import type_generic

LOG = logging.getLogger(__name__)


class ManagedFlatTypeDriver(type_flat.FlatTypeDriver,
                            type_generic.GenericProvidernetTypeDriverMixin):

    def __init__(self):
        super(ManagedFlatTypeDriver, self).__init__()

    def get_mtu(self, physical_network):
        session = db_api.get_current_session()
        providernet = self._get_providernet(session, physical_network)
        return providernet.mtu

    def _parse_networks(self, entries):
        # Noop this method so that the parent class initializer does not
        # update the physical networks
        self.flat_networks = []

    def validate_provider_segment(self, segment, context=None):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if not physical_network:
            msg = ("physical_network required for flat provider network")
            raise exc.InvalidInput(error_message=msg)
        if not self._providernet_exists(context, physical_network):
            msg = (("physical_network '%s' unknown for flat provider network")
                   % physical_network)
            raise exc.InvalidInput(error_message=msg)

        for key, value in six.iteritems(segment):
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK]:
                msg = ("%s prohibited for flat provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def initialize(self):
        LOG.info(("ML2 ManagedFlatTypeDriver initialization complete"))
