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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#

from neutron_lib.api.definitions import provider_net as provider
from neutron_lib import constants
from oslo_log import log as logging
from sqlalchemy import and_
from sqlalchemy import sql

from neutron.common import constants as n_const
from neutron.db import hosts_db
from neutron.db.models import agent as agent_model
from neutron.db.models import segment as segments_model
from neutron.db import models_v2
from neutron.db import providernet_db
from neutron.scheduler import dhcp_agent_scheduler

LOG = logging.getLogger(__name__)


class HostBasedScheduler(dhcp_agent_scheduler.AZAwareWeightScheduler):
    """
    Allocate a DHCP agent for a network based on the least loaded DHCP agent.

    This is a refinement of the default AZAwareWeightScheduler.  Its purpose
    is to block scheduling of networks onto hosts that are not yet available.
    """
    def __init__(self):
        super(HostBasedScheduler, self).__init__(HostDhcpFilter())

    def get_dhcp_subnets_for_host(self, plugin, context, host, fields):
        # NOTE(alegacy): the auto_schedule_networks method does not
        # constrain the search for networks to only those hosts that can
        # actually implement them.  The schedule network code on the other
        # hand at least tries to do this by checking the segment access of
        # all candidate hosts, but the host scheduling does not do the same.
        #  That ends up treating all agents as capable of handling all
        # networks which is not true.  To solve this we take advantage of
        # our host interface bindings to find those networks/subnets that
        # have a provider network binding to the specified host.
        query = (context.session.query(models_v2.Subnet)
                 .join(models_v2.Network,
                       models_v2.Network.id == models_v2.Subnet.network_id)
                 .join(segments_model.NetworkSegment,
                       segments_model.NetworkSegment.network_id ==
                       models_v2.Network.id)
                 .join(providernet_db.ProviderNet,
                       providernet_db.ProviderNet.name ==
                       segments_model.NetworkSegment.physical_network)
                 .join(hosts_db.HostInterfaceProviderNetBinding,
                       hosts_db.HostInterfaceProviderNetBinding
                       .providernet_id ==
                       providernet_db.ProviderNet.id)
                 .join(hosts_db.HostInterface,
                       and_(hosts_db.HostInterface.id ==
                            hosts_db.HostInterfaceProviderNetBinding
                            .interface_id,
                            hosts_db.HostInterface.network_type.
                            in_(hosts_db.DATA_NETWORK_TYPES)))
                 .join(hosts_db.Host,
                       hosts_db.Host.id == hosts_db.HostInterface.host_id)
                 .filter(hosts_db.Host.name == host)
                 .filter(models_v2.Subnet.enable_dhcp ==
                         sql.expression.true()))
        return [plugin._make_subnet_dict(s, fields=fields, context=context)
                for s in query.all()]

    def auto_schedule_networks(self, plugin, context, host):
        if not plugin.is_host_available(context, host):
            LOG.warning(('Host %s is not available'), host)
            return False
        return super(HostBasedScheduler, self).auto_schedule_networks(
            plugin, context, host)


class HostDhcpFilter(dhcp_agent_scheduler.DhcpFilter):

    def _get_active_agents(self, plugin, context, az_hints):
        """Return a list of active dhcp agents."""
        with context.session.begin(subtransactions=True):
            query = (context.session.query(agent_model.Agent)
                     .join(hosts_db.Host,
                           hosts_db.Host.name == agent_model.Agent.host)
                     .filter(agent_model.Agent.agent_type ==
                             constants.AGENT_TYPE_DHCP)
                     .filter(agent_model.Agent.admin_state_up ==
                             sql.expression.true())
                     .filter(hosts_db.Host.availability == n_const.HOST_UP))
            if az_hints:
                query = query.filter(agent_model.Agent.availability_zone ==
                                     az_hints)
            active_dhcp_agents = query.all()
            if not active_dhcp_agents:
                LOG.warning(('No more active DHCP agents on active hosts'))
                return []
        return active_dhcp_agents

    @staticmethod
    def _get_hosts_for_network(context, network):
        physical_network = network[provider.PHYSICAL_NETWORK]
        hosts = (context.session.query(hosts_db.Host)
                 .join(hosts_db.HostInterface,
                       and_((hosts_db.HostInterface.network_type.
                             in_(hosts_db.DATA_NETWORK_TYPES)),
                            (hosts_db.HostInterface.host_id ==
                             hosts_db.Host.id)))
                 .join(hosts_db.HostInterfaceProviderNetBinding,
                       (hosts_db.HostInterfaceProviderNetBinding.
                        interface_id == hosts_db.HostInterface.id))
                 .join(providernet_db.ProviderNet,
                       (providernet_db.ProviderNet.id ==
                        hosts_db.HostInterfaceProviderNetBinding.
                        providernet_id))
                 .filter(hosts_db.Host.availability == n_const.HOST_UP)
                 .filter(providernet_db.ProviderNet.name == physical_network))
        return [h.name for h in hosts.all()]

    def _filter_agents_with_network_access(self, plugin, context,
                                           network, hostable_agents):
        # NOTE(alegacy): the super class will filter the agent list down to
        # only those that have access to the network, but the mechanism by
        # which it does that relies on which mechanism driver reports that
        # it has access to that network segment.  It does not take in to
        # account that the mechanism driver may be SRIOV and may not be able
        # to hook up a DHCP agent port to that network.  In order to fix
        # that in a way that does not affect a tonne of upstream unit tests
        # we are going to deal with it in our own DHCP Filter subclass that
        # looks at the network type of each host interface binding to return
        # only those agents that are on a node that has a data interface
        # binding to the provider network which implements the specified
        # tenant network.
        if 'candidate_hosts' in network:
            hostable_dhcp_hosts = network['candidate_hosts']
        else:
            hostable_dhcp_hosts = self._get_hosts_for_network(
                context, network)
        reachable_agents = [agent for agent in hostable_agents
                            if agent['host'] in hostable_dhcp_hosts]
        return reachable_agents
