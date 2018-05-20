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

import datetime

from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
from sqlalchemy import sql
from sqlalchemy import and_, or_, func

from neutron.common import constants as n_const
from neutron.db import hosts_db
from neutron.db.models import agent as agent_model
from neutron.db.models import l3 as l3_model
from neutron.db.models import l3agent as l3agent_model
from neutron.db.models import segment as segment_model
from neutron.db import models_v2
from neutron.db import providernet_db as pnet_db
from neutron.scheduler import l3_agent_scheduler


LOG = logging.getLogger(__name__)


class HostBasedScheduler(l3_agent_scheduler.AZLeastRoutersScheduler):
    """
    Randomly allocate an L3 agent for a router.

    This is a refinement of the default ChanceScheduler.  Its purpose is to
    only schedule routers to hosts that are attached to the provider networks
    that are needed in order to correctly implement the router instance.
    """

    def _get_oldest_acceptable_hearbeat_timestamp(self):
        cutoff = timeutils.utcnow() - datetime.timedelta(
            seconds=cfg.CONF.agent_down_time)
        return cutoff

    def _get_routers_for_host(self, plugin, context, host):
        """Get the list of routers that can be scheduled to the specified
        host.  This function takes in to consideration the networks that the
        router is attached to and whether the host implements those provider
        networks.

        :param context: the context
        :param plugin: the core plugin
        :param host: the hostname of the target server
        :returns: the list of router ids that can be scheduled on to the
        specified host
        """
        # retrieve the host id
        data = plugin.get_host_by_name(context, host)
        host_id = data['id']
        # query the list of routers that are attached to networks, that are
        # implemented by provider networks that are associated to the
        # specific host.
        routers = (context.session.query(l3_model.Router.id)
                   .join(models_v2.Port,
                         or_(models_v2.Port.device_id ==
                             l3_model.Router.id,
                             models_v2.Port.id ==
                             l3_model.Router.gw_port_id))
                   .join(segment_model.NetworkSegment,
                         (segment_model.NetworkSegment.network_id ==
                          models_v2.Port.network_id))
                   .join(pnet_db.ProviderNet,
                         (pnet_db.ProviderNet.name ==
                          segment_model.NetworkSegment.physical_network))
                   .outerjoin(hosts_db.HostInterfaceProviderNetBinding,
                              (hosts_db.HostInterfaceProviderNetBinding
                               .providernet_id ==
                               pnet_db.ProviderNet.id))
                   .join(hosts_db.HostInterface,
                         (hosts_db.HostInterface.id ==
                          hosts_db.HostInterfaceProviderNetBinding.
                          interface_id))
                   .filter(hosts_db.HostInterface.host_id == host_id)
                   .filter(hosts_db.HostInterface.network_type.
                           in_(hosts_db.DATA_NETWORK_TYPES))
                   .outerjoin(l3agent_model.RouterL3AgentBinding,
                              (l3agent_model.RouterL3AgentBinding
                               .router_id == l3_model.Router.id)))
        # Group by unique router-id values but exclude any that have a port
        # without a provider network binding on the specified host
        routers = (routers
                   .group_by(l3_model.Router.id)
                   .having(func.count(models_v2.Port.id) ==
                           func.count(hosts_db.HostInterfaceProviderNetBinding.
                                      providernet_id)))
        return [entry[0] for entry in routers.all()]

    def _get_routers_can_schedule(self, plugin, context, routers, l3_agent):
        """Filter the list of routers to remove those that are not supported
        by the specified host.
        """
        host = l3_agent['host']
        router_ids = self._get_routers_for_host(plugin, context, host)
        target_routers = [r for r in routers if r['id'] in router_ids]
        # Continue to the parent class and let it further refine the list of
        # target routers.
        return super(HostBasedScheduler, self)._get_routers_can_schedule(
            plugin, context, target_routers, l3_agent)

    def _get_l3_agents_for_router(self, plugin, context, router_id,
                                  agent_id=None):
        """Query the list of agents that can support scheduling the specified
        router.  To be considered as capable of scheduling the specified
        router the list of networks that the router is attached to is used to
        filter out agents on hosts that do not implement the the provider
        networks that implement those networks.

        :param context: the context
        :param plugin: the core plugin
        :param router_id: the router to be scheduled
        :param agent_id: only consider one agent
        :returns: the list of agents that can service the router
        """
        # Count the number of networks that this router is attached to.
        networks = (context.session.query(models_v2.Port.network_id)
                    .select_from(l3_model.Router)
                    .join(models_v2.Port,
                          or_(models_v2.Port.device_id ==
                              l3_model.Router.id,
                              models_v2.Port.id ==
                              l3_model.Router.gw_port_id))
                    .filter(l3_model.Router.id == router_id)
                    .distinct(models_v2.Port.network_id))
        count = networks.count()
        if not count:
            LOG.debug("router {} has no network attachments".format(router_id))
            return []
        # Find agents that are connected to the same set of networks as the
        # specified router.
        alive_cutoff = self._get_oldest_acceptable_hearbeat_timestamp()
        agents = (context.session.query(agent_model.Agent)
                  .join(hosts_db.Host,
                        and_((hosts_db.Host.name == agent_model.Agent.host),
                             (hosts_db.Host.availability ==
                              n_const.HOST_UP)))
                  .join(hosts_db.HostInterface,
                        and_((hosts_db.HostInterface.network_type.
                              in_(hosts_db.DATA_NETWORK_TYPES)),
                             (hosts_db.HostInterface.host_id ==
                              hosts_db.Host.id)))
                  .join(hosts_db.HostInterfaceProviderNetBinding,
                        (hosts_db.HostInterfaceProviderNetBinding.
                         interface_id == hosts_db.HostInterface.id))
                  .join(pnet_db.ProviderNet,
                        (pnet_db.ProviderNet.id ==
                         hosts_db.HostInterfaceProviderNetBinding.
                         providernet_id))
                  .join(segment_model.NetworkSegment,
                        (segment_model.NetworkSegment.physical_network ==
                         pnet_db.ProviderNet.name))
                  .filter(segment_model.NetworkSegment
                          .network_id.in_(networks.subquery()))
                  .filter(agent_model.Agent
                          .agent_type == constants.AGENT_TYPE_L3)
                  .filter(agent_model.Agent
                          .admin_state_up == sql.expression.true())
                  .filter(agent_model.Agent.heartbeat_timestamp > alive_cutoff)
                  )

        if agent_id:
            # Consider only the specified agent
            agents = agents.filter(agent_model.Agent.id == agent_id)

        # Group by agents and check that the agent has the same network
        # attachments as is required by the router
        agents = (agents
                  .group_by(agent_model.Agent)
                  .having(func.count(segment_model.NetworkSegment.network_id)
                          == count))
        return agents.all()

    def get_l3_agents_for_router(self, plugin, context, router_id):
        """See _get_l3_agents_for_router for a function description.
        """
        return self._get_l3_agents_for_router(
            plugin, context, router_id, agent_id=None)

    def can_l3_agent_host_router(self, plugin, context, agent_id, router_id):
        """Return true if the agent specified can host the router.  For this
        we reuse the get_l3_agents_for_router() function and filter the list
        down to only this one agent_id.  If a non-empty list is returned then
        the agent and router are compatible.

        :returns: True if given L3 agent can host the given router id
        """
        return bool(self._get_l3_agents_for_router(
                    plugin, context, router_id, agent_id=agent_id))

    def auto_schedule_routers(self, plugin, context, host, router_ids,
                              exclude_distributed=False):
        """Schedule non-hosted routers to L3 Agent running on host.

        If router_ids is given, each router in router_ids is scheduled
        if it is not scheduled yet. Otherwise all unscheduled routers
        are scheduled.
        Do not schedule the routers which are hosted already
        by active l3 agents.

        :returns: True if routers have been successfully assigned to host
        """
        if not plugin.is_host_available(context, host):
            LOG.warning(('Host %s is not available'), host)
            return
        super(HostBasedScheduler, self).auto_schedule_routers(
            plugin, context, host, router_ids, exclude_distributed)
