# Copyright (c) 2014 OpenStack Foundation.
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

from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging

from neutron.db import hosts_db
from neutron.extensions import wrs_net

LOG = logging.getLogger(__name__)


class L3HostSchedulerDbMixin(hosts_db.HostSchedulerDbMixin):
    """This mixin provides extensions to common L3 mixin methods in order to
    add host management functionality to the router plugins.  For example,
    routers can be rescheduled when a host is taken in/out of service and if
    interfaces are added/removed from routers.
    """

    def _is_router_status_managed(self):
        if cfg.CONF.router_status_managed:
            return True
        return False

    def relocate_router(self, context, router_id, agent_id=None):
        """Move the router to a different agent if already scheduled"""
        l3_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_L3)
        if agent_id:
            result = self.list_routers_on_l3_agent(context, agent_id)
            routers = result.get('routers', [])
            if any([r['id'] == router_id for r in routers]):
                self.remove_router_from_l3_agent(context, agent_id, router_id)

        agent = self.schedule_router(context, router_id)
        if not agent:
            LOG.debug("Rescheduling of router {} "
                      "has failed".format(router_id))
            return
        if l3_notifier:
            l3_notifier.router_added_to_agent(
                context, [router_id], agent.host)

    def relocate_routers(self, context, agent_id):
        """Remove routers from given agent and attempt to reschedule to a
        different agent.  This function assumes that it whatever condition led
        to needing to relocate the routers away from the agent will also
        prevent it from rescheduling to that same agent; therefore all
        agent/host state changes must be persisted to the database before
        invoking this function.
        """
        result = self.list_routers_on_l3_agent(context, agent_id)
        routers = result.get('routers', [])
        for router in routers:
            LOG.debug("relocating router {} away from {}".format(
                    router['id'], agent_id))
            self.relocate_router(context, router['id'], agent_id)

    def update_router_scheduling(self, context, router_id):
        """Determine whether the router_id is scheduled and if it is determine
        whether the agent is still appropriate for the given router interface
        list.
        """
        try:
            agent_id = None
            agents = self._get_l3_agents_hosting_routers(context, [router_id])
            if agents:
                agent_id = agents[0].id
                # Determine if the current agent is still a valid choice
                router = self.get_router(context, router_id)
                candidates = self.get_l3_agent_candidates(context,
                                                          router,
                                                          agents)
                if candidates:
                    # The current selection is still valid
                    return
            self.relocate_router(context, router_id, agent_id)
        except Exception as e:
            LOG.exception(("Failed to update router scheduling, "
                           "exception={}").format(e))
            # continue anyway

    def _extend_router_status_dict(self, context, router):
        if not self._is_router_status_managed():
            return
        agents = self.get_l3_agents_hosting_routers(context, [router['id']])
        agent = agents[0] if len(agents) > 0 else None
        status = 'ACTIVE' if len(agents) > 0 else 'DOWN'
        router.update({wrs_net.HOST: agent.host if agent else None,
                       'status': status})

    def _update_router_gw_info(self, context, router_id, info, router=None):
        """
        Intercept the router gateway info update request to adjust scheduling
        of the router if necessary.
        """
        info = super(L3HostSchedulerDbMixin, self)._update_router_gw_info(
            context, router_id, info, router)
        # Schedule the router as the admin because it will be necessary to
        # query the gateway ports which are owned by the admin
        self.update_router_scheduling(context.elevated(), router_id)
        return info

    def add_router_interface(self, context, router_id, interface_info=None):
        """
        Intercept the router interface add request to adjust scheduling of the
        router if necessary.
        """
        info = super(L3HostSchedulerDbMixin, self).add_router_interface(
            context, router_id, interface_info)
        # Schedule the router as the admin because it will be necessary to
        # query the gateway ports which are owned by the admin
        self.update_router_scheduling(context.elevated(), router_id)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        """
        Intercept the router interface remove request to adjust scheduling of
        the router if necessary.
        """
        info = super(L3HostSchedulerDbMixin, self).remove_router_interface(
            context, router_id, interface_info)
        # Schedule the router as the admin because it will be necessary to
        # query the gateway ports which are owned by the admin
        self.update_router_scheduling(context.elevated(), router_id)
        return info

    def get_router(self, context, router_id, fields=None):
        """
        Intercept the router get request to extend it with the hostname of the
        agent that is currently hosting it.
        """
        session = context.session
        with session.begin(subtransactions=True):
            router = super(L3HostSchedulerDbMixin, self).get_router(
                context, router_id, None)
            self._extend_router_status_dict(context, router)
        return self._fields(router, fields)

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        """
        Intercept the router get request to extend it with the hostname of the
        agent that is currently hosting it.
        """
        session = context.session
        with session.begin(subtransactions=True):
            routers = super(L3HostSchedulerDbMixin, self).get_routers(
                context, filters, None, sorts, limit, marker, page_reverse)
            for router in routers:
                self._extend_router_status_dict(context, router)
        return [self._fields(router, fields) for router in routers]
