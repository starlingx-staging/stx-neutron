# Copyright (c) 2013 OpenStack Foundation.
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
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#


import datetime
import random
import time

from neutron_lib import constants
from neutron_lib import context as ncontext
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import timeutils
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron._i18n import _
from neutron.agent.common import utils as agent_utils
from neutron.common import constants as n_const
from neutron.common import utils
from neutron.db import agents_db
from neutron.db.availability_zone import network as network_az
from neutron.db.models import agent as agent_model
from neutron.db import models_v2
from neutron.db.network_dhcp_agent_binding import models as ndab_model
from neutron.extensions import agent as ext_agent
from neutron.extensions import dhcpagentscheduler
from neutron.extensions import wrs_net
from neutron import worker as neutron_worker


LOG = logging.getLogger(__name__)

AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('network_scheduler_driver',
               default='neutron.scheduler.'
                       'dhcp_agent_scheduler.WeightScheduler',
               help=_('Driver to use for scheduling network to DHCP agent')),
    cfg.IntOpt('network_reschedule_threshold',
               default=1,
               help=_('Threshold that when current network distribution has '
                      'one DHCP agent with this many more networks than '
                      'another DHCP agent, then rescheduling is needed')),
    cfg.BoolOpt('network_auto_schedule', default=True,
                help=_('Allow auto scheduling networks to DHCP agent.')),
    cfg.BoolOpt('allow_automatic_dhcp_failover', default=True,
                help=_('Automatically remove networks from offline DHCP '
                       'agents.')),
    cfg.IntOpt('dhcp_agents_per_network', default=1,
               help=_('Number of DHCP agents scheduled to host a tenant '
                      'network. If this number is greater than 1, the '
                      'scheduler automatically assigns multiple DHCP agents '
                      'for a given tenant network, providing high '
                      'availability for DHCP service.')),
    cfg.BoolOpt('enable_services_on_agents_with_admin_state_down',
                default=False,
                help=_('Enable services on an agent with admin_state_up '
                       'False. If this option is False, when admin_state_up '
                       'of an agent is turned False, services on it will be '
                       'disabled. Agents with admin_state_up False are not '
                       'selected for automatic scheduling regardless of this '
                       'option. But manual scheduling to such agents is '
                       'available if this option is True.')),
]

cfg.CONF.register_opts(AGENTS_SCHEDULER_OPTS)


class AgentSchedulerDbMixin(agents_db.AgentDbMixin):
    """Common class for agent scheduler mixins."""

    # agent notifiers to handle agent update operations;
    # should be updated by plugins;
    agent_notifiers = {
        constants.AGENT_TYPE_DHCP: None,
        constants.AGENT_TYPE_L3: None,
        constants.AGENT_TYPE_LOADBALANCER: None,
    }

    @staticmethod
    def is_eligible_agent(active, agent):
        if active is None:
            # filtering by activeness is disabled, all agents are eligible
            return True
        else:
            # note(rpodolyaka): original behaviour is saved here: if active
            #                   filter is set, only agents which are 'up'
            #                   (i.e. have a recent heartbeat timestamp)
            #                   are eligible, even if active is False
            return not agent_utils.is_agent_down(
                agent['heartbeat_timestamp'])

    def update_agent(self, context, id, agent):
        original_agent = self.get_agent(context, id)
        result = super(AgentSchedulerDbMixin, self).update_agent(
            context, id, agent)
        agent_data = agent['agent']
        agent_notifier = self.agent_notifiers.get(original_agent['agent_type'])
        if (agent_notifier and
            'admin_state_up' in agent_data and
            original_agent['admin_state_up'] != agent_data['admin_state_up']):
            agent_notifier.agent_updated(context,
                                         agent_data['admin_state_up'],
                                         original_agent['host'])
        return result

    def add_agent_status_check_worker(self, function):
        # TODO(enikanorov): make interval configurable rather than computed
        interval = max(cfg.CONF.agent_down_time // 2, 1)
        # add random initial delay to allow agents to check in after the
        # neutron server first starts. random to offset multiple servers
        initial_delay = random.randint(interval, interval * 2)

        check_worker = neutron_worker.PeriodicWorker(function, interval,
                                                     initial_delay)
        self.add_worker(check_worker)

    def agent_dead_limit_seconds(self):
        return cfg.CONF.agent_down_time * 2

    def wait_down_agents(self, agent_type, agent_dead_limit):
        """Gives chance for agents to send a heartbeat."""
        # check for an abrupt clock change since last check. if a change is
        # detected, sleep for a while to let the agents check in.
        tdelta = timeutils.utcnow() - getattr(self, '_clock_jump_canary',
                                              timeutils.utcnow())
        if tdelta.total_seconds() > cfg.CONF.agent_down_time:
            LOG.warning("Time since last %s agent reschedule check has "
                        "exceeded the interval between checks. Waiting "
                        "before check to allow agents to send a heartbeat "
                        "in case there was a clock adjustment.",
                        agent_type)
            time.sleep(agent_dead_limit)
        self._clock_jump_canary = timeutils.utcnow()

    def get_cutoff_time(self, agent_dead_limit):
        cutoff = timeutils.utcnow() - datetime.timedelta(
            seconds=agent_dead_limit)
        return cutoff

    def reschedule_resources_from_down_agents(self, agent_type,
                                              get_down_bindings,
                                              agent_id_attr,
                                              resource_id_attr,
                                              resource_name,
                                              reschedule_resource,
                                              rescheduling_failed):
        """Reschedule resources from down neutron agents
        if admin state is up.
        """
        agent_dead_limit = self.agent_dead_limit_seconds()
        self.wait_down_agents(agent_type, agent_dead_limit)

        context = ncontext.get_admin_context()
        try:
            down_bindings = get_down_bindings(context, agent_dead_limit)

            agents_back_online = set()
            for binding in down_bindings:
                binding_agent_id = getattr(binding, agent_id_attr)
                binding_resource_id = getattr(binding, resource_id_attr)
                if binding_agent_id in agents_back_online:
                    continue
                else:
                    # we need new context to make sure we use different DB
                    # transaction - otherwise we may fetch same agent record
                    # each time due to REPEATABLE_READ isolation level
                    context = ncontext.get_admin_context()
                    agent = self._get_agent(context, binding_agent_id)
                    if agent.is_active:
                        agents_back_online.add(binding_agent_id)
                        continue

                LOG.warning(
                    "Rescheduling %(resource_name)s %(resource)s from agent "
                    "%(agent)s because the agent did not report to the server "
                    "in the last %(dead_time)s seconds.",
                    {'resource_name': resource_name,
                     'resource': binding_resource_id,
                     'agent': binding_agent_id,
                     'dead_time': agent_dead_limit})
                try:
                    reschedule_resource(context, binding_resource_id)
                except (rescheduling_failed, oslo_messaging.RemoteError):
                    # Catch individual rescheduling errors here
                    # so one broken one doesn't stop the iteration.
                    LOG.exception("Failed to reschedule %(resource_name)s "
                                  "%(resource)s",
                                  {'resource_name': resource_name,
                                   'resource': binding_resource_id})
        except Exception:
            # we want to be thorough and catch whatever is raised
            # to avoid loop abortion
            LOG.exception("Exception encountered during %(resource_name)s "
                          "rescheduling.",
                          {'resource_name': resource_name})


class DhcpAgentSchedulerDbMixin(dhcpagentscheduler
                                .DhcpAgentSchedulerPluginBase,
                                AgentSchedulerDbMixin):
    """Mixin class to add DHCP agent scheduler extension to db_base_plugin_v2.
    """

    network_scheduler = None

    def add_periodic_dhcp_agent_status_check(self):
        if not cfg.CONF.allow_automatic_dhcp_failover:
            LOG.info("Skipping periodic DHCP agent status check because "
                     "automatic network rescheduling is disabled.")
            return

        self.add_agent_status_check_worker(
            self.remove_networks_from_down_agents
        )

    def is_eligible_agent(self, context, active, agent):
        # eligible agent is active or starting up
        return (AgentSchedulerDbMixin.is_eligible_agent(active, agent) or
                self.agent_starting_up(context, agent))

    def agent_starting_up(self, context, agent):
        """Check if agent was just started.

        Method returns True if agent is in its 'starting up' period.
        Return value depends on amount of networks assigned to the agent.
        It doesn't look at latest heartbeat timestamp as it is assumed
        that this method is called for agents that are considered dead.
        """
        agent_dead_limit = datetime.timedelta(
            seconds=self.agent_dead_limit_seconds())
        network_count = (context.session.query(ndab_model.
                                               NetworkDhcpAgentBinding).
                         filter_by(dhcp_agent_id=agent['id']).count())
        # amount of networks assigned to agent affect amount of time we give
        # it so startup. Tests show that it's more or less sage to assume
        # that DHCP agent processes each network in less than 2 seconds.
        # So, give it this additional time for each of the networks.
        additional_time = datetime.timedelta(seconds=2 * network_count)
        LOG.debug("Checking if agent starts up and giving it additional %s",
                  additional_time)
        agent_expected_up = (agent['started_at'] + agent_dead_limit +
                             additional_time)
        return agent_expected_up > timeutils.utcnow()

    def _schedule_network(self, context, network_id, dhcp_notifier):
        LOG.info("Scheduling unhosted network %s", network_id)
        try:
            # TODO(enikanorov): have to issue redundant db query
            # to satisfy scheduling interface
            network = self.get_network(context, network_id)
            agents = self.schedule_network(context, network)
            if not agents:
                LOG.info("Failed to schedule network %s, "
                         "no eligible agents or it might be "
                         "already scheduled by another server",
                         network_id)
                return
            if not dhcp_notifier:
                return
            for agent in agents:
                LOG.info("Adding network %(net)s to agent "
                         "%(agent)s on host %(host)s",
                         {'net': network_id,
                          'agent': agent.id,
                          'host': agent.host})
                dhcp_notifier.network_added_to_agent(
                    context, network_id, agent.host)
        except Exception:
            # catching any exception during scheduling
            # so if _schedule_network is invoked in the loop it could
            # continue in any case
            LOG.exception("Failed to schedule network %s", network_id)

    def _filter_bindings(self, context, bindings):
        """Skip bindings for which the agent is dead, but starting up."""

        # to save few db calls: store already checked agents in dict
        # id -> is_agent_starting_up
        checked_agents = {}
        for binding in bindings:
            try:
                agent_id = binding.dhcp_agent['id']
                if agent_id not in checked_agents:
                    if self.agent_starting_up(context, binding.dhcp_agent):
                        # When agent starts and it has many networks to process
                        # it may fail to send state reports in defined interval
                        # The server will consider it dead and try to remove
                        # networks from it.
                        checked_agents[agent_id] = True
                        LOG.debug("Agent %s is starting up, skipping",
                                  agent_id)
                    else:
                        checked_agents[agent_id] = False
                if not checked_agents[agent_id]:
                    yield binding
            except exc.ObjectDeletedError:
                # we're not within a transaction, so object can be lost
                # because underlying row is removed, just ignore this issue
                LOG.debug("binding was removed concurrently, skipping it")

    def remove_networks_from_down_agents(self):
        """Remove networks from down DHCP agents if admin state is up.

        Reschedule them if configured so.
        """

        agent_dead_limit = self.agent_dead_limit_seconds()
        self.wait_down_agents('DHCP', agent_dead_limit)
        cutoff = self.get_cutoff_time(agent_dead_limit)

        context = ncontext.get_admin_context()
        try:
            down_bindings = (
                context.session.query(ndab_model.NetworkDhcpAgentBinding).
                join(agent_model.Agent).
                filter(agent_model.Agent.heartbeat_timestamp < cutoff,
                       agent_model.Agent.admin_state_up))
            dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
            dead_bindings = [b for b in
                             self._filter_bindings(context, down_bindings)]
            agents = self.get_agents_db(
                context, {'agent_type': [constants.AGENT_TYPE_DHCP]})
            if not agents:
                # No agents configured so nothing to do.
                return
            active_agents = [agent for agent in agents if
                             self.is_eligible_agent(context, True, agent)]
            if not active_agents:
                LOG.warning("No DHCP agents available, "
                            "skipping rescheduling")
                return
            for binding in dead_bindings:
                LOG.warning("Removing network %(network)s from agent "
                            "%(agent)s because the agent did not report "
                            "to the server in the last %(dead_time)s "
                            "seconds.",
                            {'network': binding.network_id,
                             'agent': binding.dhcp_agent_id,
                             'dead_time': agent_dead_limit})
                # save binding object to avoid ObjectDeletedError
                # in case binding is concurrently deleted from the DB
                saved_binding = {'net': binding.network_id,
                                 'agent': binding.dhcp_agent_id}
                try:
                    # do not notify agent if it considered dead
                    # so when it is restarted it won't see network delete
                    # notifications on its queue
                    self.remove_network_from_dhcp_agent(context,
                                                        binding.dhcp_agent_id,
                                                        binding.network_id,
                                                        notify=False)
                except dhcpagentscheduler.NetworkNotHostedByDhcpAgent:
                    # measures against concurrent operation
                    LOG.debug("Network %(net)s already removed from DHCP "
                              "agent %(agent)s",
                              saved_binding)
                    # still continue and allow concurrent scheduling attempt
                except Exception:
                    LOG.exception("Unexpected exception occurred while "
                                  "removing network %(net)s from agent "
                                  "%(agent)s",
                                  saved_binding)

                if cfg.CONF.network_auto_schedule:
                    self._schedule_network(
                        context, saved_binding['net'], dhcp_notifier)
        except Exception:
            # we want to be thorough and catch whatever is raised
            # to avoid loop abortion
            LOG.exception("Exception encountered during network "
                          "rescheduling")

    def get_dhcp_agents_hosting_networks(
            self, context, network_ids, active=None, admin_state_up=None,
            hosts=None):
        if not network_ids:
            return []
        query = context.session.query(ndab_model.NetworkDhcpAgentBinding)
        query = query.options(orm.contains_eager(
                              ndab_model.NetworkDhcpAgentBinding.dhcp_agent))
        query = query.join(ndab_model.NetworkDhcpAgentBinding.dhcp_agent)
        if network_ids:
            query = query.filter(
                ndab_model.NetworkDhcpAgentBinding.network_id.in_(network_ids))
        if hosts:
            query = query.filter(agent_model.Agent.host.in_(hosts))
        if admin_state_up is not None:
            query = query.filter(agent_model.Agent.admin_state_up ==
                                 admin_state_up)

        return [binding.dhcp_agent
                for binding in query
                if self.is_eligible_agent(context, active,
                                          binding.dhcp_agent)]

    def add_network_to_dhcp_agent(self, context, id, network_id):
        self._get_network(context, network_id)
        with context.session.begin(subtransactions=True):
            agent_db = self._get_agent(context, id)
            if (agent_db['agent_type'] != constants.AGENT_TYPE_DHCP or
                    not services_available(agent_db['admin_state_up'])):
                raise dhcpagentscheduler.InvalidDHCPAgent(id=id)
            dhcp_agents = self.get_dhcp_agents_hosting_networks(
                context, [network_id])
            for dhcp_agent in dhcp_agents:
                if id == dhcp_agent.id:
                    raise dhcpagentscheduler.NetworkHostedByDHCPAgent(
                        network_id=network_id, agent_id=id)
            binding = ndab_model.NetworkDhcpAgentBinding()
            binding.dhcp_agent_id = id
            binding.network_id = network_id
            context.session.add(binding)
        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        if dhcp_notifier:
            dhcp_notifier.network_added_to_agent(
                context, network_id, agent_db.host)

    def remove_network_from_dhcp_agent(self, context, id, network_id,
                                       notify=True):
        agent = self._get_agent(context, id)
        try:
            query = context.session.query(ndab_model.NetworkDhcpAgentBinding)
            binding = query.filter(
                ndab_model.NetworkDhcpAgentBinding.network_id == network_id,
                ndab_model.NetworkDhcpAgentBinding.dhcp_agent_id == id).one()
        except exc.NoResultFound:
            raise dhcpagentscheduler.NetworkNotHostedByDhcpAgent(
                network_id=network_id, agent_id=id)

        # reserve the port, so the ip is reused on a subsequent add
        device_id = utils.get_dhcp_agent_device_id(network_id,
                                                   agent['host'])
        filters = dict(network_id=[network_id],
                       device_owner=[constants.DEVICE_OWNER_DHCP])
        ports = self.get_ports(context, filters=filters)
        # NOTE(kevinbenton): there should only ever be one port per
        # DHCP agent per network so we don't have to worry about one
        # update_port passing and another failing
        for port in ports:
            if port['device_id'].startswith(device_id):
                port['device_id'] = n_const.DEVICE_ID_RESERVED_DHCP_PORT
                try:
                    self.update_port(context, port['id'], dict(port=port))
                except n_exc.PortNotFound:
                    LOG.warning("Port %(port)s deleted concurrently "
                                "by agent",
                                {'port': port['id']})
        with context.session.begin():
            context.session.delete(binding)
        LOG.warning("Unbinding network %(network)s from agent %(agent)s",
                    {'network': network_id, 'agent': id})

        if not notify:
            return
        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        if dhcp_notifier:
            dhcp_notifier.network_removed_from_agent(
                context, network_id, agent['host'])

    def list_networks_on_dhcp_agent(self, context, id):
        query = context.session.query(
            ndab_model.NetworkDhcpAgentBinding.network_id)
        query = query.filter(
            ndab_model.NetworkDhcpAgentBinding.dhcp_agent_id == id)

        net_ids = [item[0] for item in query]
        if net_ids:
            return {'networks':
                    self.get_networks(context, filters={'id': net_ids})}
        else:
            # Exception will be thrown if the requested agent does not exist.
            self._get_agent(context, id)
            return {'networks': []}

    def list_active_networks_on_active_dhcp_agent(self, context, host):
        try:
            agent = self._get_agent_by_type_and_host(
                context, constants.AGENT_TYPE_DHCP, host)
        except ext_agent.AgentNotFoundByTypeHost:
            LOG.debug("DHCP Agent not found on host %s", host)
            return []

        if not services_available(agent.admin_state_up):
            return []
        query = context.session.query(
            ndab_model.NetworkDhcpAgentBinding.network_id)
        query = query.filter(
            ndab_model.NetworkDhcpAgentBinding.dhcp_agent_id == agent.id)

        net_ids = [item[0] for item in query]
        if net_ids:
            return self.get_networks(
                context,
                filters={'id': net_ids, 'admin_state_up': [True]}
            )
        else:
            return []

    def list_dhcp_agents_hosting_network(self, context, network_id):
        dhcp_agents = self.get_dhcp_agents_hosting_networks(
            context, [network_id])
        agent_ids = [dhcp_agent.id for dhcp_agent in dhcp_agents]
        if agent_ids:
            return {
                'agents': self.get_agents(context, filters={'id': agent_ids})}
        else:
            return {'agents': []}

    @utils.synchronized('schedule-networks', external=True)
    def schedule_network(self, context, created_network):
        if self.network_scheduler:
            return self.network_scheduler.schedule(
                self, context, created_network)

    @utils.synchronized('auto-schedule-networks', external=True)
    def auto_schedule_networks(self, context, host):
        if self.network_scheduler:
            self.network_scheduler.auto_schedule_networks(self, context, host)

    def _relocate_network(self, context, agent_id, network):
        LOG.debug("relocating network {}".format(network['id']))
        try:
            self.remove_network_from_dhcp_agent(context,
                                                agent_id,
                                                network['id'])
        except dhcpagentscheduler.NetworkNotHostedByDhcpAgent:
            # measures against concurrent operation
            LOG.warning("Network %(net)s already removed from DHCP "
                        "agent %(agent)s",
                        {"net": network['id'],
                         "agent": agent_id})
            return []

        agents = self.schedule_network(context, network)
        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        if not agents:
            LOG.warning(("Relocation of network {} has failed").format(
                network['id']))
            return []
        elif dhcp_notifier:
            for agent in agents:
                dhcp_notifier.network_added_to_agent(
                    context, network['id'], agent['host'])
        return agents

    def relocate_networks(self, context, agent):
        """Remove networks from given agent and attempt to reschedule to a
        different agent.  This function assumes that it whatever condition led
        to needing to relocate the networks away from the agent will also
        prevent it from rescheduling to that same agent; therefore all
        agent/host state changes must be persisted to the database before
        invoking this function.
        """
        agent_id = agent['id']
        result = self.list_networks_on_dhcp_agent(context, agent_id)
        networks = result.get('networks')

        device_id = utils.get_dhcp_agent_device_id("%", agent['host'])
        with context.session.begin():
            # Reserve all the DHCP ports for networks on this agent,
            # so that the ips are reused on subsequent adds.
            query = context.session.query(models_v2.Port)
            query = query.filter(
                models_v2.Port.device_id.like(device_id)
            )
            query.update({'device_id': n_const.DEVICE_ID_RESERVED_DHCP_PORT},
                         synchronize_session=False)

            # Delete all the dhcp network bindings for this agent.
            query = context.session.query(ndab_model.NetworkDhcpAgentBinding)
            query = query.filter(
                ndab_model.NetworkDhcpAgentBinding.dhcp_agent_id == agent_id
            )
            query.delete(synchronize_session=False)

        # Iterate through networks on the agent, notifying the guest that each
        # network is removed, and then reschedule the network to a new agent.
        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        for network in networks:
            network_id = network['id']
            if dhcp_notifier:
                dhcp_notifier.network_removed_from_agent(
                    context, network_id, agent['host'])
            new_agents = self.schedule_network(context, network)
            if not new_agents:
                LOG.warning(("Relocation of network {} has failed").format(
                    network_id))
                continue
            elif dhcp_notifier:
                for new_agent in new_agents:
                    dhcp_notifier.network_added_to_agent(
                        context, network_id, new_agent['host'])

    def _can_dhcp_agent_host_network(self, context, agent, network_id):
        """Return true if the agent specified can host the network.

        :returns: True if given DHCP agent can host the given network id
        """
        if not self.is_host_available(context, agent['host']):
            return False

        candidate_hosts = self.filter_hosts_with_network_access(
            context, network_id, [agent['host']])
        return bool(candidate_hosts)

    def _count_net_vlan_segments(self, networks):
        count = 0
        for network in networks:
            count += network['dhcp_vlan_segments']
        return count

    def redistribute_networks(self, context,
                              _meets_network_rescheduling_threshold):
        """Redistribute to a more optimal network distribution"""
        # Don't reschedule if more than one DHCP agent per DHCP server
        if cfg.CONF.dhcp_agents_per_network > 1:
            LOG.warning("DHCP agent redistribution disabled because "
                        "dhcp_agents_per_network is greater than 1")
            return
        start_time = time.time()
        filters = {'agent_type': [constants.AGENT_TYPE_DHCP]}
        agents = self.get_agents(context, filters)
        networks_on_agents = []
        rescheduled_networks = []
        network_vlans = {}

        # Count vlan segments on networks
        subnet_filters = {"enable_dhcp": [True]}
        for subnet in self.get_subnets(context, filters=subnet_filters):
            network_id = subnet['network_id']
            vlan_id = subnet.get(wrs_net.VLAN, 0)
            if network_id not in network_vlans:
                network_vlans[network_id] = set()
            network_vlans[network_id].add(vlan_id)
        # Create a list of tuples (agent_id, [network_id_0, ..., network_id_n])
        for agent in agents:
            result = self.list_networks_on_dhcp_agent(context, agent['id'])
            for network in result['networks']:
                network_id = network['id']
                vlan_segments = len(network_vlans.get(network_id, []))
                network['dhcp_vlan_segments'] = vlan_segments
            networks_on_agents.append((agent, result))
        db_completion_time = time.time()

        found_match = None
        # Loop through agents to try redistributing on all but the last agent
        while len(networks_on_agents) > 1 or found_match:
            # Sort by number of networks during first run,
            # and re-sort the list if any networks are relocated
            networks_on_agents.sort(
                key=(lambda x: self._count_net_vlan_segments(x[1]['networks']))
            )

            # If arriving here either during first run, or after going through
            # without any relocations, then pop the agent with most networks,
            # and try redistributing its networks.
            if not found_match:
                busiest_agent_networks = networks_on_agents.pop()
            found_match = None
            networks_on_busiest_agent = self._count_net_vlan_segments(
                busiest_agent_networks[1]['networks']
            )

            # Iterate through list of DHCP agents sorted in ascending order
            # by the number of networks they are hosting
            for agent_networks in networks_on_agents:
                minimum_networks = self._count_net_vlan_segments(
                    agent_networks[1]['networks']
                )
                # Stop trying to reschedule from the busiest agent, if there is
                # no possibility to reschedule to the agent of the current
                # iteration. Because the list of agents is sorted by number
                # of networks, if the agent of the current iteration doesn't
                # meet the rescheduling threshold from the busiest agent, then
                # no agent will.
                if not _meets_network_rescheduling_threshold(
                        networks_on_busiest_agent, minimum_networks):
                    break

                # Sort based on number of vlan segments, so that network with
                # most vlan segments is rescheduled first.
                busiest_agent_networks[1]['networks'].sort(
                    key=(lambda x: self._count_net_vlan_segments([x])),
                    reverse=True
                )

                # Loop through networks on busiest agent, and see if it can be
                # rescheduled to the agent of the current iteration.  This is
                # only to check if rescheduling is possible; if it can be
                # rescheduled, then it will still use the default scheduler to
                # schedule it.
                for network in busiest_agent_networks[1]['networks']:
                    # Reschedule network at most once per run. This will
                    # minimize the downtime of the network's DHCP service,
                    # as well as linearly bound the number of relocations.
                    if network['id'] in rescheduled_networks:
                        continue

                    # In the case of multiple vlans on network, check that it
                    # still meets the rescheduling threshold
                    vlan_subnets = self._count_net_vlan_segments([network])
                    if not _meets_network_rescheduling_threshold(
                        networks_on_busiest_agent - vlan_subnets + 1,
                        minimum_networks):
                        continue

                    if self._can_dhcp_agent_host_network(context,
                                                         agent_networks[0],
                                                         network['id']):
                        rescheduled_networks.append(network['id'])
                        new_agents = self._relocate_network(
                            context, busiest_agent_networks[0]['id'], network
                        )
                        for new_agent in new_agents:
                            for networks_on_agent in networks_on_agents:
                                agent = networks_on_agent[0]
                                if agent['host'] == new_agent['host']:
                                    networks_on_agent[1]['networks'].append(
                                        network
                                    )
                        found_match = network
                        break
                if found_match:
                    busiest_agent_networks[1]['networks'].remove(found_match)
                    break
        end_time = time.time()

        LOG.warning("redistribute_networks took %(total_time)d seconds to "
                    "relocate %(count)d networks including "
                    "%(db_access_time)d seconds accessing DB",
                    {'total_time': (end_time - start_time),
                     'count': len(rescheduled_networks),
                     'db_access_time': (db_completion_time - start_time)})


class AZDhcpAgentSchedulerDbMixin(DhcpAgentSchedulerDbMixin,
                                  network_az.NetworkAvailabilityZoneMixin):
    """Mixin class to add availability_zone supported DHCP agent scheduler."""

    def get_network_availability_zones(self, network):
        zones = {agent.availability_zone for agent in network.dhcp_agents}
        return list(zones)


# helper functions for readability.
def services_available(admin_state_up):
    if cfg.CONF.enable_services_on_agents_with_admin_state_down:
        # Services are available regardless admin_state_up
        return True
    return admin_state_up


def get_admin_state_up_filter():
    if cfg.CONF.enable_services_on_agents_with_admin_state_down:
        # Avoid filtering on admin_state_up at all
        return None
    # Filters on admin_state_up is True
    return True
