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

# Copyright (c) 2017 Wind River Systems, Inc.
#

from neutron_lib.api.definitions import provider_net
from neutron_lib import constants as lib_constants
from neutron_lib.plugins import constants as p_const
from neutron_lib.plugins import directory
from oslo_log import log as logging
from sqlalchemy import orm
from sqlalchemy.sql import expression as sql

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db.models import agent as agent_models
from neutron.db.models import l3 as l3_models
from neutron.db.models import l3_attrs as l3_attrs_models
from neutron.db import models_v2
from neutron.plugins.common import constants
from neutron.plugins.ml2.drivers.l2pop import mech_driver as l2pop_driver
from neutron.plugins.ml2.drivers.l2pop.mech_driver import l2pop_db as l2pop_db
from neutron.plugins.ml2.drivers.l2pop.mech_driver import l2pop_rpc as \
    l2pop_rpc
from neutron.plugins.ml2 import models as ml2_models

LOG = logging.getLogger(__name__)


class L3RouterL2PopMixin(object):

    def __new__(cls):
        new = super(L3RouterL2PopMixin, cls).__new__(cls)
        new.subscribe_l2pop_callbacks()
        return new

    def subscribe_l2pop_callbacks(self):
        registry.subscribe(
            self._notify_fip_status_callback, resources.FLOATING_IP,
            events.AFTER_UPDATE)
        l2pop_driver.register_fdb_extend_func(
            p_const.L3, self.l3_fdb_extend_func)

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    @staticmethod
    def _get_fip_fdb_entry(context, floating_ip_address, router_id):
        """Returns FDB information for a single non-DVR FIP entry.

        This special query is needed because there are instances where we
        are notified of a FIP deletion after the FIP DB resource has already
        been deleted therefore we cannot use the full query; instead we need
        to use the known ip_address, router_id, and port_id values to
        fill-in the missing information.
        """
        query = context.session.query(ml2_models.PortBinding.host,
                                      models_v2.Port.mac_address)
        query = (query.select_from(l3_models.Router)
                 .join(l3_attrs_models.RouterExtraAttributes,
                       l3_attrs_models.RouterExtraAttributes.router_id ==
                       l3_models.Router.id)
                 .join(models_v2.Port,
                       models_v2.Port.device_id == l3_models.Router.id)
                 .join(ml2_models.PortBinding,
                       ml2_models.PortBinding.port_id == models_v2.Port.id)
                 .filter(l3_models.Router.id == router_id)
                 .filter(models_v2.Port.device_owner ==
                         lib_constants.DEVICE_OWNER_ROUTER_GW)
                 .filter(l3_attrs_models.RouterExtraAttributes.distributed ==
                         sql.false()))
        # return [(host, mac, ip)...]
        return [(e[0], e[1], floating_ip_address) for e in query.all()]

    @staticmethod
    def _get_fip_fdb_entries(context, network_id, floatingip_id=None,
                             exclude_host=None):
        """Returns FDB information for all non-DVR FIP resources.

        The DB queries for all FIP resources that are associated to non-DVR
        routers and then returns a tuple describing which (host, mac_address,
        ip_address) relates to each FIP resource.  The tuple describes the
        MAC address of the gateway interface that is servicing that FIP
        resource and on which node that gateway router resides.
        """
        query = context.session.query(ml2_models.PortBinding.host,
                                      models_v2.Port.mac_address,
                                      l3_models.FloatingIP.floating_ip_address)
        query = (query.select_from(l3_models.FloatingIP)
                 .join(l3_models.Router,
                       l3_models.Router.id == l3_models.FloatingIP.router_id)
                 .join(l3_attrs_models.RouterExtraAttributes,
                       l3_attrs_models.RouterExtraAttributes.router_id ==
                       l3_models.Router.id)
                 .join(models_v2.Port,
                       models_v2.Port.device_id == l3_models.Router.id)
                 .join(ml2_models.PortBinding,
                       ml2_models.PortBinding.port_id == models_v2.Port.id)
                 .filter(models_v2.Port.device_owner ==
                         lib_constants.DEVICE_OWNER_ROUTER_GW)
                 .filter(l3_models.FloatingIP.floating_network_id ==
                         network_id)
                 .filter(l3_attrs_models.RouterExtraAttributes.distributed ==
                         sql.false()))
        if floatingip_id is not None:
            query = query.filter(l3_models.FloatingIP.id == floatingip_id)
        if exclude_host is not None:
            query = query.filter(agent_models.Agent.host != exclude_host)
        # return [(host, mac, ip)...]
        return [(e[0], e[1], e[2]) for e in query.all()]

    @staticmethod
    def _get_fip_dvr_fdb_entry(context, floating_ip_address, fixed_port_id,
                               router_id):
        """Returns FDB information for a single non-DVR FIP entry.

        This special query is needed because there are instances where we
        are notified of a FIP deletion after the FIP DB resource has already
        been deleted therefore we cannot use the full query; instead we need
        to use the known ip_address, router_id, and port_id values to
        fill-in the missing information.
        """
        agent_ports = orm.aliased(models_v2.Port, name='agent_ports')
        query = context.session.query(agent_models.Agent.host,
                                      agent_ports.mac_address)
        query = (query.select_from(l3_models.Router)
                 .join(l3_attrs_models.RouterExtraAttributes,
                       l3_attrs_models.RouterExtraAttributes.router_id ==
                       l3_models.Router.id)
                 .join(ml2_models.DistributedPortBinding,
                       ml2_models.DistributedPortBinding.router_id ==
                       l3_models.Router.id)
                 .join(agent_models.Agent,
                       agent_models.Agent.host ==
                       ml2_models.DistributedPortBinding.host)
                 .join(agent_ports,
                       agent_ports.device_id == agent_models.Agent.id)
                 .join(ml2_models.PortBinding,
                       ml2_models.PortBinding.host == agent_models.Agent.host)
                 .join(models_v2.Port,
                       models_v2.Port.id == ml2_models.PortBinding.port_id)
                 .filter(models_v2.Port.id == fixed_port_id)
                 .filter(agent_ports.device_owner ==
                         lib_constants.DEVICE_OWNER_AGENT_GW)
                 .filter(l3_models.Router.id == router_id)
                 .filter(l3_attrs_models.RouterExtraAttributes.distributed ==
                         sql.true())
                 .group_by(agent_models.Agent.host,
                           agent_ports.mac_address))
        # return [(host, mac, ip)...]
        return [(e[0], e[1], floating_ip_address) for e in query.all()]

    @staticmethod
    def _get_fip_dvr_fdb_entries(context, network_id, floatingip_id=None,
                                 exclude_host=None):
        """Returns FDB information about all DVR FIP resources.

        The DB queries for all FIP resources that are associated to DVR
        routers and then returns a tuple describing which (host, mac_address,
        ip_address) relates to each FIP resource.  The tuple describes the
        MAC address of the floatingip agent gateway interface that is
        servicing that FIP resource and on which node that agent gateway
        interface resides.
        """
        agent_ports = orm.aliased(models_v2.Port, name='agent_ports')
        query = context.session.query(agent_models.Agent.host,
                                      agent_ports.mac_address,
                                      l3_models.FloatingIP.floating_ip_address)
        query = (query.select_from(l3_models.FloatingIP)
                 .join(l3_models.Router,
                       l3_models.Router.id == l3_models.FloatingIP.router_id)
                 .join(l3_attrs_models.RouterExtraAttributes,
                       l3_attrs_models.RouterExtraAttributes.router_id ==
                       l3_models.Router.id)
                 .join(models_v2.Port,
                       models_v2.Port.id == l3_models.FloatingIP.fixed_port_id)
                 .join(ml2_models.PortBinding,
                       ml2_models.PortBinding.port_id == models_v2.Port.id)
                 .join(agent_models.Agent,
                       agent_models.Agent.host == ml2_models.PortBinding.host)
                 .join(agent_ports,
                       agent_ports.device_id == agent_models.Agent.id)
                 .filter(agent_ports.device_owner ==
                         lib_constants.DEVICE_OWNER_AGENT_GW)
                 .filter(l3_models.FloatingIP.floating_network_id ==
                         network_id)
                 .filter(l3_attrs_models.RouterExtraAttributes.distributed ==
                         sql.true()))
        if floatingip_id is not None:
            query = query.filter(l3_models.FloatingIP.id == floatingip_id)
        if exclude_host is not None:
            query = query.filter(agent_models.Agent.host != exclude_host)
        # return [(host, mac, ip)...]
        return [(e[0], e[1], e[2]) for e in query.all()]

    def l3_fdb_extend_func(self, context, network_id, fdb_entries,
                           exclude_host=None):
        """Hook in to the l2pop FDB generation and add FIP entries to it."""
        dvr_fip_entries = self._get_fip_dvr_fdb_entries(
            context, network_id, exclude_host=exclude_host)
        fip_entries = self._get_fip_fdb_entries(
            context, network_id, exclude_host=exclude_host)
        entries = dvr_fip_entries + fip_entries
        agent_ips = {}
        ports = fdb_entries[network_id]['ports']
        physical_network = fdb_entries[network_id]['physical_network']
        for host, mac_address, ip_address in entries:
            key = '{}-{}'.format(host, physical_network)
            if key not in agent_ips:
                agent_ip = l2pop_db.get_agent_ip_by_host(
                    context.session, host, physical_network)
                agent_ips[key] = agent_ip
            agent_ip = agent_ips[key]
            if agent_ip not in ports:
                ports[agent_ip] = [lib_constants.FLOODING_ENTRY]
            info = l2pop_rpc.PortInfo(mac_address, ip_address)
            ports[agent_ip].append(info)
        return fdb_entries

    @staticmethod
    def _get_fdb_template(network):
        return {network['id']:
                {'ports': {},
                 'physical_network': network[provider_net.PHYSICAL_NETWORK],
                 'segment_id': network[provider_net.SEGMENTATION_ID],
                 'network_type': network[provider_net.NETWORK_TYPE]}}

    @property
    def l2pop_notifier(self):
        if not hasattr(self, '_l2pop_notifier'):
            self._l2pop_notifier = l2pop_rpc.L2populationAgentNotifyAPI()
        return self._l2pop_notifier

    def _handle_fip_status_update(self, context, fip, fdb_entry):
        host, mac_address, ip_address = fdb_entry
        network_id = fip['floating_network_id']
        network = self._core_plugin.get_network(context, network_id)
        physical_network = network[provider_net.PHYSICAL_NETWORK]
        network_type = network[provider_net.NETWORK_TYPE]
        if network_type != constants.TYPE_VXLAN:
            return
        agent_ip = l2pop_db.get_agent_ip_by_host(
            context.session, host, physical_network)
        fdb_entries = self._get_fdb_template(network)
        ports = fdb_entries[network_id]['ports']
        if fip['status'] == lib_constants.ACTIVE and fip['fixed_port_id']:
            # NOTE(alegacy): make sure that it is understood that this node
            # is participating in this network if we are adding an entry but
            # to be cautious do not remove the flood entry on delete; leave
            # that up to the l2pop driver itself.
            ports[agent_ip] = [lib_constants.FLOODING_ENTRY]
        else:
            ports[agent_ip] = []
        ports[agent_ip].append(l2pop_rpc.PortInfo(mac_address, ip_address))
        fdb_entries['source'] = p_const.L3
        if fip['status'] == lib_constants.ACTIVE and fip['fixed_port_id']:
            self.l2pop_notifier.add_fdb_entries(context, fdb_entries)
        else:
            self.l2pop_notifier.remove_fdb_entries(context, fdb_entries)

    def handle_fip_status_update(self, context, fip):
        # NOTE(alegacy): on delete notifications the router/port id are cleared
        router_id = fip['router_id'] or fip['last_known_router_id']
        fixed_port_id = fip['fixed_port_id'] or fip.get('last_fixed_port_id')
        if 'status' not in fip or not fixed_port_id:
            return
        entries = self._get_fip_dvr_fdb_entry(
            context, fip['floating_ip_address'], fixed_port_id, router_id)
        if not entries:
            entries = self._get_fip_fdb_entry(
                context, fip['floating_ip_address'], router_id)
            if not entries:
                return  # no data available for this FIP
        assert len(entries) == 1
        entry = entries[0]
        return self._handle_fip_status_update(context, fip, entry)

    def _notify_fip_status_callback(self, resource, event, trigger, **kwargs):
        context = kwargs.pop('context')
        self.handle_fip_status_update(context, kwargs)
