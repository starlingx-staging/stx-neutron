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
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#

import re

import six
from tsconfig import tsconfig

from neutron_lib import constants as lib_constants
from neutron_lib import context
from neutron_lib.db import model_base
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.orm import aliased, exc
from sqlalchemy import and_, or_, func

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants
from neutron.common import topics
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db import providernet_db
from neutron.drivers import fm
from neutron.drivers import host
from neutron.extensions import host as ext_host
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)

DATA_NETWORK = "data"

# data interface types to be considered when scheduling resources
DATA_NETWORK_TYPES = [DATA_NETWORK]

PCI_PASSTHROUGH = "pci-passthrough"
PCI_SRIOV_PASSTHROUGH = "pci-sriov"
PCI_NETWORK_TYPES = [PCI_PASSTHROUGH, PCI_SRIOV_PASSTHROUGH]


class Host(model_base.BASEV2):
    """Represents compute host running in neutron deployments."""

    # system host uuid (set to hostname until maintenance uses uuid)
    id = sa.Column(sa.String(36), primary_key=True, nullable=False)

    # system hostname
    name = sa.Column(sa.String(255), unique=True, nullable=False)

    # host operational state
    availability = sa.Column(sa.Enum(constants.HOST_UP,
                                     constants.HOST_DOWN,
                                     name='availability_states'),
                             default=constants.HOST_DOWN, nullable=False)

    # the time when first report came from maintenance
    created_at = sa.Column(sa.DateTime, nullable=False)

    # the time when last report came from maintenance
    updated_at = sa.Column(sa.DateTime, nullable=True)


class HostInterface(model_base.BASEV2):
    """Represents a data interface on a compute host."""

    # system inventory uuid
    id = sa.Column(sa.String(36), primary_key=True, nullable=False)

    # parent compute node
    host_id = sa.Column(sa.String(36),
                        sa.ForeignKey("hosts.id", ondelete='CASCADE'))

    # MTU value of the interface
    mtu = sa.Column(sa.Integer, nullable=False, default=0)

    # Network type of the interface (i.e., data, pci-passthrough, etc...)
    network_type = sa.Column(sa.String(255), default=DATA_NETWORK)

    # Comma separated list of reserved vlan values
    vlans = sa.Column(sa.String(255))

    # the time when first report came from maintenance
    created_at = sa.Column(sa.DateTime, nullable=False)

    # the time when last report came from maintenance
    updated_at = sa.Column(sa.DateTime, nullable=True)


class HostInterfaceProviderNetBinding(model_base.BASEV2):
    """Represents the binding between host interfaces and their associated
    provider networks.
    """
    providernet_id = sa.Column(sa.String(36),
                               sa.ForeignKey("providernets.id",
                                             ondelete='CASCADE'),
                               primary_key=True)

    interface_id = sa.Column(sa.String(36),
                             sa.ForeignKey("hostinterfaces.id",
                                           ondelete='CASCADE'),
                             primary_key=True)


class HostProviderNetBinding(model_base.BASEV2):
    """Represents the binding between hosts and their associated provider
    networks.
    """
    providernet_id = sa.Column(sa.String(36),
                               sa.ForeignKey("providernets.id",
                                             ondelete='CASCADE'),
                               primary_key=True)
    host_id = sa.Column(sa.String(36),
                        sa.ForeignKey("hosts.id", ondelete='CASCADE'),
                        primary_key=True)


class HostDbMixin(ext_host.HostPluginBase):
    """
    Mixin class to add the host extension to the db_plugin_base_v2.
    """

    host_notifier = None
    host_driver = host.NoopHostDriver()

    def _get_host_by_id(self, context, id):
        try:
            query = self._model_query(context, Host)
            host = query.filter(Host.id == id).one()
        except exc.NoResultFound:
            raise ext_host.HostNotFoundById(id=id)
        return host

    def _get_host_by_name(self, context, name):
        try:
            query = self._model_query(context, Host)
            host = query.filter(Host.name == name).one()
        except exc.NoResultFound:
            raise ext_host.HostNotFoundByName(hostname=name)
        return host

    def _make_host_dict(self, host, fields=None):
        attr = ext_host.RESOURCE_ATTRIBUTE_MAP.get(
            ext_host.RESOURCE_NAME + 's')
        res = dict((k, host[k]) for k in attr
                   if k not in ext_host.OPERATIONAL_ATTRIBUTES)
        # Set operational attributes
        res.setdefault('agents', [])
        res.setdefault('subnets', 0)
        res.setdefault('routers', 0)
        res.setdefault('ports', 0)
        return self._fields(res, fields)

    def _create_or_update_host(self, context, id, host):
        host_data = host['host']
        res = {}
        with context.session.begin(subtransactions=True):
            current_time = timeutils.utcnow()
            try:
                event_type = events.AFTER_UPDATE
                host_db = self._get_host_by_id(context, id)
                if 'availability' in host_data:
                    # If availability changes, run pnet connectivity tests
                    if host_db.availability != host_data['availability']:
                        if host_data['availability'] == constants.HOST_DOWN:
                            self._set_connectivity_data_to_unknown_by_host(
                                context, host_db.id
                            )
                        else:
                            host_providernets = self.get_providernets_on_host(
                                context, host_db.id)
                            self.notify_schedule_audit_providernets(
                                context, list(set(host_providernets)),
                                by_event=True)
                    res['availability'] = host_data['availability']
                    res['updated_at'] = current_time
                    host_db.update(res)
            except ext_host.HostNotFoundById:
                res['id'] = id
                res['name'] = host_data['name']
                res['created_at'] = current_time
                res['availability'] = host_data.get('availability',
                                                    constants.HOST_DOWN)
                event_type = events.AFTER_CREATE
                host_db = Host(**res)
                context.session.add(host_db)
        host_data = self._make_host_dict(host_db)
        registry.notify(resources.HOST, event_type, self,
                        context=context, host=host_data)
        return host_data

    def get_host_uuid(self, context, hostname):
        """
        Returns the UUID value assigned to the specified hostname
        """
        # Try looking it up in our DB first
        try:
            host = self.get_host_by_name(context, hostname)
            return host['id']
        except ext_host.HostNotFoundByName:
            # Does not exist yet
            pass
        # Try looking it up with the host driver
        return self.host_driver.get_host_uuid(context, hostname)

    def _get_providernet_bindings(self, context, interface_uuid):
        query = (context.session.query(HostInterfaceProviderNetBinding).
                 filter((HostInterfaceProviderNetBinding.interface_id ==
                         interface_uuid)))
        return [binding.providernet_id for binding in query.all()]

    def _get_providernet_networktype(self, context, networktypes):
        """
        Returns the list of inactive provider networks that are attached
        to the interface of the specified network types on the
        given host.
        """
        providernets = (
            context.session.query(providernet_db.ProviderNet)
            .join(HostInterfaceProviderNetBinding,
                  HostInterfaceProviderNetBinding.providernet_id ==
                  providernet_db.ProviderNet.id)
            .join(HostInterface,
                  and_((HostInterface.id ==
                        HostInterfaceProviderNetBinding.interface_id),
                       (HostInterface.network_type.
                        in_(networktypes))))
            .join(Host,
                  Host.id == HostInterface.host_id)
            .filter(Host.availability == constants.HOST_UP)
            .filter(providernet_db.ProviderNet.status !=
                    constants.PROVIDERNET_ACTIVE)
            .group_by(providernet_db.ProviderNet.id)
            .all())
        return providernets

    def _update_providernet_states(self, context):
        with context.session.begin(subtransactions=True):
            # Find all providernets that are currently marked as DOWN and are
            # bound to a host that is UP.  Only do this for 'data' networktypes
            # since only limited state information is available for the pci nts
            providernets = self._get_providernet_networktype(
                context, DATA_NETWORK_TYPES)
            data = {'status': constants.PROVIDERNET_ACTIVE}
            LOG.debug("updating {} providernets to ACTIVE".format(
                    len(providernets)))
            for providernet in providernets:
                providernet.update(data)
                self._clear_providernet_fault(providernet)

            # Clear the provider network alarm without changing the status
            # only for 'pci-passthrough' and 'pci-sriov' networktypes.
            # Find all providernets that are currently marked as DOWN and are
            # bound to a host that is UP.
            providernets = self._get_providernet_networktype(
                context, PCI_NETWORK_TYPES)
            for providernet in providernets:
                LOG.info(("clearing alarm for providernet {}").format(
                    providernet))
                self._clear_providernet_fault(providernet)

            # Update providernet states for providernets without at least one
            # binding to a host that is UP.  Only do this for 'data'
            # networktypes since only limited state information is available
            # for the pci nts
            providernets = (
                context.session.query(providernet_db.ProviderNet)
                .outerjoin(HostInterfaceProviderNetBinding,
                      HostInterfaceProviderNetBinding.providernet_id ==
                      providernet_db.ProviderNet.id)
                .outerjoin(HostInterface,
                           and_((HostInterface.network_type.
                                 in_(DATA_NETWORK_TYPES)),
                                (HostInterface.id ==
                                 HostInterfaceProviderNetBinding.
                                 interface_id)))
                .outerjoin(Host,
                           and_(Host.id == HostInterface.host_id,
                                Host.availability == constants.HOST_UP))
                .filter(providernet_db.ProviderNet.status ==
                        constants.PROVIDERNET_ACTIVE)
                .group_by(providernet_db.ProviderNet.id)
                .having(or_(func.count(Host.id) == 0,
                            func.count(HostInterfaceProviderNetBinding.
                                       providernet_id)
                            == 0))
                .all())
            data = {'status': constants.PROVIDERNET_DOWN}
            LOG.debug("updating {} providernets to DOWN".format(
                    len(providernets)))
            for providernet in providernets:
                providernet.update(data)
                self._report_providernet_fault(providernet)

    def _update_interface_providernet_bindings(self, context, interface_uuid,
                                               current_bindings):
        previous_bindings = self._get_providernet_bindings(
            context, interface_uuid)
        previous = set(previous_bindings)
        current = set(current_bindings)
        stale_providernets = previous - current
        new_providernets = current - previous
        if not stale_providernets and not new_providernets:
            return
        LOG.warning(("Updating provider net bindings for "
                     "interface {} removed={} added={}").format(
            interface_uuid, stale_providernets, new_providernets))
        with context.session.begin(subtransactions=True):
            if stale_providernets:
                # remove stale entries
                query = (context.session.
                         query(HostInterfaceProviderNetBinding).
                         filter((HostInterfaceProviderNetBinding.
                                 interface_id == interface_uuid)).
                         filter(HostInterfaceProviderNetBinding.providernet_id.
                                in_(stale_providernets)))
                query.delete(synchronize_session='fetch')
            # Add new entries
            for providernet_id in new_providernets:
                binding = HostInterfaceProviderNetBinding()
                binding.providernet_id = providernet_id
                binding.interface_id = interface_uuid
                context.session.add(binding)

    def _create_or_update_interface(self, context, host_uuid,
                                    interface_uuid, body):
        fields = {'mtu': body['mtu'],
                  'vlans': body['vlans'],
                  'network_type': body['network_type']}
        with context.session.begin(subtransactions=True):
            query = (context.session.query(HostInterface).
                     filter(HostInterface.id == interface_uuid))
            interface = query.one_or_none()
            if interface:
                fields['updated_at'] = timeutils.utcnow()
                interface.update(fields)
            else:
                fields['id'] = interface_uuid
                fields['host_id'] = host_uuid
                fields['created_at'] = timeutils.utcnow()
                interface = HostInterface(**fields)
                context.session.add(interface)
            self._update_interface_providernet_bindings(
                context, interface_uuid, body['providernet_ids'])

    def is_host_available(self, context, hostname):
        return self.host_driver.is_host_available(context, hostname)

    def get_providernet_hosts(self, context, providernet_id):
        """
        Returns the list of hosts with interfaces attached to the specified
        provider network.
        """
        bindings = (context.session.query(Host)
                    .order_by(Host.updated_at)
                    .join(HostInterface,
                          HostInterface.host_id == Host.id)
                    .join(HostInterfaceProviderNetBinding,
                          (HostInterfaceProviderNetBinding.interface_id ==
                           HostInterface.id))
                    .filter(HostInterfaceProviderNetBinding.providernet_id ==
                            providernet_id)
                    .all())
        return [binding.id for binding in bindings]

    def get_providernet_host_objects(self, context, providernet_id):
        """
        Returns the list of hosts with interfaces attached to the specified
        provider network.
        """
        bindings = (context.session.query(Host)
                    .order_by(Host.updated_at)
                    .join(HostInterface,
                          HostInterface.host_id == Host.id)
                    .join(HostInterfaceProviderNetBinding,
                          (HostInterfaceProviderNetBinding.interface_id ==
                           HostInterface.id))
                    .filter(HostInterfaceProviderNetBinding.providernet_id ==
                            providernet_id)
                    .all())
        return bindings

    def get_providernets_on_host(self, context, host_id):
        """
        Returns the list of provider networks that interfaces on this the
        specified host are attached to.
        """
        bindings = (context.session.query(HostInterfaceProviderNetBinding)
                    .join(HostInterface,
                          (HostInterfaceProviderNetBinding.interface_id ==
                           HostInterface.id))
                    .filter(HostInterface.host_id == host_id)
                    .all())
        return [binding.providernet_id for binding in bindings]

    def get_providernet_connectivity_query(self, context):
        with context.session.begin(subtransactions=True):
            master = aliased(Host, name="Master")
            pnet_state_class = providernet_db.ProviderNetConnectivityState
            query = context.session.query(pnet_state_class, Host, master,
                                          providernet_db.ProviderNet)
            query = query.join(Host, Host.id == pnet_state_class.host_id)
            query = query.join(master,
                               master.id == pnet_state_class.master_host_id)
            query = query.join(providernet_db.ProviderNet,
                               providernet_db.ProviderNet.id ==
                               pnet_state_class.providernet_id)
            return query

    def create_or_update_host(self, context, hostname):
        host_uuid = self.get_host_uuid(context, hostname)
        if not host_uuid:
            LOG.error(("Failed to retrieve uuid value for host {}").format(
                hostname))
            raise ext_host.HostNotFoundByName(hostname=hostname)
        host = {}
        host['host'] = {'id': host_uuid, 'name': hostname}
        self._create_or_update_host(context, host_uuid, host)

    @db_api.retry_if_session_inactive()
    def create_host(self, context, host):
        host_data = host['host']
        id = host_data.get('id')
        host = self._create_or_update_host(context, id, host)
        self._update_providernet_states(context)
        return host

    def _fix_host_data(self, context, id, host):
        hostname = id
        id = self.get_host_uuid(context, hostname)
        if not id:
            LOG.error(("Failed to query UUID for host {}").format(hostname))
            raise ext_host.HostNotFoundByName(hostname=hostname)
        host_data = host['host']
        host_data.update({'name': hostname, 'id': id})
        host.update({'host': host_data})
        return id

    @db_api.retry_if_session_inactive()
    def update_host(self, context, id, host):
        host = self._create_or_update_host(context, id, host)
        self._update_providernet_states(context)
        if host.get('availability') == constants.HOST_UP:
            host_state_up = True
        else:
            host_state_up = False
        self.host_notifier.host_updated(context, host_state_up, host['name'])
        return host

    @db_api.retry_if_session_inactive()
    def delete_host(self, context, id):
        with context.session.begin(subtransactions=True):
            host = self._get_host_by_id(context, id)
            context.session.delete(host)

    def get_host_by_name(self, context, name, fields=None):
        host = self._get_host_by_name(context, name)
        return self._make_host_dict(host, fields)

    def get_hostname(self, context, id):
        host = self._get_host_by_id(context, id)
        return host['name']

    @db_api.retry_if_session_inactive()
    def get_host(self, context, id, fields=None):
        host = self._get_host_by_id(context, id)
        return self._make_host_dict(host, fields)

    @db_api.retry_if_session_inactive()
    def get_hosts(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None, page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'host', limit, marker)
        return self._get_collection(
            context, Host, self._make_host_dict,
            filters=filters, fields=fields, sorts=sorts, limit=limit,
            marker_obj=marker_obj, page_reverse=page_reverse)

    def _get_interface_by_id(self, context, interface_uuid):
        try:
            query = self._model_query(context, HostInterface)
            host = query.filter(HostInterface.id == interface_uuid).one()
        except exc.NoResultFound:
            raise ext_host.HostInterfaceNotFoundById(id=interface_uuid)
        return host

    def _delete_interface(self, context, interface_uuid):
        with context.session.begin(subtransactions=True):
            interface = self._get_interface_by_id(context, interface_uuid)
            context.session.delete(interface)

    def _validate_interface_uuid(self, context, interface):
        if 'uuid' not in interface:
            raise ext_host.HostMissingInterfaceUuid()
        if not uuidutils.is_uuid_like(interface['uuid']):
            raise ext_host.HostInvalidInterfaceUuid(
                value=interface['uuid'])

    def _validate_interface_mtu(self, context, interface):
        if 'mtu' not in interface:
            raise ext_host.HostMissingInterfaceMtu()
        mtu = interface['mtu']
        try:
            mtu = int(mtu)
        except ValueError:
            raise ext_host.HostInvalidInterfaceMtu(value=mtu)
        if (mtu < constants.MINIMUM_MTU) or (mtu > constants.MAXIMUM_MTU):
            raise ext_host.HostOutOfRangeInterfaceMtu(
                minimum=constants.MINIMUM_MTU,
                maximum=constants.MAXIMUM_MTU)

    def _validate_interface_providernets(self, context, interface):
        if 'providernets' not in interface:
            raise ext_host.HostMissingInterfaceProviderNetworks()
        pnets = interface['providernets'].strip()
        pnets = re.sub(',,+', ',', pnets)
        pnets = pnets.split(',')
        values = []
        for pnet in pnets:
            providernet = self._get_providernet_by_name(context, pnet)
            values.append(providernet['id'])
        # Update the request body with a validated set of values
        interface['providernets'] = ','.join(values)
        interface['providernet_ids'] = values

    def _validate_interface_vlans(self, context, interface):
        if 'vlans' not in interface or not interface['vlans'].strip():
            interface['vlans'] = ''
            interface['vlan_ids'] = []
            return
        vlans = interface['vlans'].strip()
        vlans = re.sub(',,+', ',', vlans)
        vlans = vlans.split(',')
        values = []
        for vlan_id in vlans:
            try:
                values.append(int(vlan_id))
            except ValueError:
                raise ext_host.HostInvalidInterfaceVlans(
                    values=interface['vlans'])
            if ((int(vlan_id) < constants.MIN_VLAN_TAG) or
                (int(vlan_id) > constants.MAX_VLAN_TAG)):
                raise ext_host.HostOutOfRangeInterfaceVlan(
                    vlan_id=vlan_id,
                    minimum=constants.MIN_VLAN_TAG,
                    maximum=constants.MAX_VLAN_TAG)
        # Update the request body with a validated set of vlans
        interface['vlans'] = ','.join([str(x) for x in values])
        interface['vlan_ids'] = values

    def _validate_interface_network_type(self, context, interface):
        interface.setdefault('network_type', DATA_NETWORK)
        network_type = interface['network_type']
        if network_type not in [DATA_NETWORK,
            PCI_PASSTHROUGH, PCI_SRIOV_PASSTHROUGH]:
            raise ext_host.HostInvalidInterfaceNetworkType(
                value=network_type)

    def _validate_interface(self, context, body):
        if 'interface' not in body:
            raise ext_host.HostMissingInterfaceBody()
        interface = body['interface']
        self._validate_interface_uuid(context, interface)
        self._validate_interface_mtu(context, interface)
        self._validate_interface_providernets(context, interface)
        self._validate_interface_vlans(context, interface)
        self._validate_interface_network_type(context, interface)

    def bind_interface(self, context, id, body):
        host = self._get_host_by_id(context, id)
        LOG.debug("Binding interface to host {} with values: {}".format(
                host['name'], body))
        with context.session.begin(subtransactions=True):
            self._validate_interface(context, body)
            interface = body['interface']
            test_only = interface.get('test', False)
            if test_only:
                # API user is testing whether this bind would succeed; no
                # action is required.
                return
            interface_uuid = interface['uuid']
            self._create_or_update_interface(
                context, host['id'], interface_uuid, interface)
        return body

    def unbind_interface(self, context, id, body):
        host = self._get_host_by_id(context, id)
        LOG.debug("Unbinding interface to host {} with values: {}".format(
                host['name'], body))
        if 'interface' not in body:
            raise ext_host.HostMissingInterfaceBody()
        interface = body['interface']
        self._validate_interface_uuid(context, interface)
        try:
            self._delete_interface(context, interface['uuid'])
        except ext_host.HostInterfaceNotFoundById:
            pass
        return body


class HostSchedulerDbMixin(HostDbMixin):

    agents = {}
    fm_driver = fm.NoopFmDriver()

    def _update_agent(self, context, agent_type, host_id, admin_state_up):
        LOG.debug("updating {} agent on {} with admin_state_up {}".format(
                agent_type, host_id, admin_state_up))
        agent_notifier = self.agent_notifiers.get(agent_type)
        if (agent_notifier and hasattr(agent_notifier, 'agent_updated')):
            agent_notifier.agent_updated(context, admin_state_up, host_id)

    def _extend_host_dict(self, host, agent, fields=None):
        if not fields or 'agents' in set(fields):
            host['agents'].append({'type': agent['agent_type'],
                                   'id': agent['id']})
        if not fields or 'subnets' in set(fields):
            if agent['topic'] == topics.DHCP_AGENT:
                host['subnets'] = agent['configurations'].get('subnets')

        if not fields or 'routers' in set(fields):
            if agent['topic'] == topics.L3_AGENT:
                host['routers'] = agent['configurations'].get('routers')

        if not fields or 'ports' in set(fields):
            if agent['agent_type'] == constants.AGENT_TYPE_WRS_VSWITCH:
                # There is no topic for other agent types and this
                # functionality is specific to the WRS VSWITCH
                host['ports'] = agent['configurations'].get('devices')
        return host

    def _relocate_agent(self, context, agent):
        if agent['topic'] == topics.DHCP_AGENT:
            plugin = directory.get_plugin()
            plugin.relocate_networks(context, agent)
        elif agent['topic'] == topics.L3_AGENT:
            plugin = directory.get_plugin(plugin_constants.L3)
            if utils.is_extension_supported(
                    plugin, lib_constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
                plugin.relocate_routers(context, agent['id'])

    def _auto_schedule_host(self, context, host):
        plugin = directory.get_plugin()
        plugin.auto_schedule_networks(context, host['name'])

        plugin = directory.get_plugin(plugin_constants.L3)
        if utils.is_extension_supported(
                plugin, lib_constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
            plugin.auto_schedule_routers(context, host['name'], None)

    @db_api.retry_if_session_inactive()
    def delete_host(self, context, id):
        LOG.warning(("delete_host id={}").format(id))
        hostname = self.get_hostname(context, id)
        super(HostSchedulerDbMixin, self).delete_host(context, id)
        agents = self.get_agents_by_hosts(context, [hostname])
        LOG.debug("disabling {} agents on {}".format(len(agents), hostname))
        for agent in agents:
            self._relocate_agent(context, agent)
            self.delete_agent(context, agent['id'])

    @db_api.retry_if_session_inactive()
    def update_host(self, context, id, host):
        LOG.warning(("update_host id={}, host={}").format(id, host))
        data = super(HostSchedulerDbMixin, self).update_host(
            context, id, host)
        agents = self.get_agents_by_hosts(context, [data['name']])

        # Check if the l3 agent needs to be deleted
        sdn_enabled = False
        if tsconfig.sdn_enabled.lower() == 'yes':
            sdn_enabled = True
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if (l3plugin and sdn_enabled and
            not utils.is_extension_supported(
                    l3plugin, lib_constants.L3_AGENT_SCHEDULER_EXT_ALIAS)):
            for agent in agents[:]:
                if agent['agent_type'] == lib_constants.AGENT_TYPE_L3:
                    # agent should not be configured since l3plugin router is
                    # not enabled
                    LOG.info("Deleting agent {}".format(agent['id']))
                    self.delete_agent(context, agent['id'])
                    agents.remove(agent)

        if data.get('availability', constants.HOST_DOWN) == constants.HOST_UP:
            LOG.debug("enabling {} agents on {}".format(len(agents), id))
            self._auto_schedule_host(context, data)
            for agent in agents:
                self._update_agent(context, agent['agent_type'],
                                   data['name'], agent['admin_state_up'])
        else:
            LOG.debug("disabling {} agents on {}".format(len(agents), id))
            for agent in agents:
                self._relocate_agent(context, agent)
        return self.get_host(context, id)

    @db_api.retry_if_session_inactive()
    def get_hosts(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None, page_reverse=False):
        LOG.debug("get_hosts filters={}, fields={}".format(
                filters, fields))
        hosts = super(HostSchedulerDbMixin, self).get_hosts(
            context, filters, fields, sorts, limit, marker, page_reverse)
        for h in hosts:
            agents = self.get_agents_by_hosts(
                context, [self.get_hostname(context, h['id'])])
            for agent in agents:
                self._extend_host_dict(h, agent, fields)
        return hosts

    @db_api.retry_if_session_inactive()
    def get_host(self, context, id, fields=None):
        LOG.debug("get_host id={}, fields={}".format(id, fields))
        host = super(HostSchedulerDbMixin, self).get_host(
            context, id, fields)
        if host:
            agents = self.get_agents_by_hosts(
                context, [self.get_hostname(context, host['id'])])
            for agent in agents:
                host = self._extend_host_dict(host, agent, fields)
        return host

    def get_agents_by_hosts(self, context, names=None):
        filter = {'host': names} if names else None
        return self.get_agents(context, filter)

    def audit_agent_state(self):
        """
        Audit the current state of the agent to determine if fault reports
        need to be raised or cleared
        """
        LOG.debug("Audit agent state")
        previous_agents = self.agents
        admin_context = context.get_admin_context()
        self.agents = {a['id']: a for a in self.get_agents(admin_context)}
        new_alive_topics = set()
        host_availability = {}
        for uuid, agent in six.iteritems(self.agents):
            if agent['agent_type'] == constants.AGENT_TYPE_BGP_ROUTING:
                if not self.is_bgp_enabled():
                    self.agents[uuid] = None
                    self.delete_agent(admin_context, uuid)
                    continue
            hostname = agent['host']
            if hostname not in host_availability:
                # NOTE(alegacy): Cache to avoid repeating for multiple
                # agents on same host.
                host_availability[hostname] = \
                    self.is_host_available(admin_context, hostname)
            if not host_availability[hostname]:
                # If agent dies while host is down, delay updating list of
                # agents until after the host comes online, so that audit
                # can correctly assess change in agent state at that point.
                # Set to None so that alarm will be raised or cleared when
                # host comes up.
                self.agents[uuid] = None
                continue
            elif uuid in previous_agents:
                previous = previous_agents[uuid]
            else:
                previous = None

            # Raise or clear alarm either if the alive state changes, or
            # if the alarm hasn't been raised/cleared for this agent yet.
            if not previous or agent['alive'] != previous['alive']:
                registry.notify(resources.AGENT, events.AFTER_UPDATE, self,
                                context=admin_context, host=agent['host'],
                                plugin=self, agent=agent)
                # TODO(alegacy): move fault reporting to a registry callback
                # Clear fault if agent is alive
                if agent['alive']:
                    self.clear_agent_fault(agent)
                    new_alive_topics.add(agent['topic'])
                # Only report fault if agent's host is online
                else:
                    self.report_agent_fault(agent)
        for new_alive_topic in new_alive_topics:
            self._redistribute_for_new_agent(admin_context, new_alive_topic)

    def report_agent_fault(self, agent):
        """
        Generate a fault management alarm condition for agent alive
        """
        LOG.debug("Report agent fault: {}".format(agent['id']))
        self.fm_driver.report_agent_fault(agent['host'], agent['id'])

    def clear_agent_fault(self, agent):
        """
        Clear a fault management alarm condition for agent alive
        """
        LOG.debug("Clear agent fault: {}".format(agent['id']))
        self.fm_driver.clear_agent_fault(agent['host'], agent['id'])

    def _redistribute_for_new_agent(self, context, topic):
        """
        Attempt to reschedule DHCP servers or routers if new agent comes up
        """
        network_reschedule_threshold = cfg.CONF.network_reschedule_threshold
        router_reschedule_threshold = cfg.CONF.router_reschedule_threshold
        try:
            if topic == topics.DHCP_AGENT:
                plugin = directory.get_plugin()
                plugin.redistribute_networks(
                    context,
                    (lambda a, b: a > b + network_reschedule_threshold))
            elif topic == topics.L3_AGENT:
                plugin = directory.get_plugin(plugin_constants.L3)
                if utils.is_extension_supported(
                        plugin, lib_constants.L3_AGENT_SCHEDULER_EXT_ALIAS):
                    plugin.redistribute_routers(
                        context,
                        (lambda a, b: a > b + router_reschedule_threshold))
        except Exception as e:
            LOG.error("{} redistribution failed, {}".format(topic, e))
            return
