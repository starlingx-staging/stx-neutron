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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#

from datetime import datetime
from datetime import timedelta
import itertools
import time

from neutron_lib.api.definitions import provider_net as provider
from neutron_lib.api import validators
from neutron_lib.db import model_base
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import uuidutils
import six

import sqlalchemy as sa
from sqlalchemy import and_
from sqlalchemy import orm
from sqlalchemy.orm import contains_eager
from sqlalchemy.orm import exc
from sqlalchemy.sql.expression import literal_column

from neutron._i18n import _
from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import api as db_api
from neutron.db.models import segment as segments_model
from neutron.db import models_v2
from neutron.db import segments_db
from neutron.drivers import fm
from neutron.extensions import wrs_provider as ext_providernet
from neutron.plugins.ml2.drivers.l2pop import db as l2pop_db


LOG = logging.getLogger(__name__)

PNET_CONNECTIVITY_OPTS = [
    cfg.BoolOpt('pnet_audit_enabled', default=True,
               help=_('Whether to enable the provider network audit.')),
    cfg.IntOpt('pnet_audit_interval', default=1800,
               help=_('How frequently to run connectivity audits.')),
    cfg.BoolOpt('pnet_audit_schedule_by_event', default=True,
               help=_('Whether to schedule based on neutron events.')),
    cfg.IntOpt('pnet_audit_startup_delay', default=300,
               help=_('Delay before first audit.')),
    cfg.IntOpt('pnet_audit_timeout', default=120,
               help=_('Timeout if no results are received from compute.')),
    cfg.IntOpt('pnet_audit_batch_size', default=10,
               help=_('Number of segments to test in individual audit.')),
    cfg.IntOpt('pnet_audit_number_of_masters', default=2,
               help=_('Number of compute nodes to serve as masters.')),
]

cfg.CONF.register_opts(PNET_CONNECTIVITY_OPTS, "pnet_connectivity")


class ProviderNetConnectivityState(model_base.BASEV2):
    """Represents VXLAN specific data for a provider network."""
    __tablename__ = 'providernet_connectivity_states'

    providernet_connectivity_state = sa.Enum(
        constants.PROVIDERNET_CONNECTIVITY_UNKNOWN,
        constants.PROVIDERNET_CONNECTIVITY_PASS,
        constants.PROVIDERNET_CONNECTIVITY_FAIL,
        name='pnet_connectivity_state_enum'
    )

    # hostname of compute node this state data is for
    host_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('hosts.id', ondelete='CASCADE'),
        primary_key=True, nullable=False)

    # n-to-1 relationship back to provider network table
    providernet_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('providernets.id', ondelete='CASCADE'),
        primary_key=True, nullable=False)

    # Starting segmentation ID of this batch of network segments
    segmentation_id = sa.Column(
        sa.String(36), primary_key=True,
        nullable=False)

    # hostname of compute-master node
    master_host_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('hosts.id', ondelete='CASCADE'),
        primary_key=True, nullable=False)

    # Details of test being run
    test_details = sa.Column(sa.String(255), nullable=True)

    # connectivity state from compute to this master node for this range
    master_connectivity_state = sa.Column(providernet_connectivity_state,
                                          nullable=False)

    # UUID assigned to this audit
    audit_uuid = sa.Column(sa.String(36), nullable=False)

    # the time when last updated
    updated_at = sa.Column(sa.DateTime, nullable=False)

    def __init__(self, host_id, providernet_id, segmentation_id,
                 master_host_id, test_details, master_connectivity_state,
                 audit_uuid, updated_at):
        self.host_id = host_id
        self.providernet_id = providernet_id
        self.segmentation_id = segmentation_id
        self.master_host_id = master_host_id
        self.test_details = test_details
        self.master_connectivity_state = master_connectivity_state
        self.audit_uuid = audit_uuid
        self.updated_at = updated_at

    def __repr__(self):
        return "<ProviderNetConnectivityState(%s,%s,%s,%s,%s,,%s,%s,%s)>" % (
            self.host_id,
            self.providernet_id,
            self.segmentation_id,
            self.master_host_id,
            self.test_details,
            str(self.master_connectivity_state),
            self.audit_uuid,
            self.updated_at
        )


class ProviderNetRangeVxLan(model_base.BASEV2, model_base.HasId):
    """Represents VXLAN specific data for a provider network."""
    __tablename__ = 'providernet_range_vxlans'

    # IP address of the multicast group
    group = sa.Column(sa.String(64), nullable=True)

    # Destination DP port value for all instances
    port = sa.Column(sa.Integer, default=constants.DEFAULT_VXLAN_UDP_PORT,
                     nullable=False)
    # Time-to-live value for all instances
    ttl = sa.Column(sa.Integer, default=constants.DEFAULT_VXLAN_TTL,
                    nullable=False)
    # defines dynamic learning with multicast is enable/disabled
    mode = sa.Column(sa.String(32),
                     default=constants.PROVIDERNET_VXLAN_DYNAMIC,
                     nullable=False)

    # 1-to-1 relationship back to provider network range table
    providernet_range_id = sa.Column(sa.String(36),
                                     sa.ForeignKey('providernet_ranges.id'))

    def __init__(self, group, port, ttl, mode, providernet_range_id=None):
        self.group = group if validators.is_attr_set(group) else None
        self.port = port
        self.ttl = ttl
        self.mode = mode
        self.providernet_range_id = providernet_range_id

    def __repr__(self):
        return "<ProviderNetRangeVxLan(%s,%s,%s,%s,%s)>" % (
            self.group, self.port, self.ttl, self.mode,
            self.providernet_range_id)


class ProviderNetRange(model_base.BASEV2, model_base.HasId,
                       model_base.HasProject):
    """Represents provider network segmentation id range data."""
    __tablename__ = 'providernet_ranges'

    # user-defined provider network segmentation id range name
    name = sa.Column(sa.String(255), nullable=True)

    # user-defined provider network segmentation id range description
    description = sa.Column(sa.String(255), nullable=True)

    # defines whether multiple tenants can use this provider network range
    shared = sa.Column(sa.Boolean, default=True, nullable=False)

    # minimum segmentation id value
    minimum = sa.Column(sa.Integer, default=0)

    # maximum segmentation id value
    maximum = sa.Column(sa.Integer, default=0)

    # n-to-1 relationship back to provider network table
    providernet_id = sa.Column(sa.String(36), sa.ForeignKey('providernets.id'))

    # 1-to-1 relationship to provider network VLAN per-range data table
    vxlan = orm.relationship(
        ProviderNetRangeVxLan,
        uselist=False,
        backref="providernet_range",
        cascade="all, delete-orphan")

    def __init__(self, id, name, description, shared, minimum, maximum,
                 providernet_id, tenant_id=None):
        self.id = id
        self.name = name
        self.description = description
        self.minimum = minimum
        self.maximum = maximum
        self.providernet_id = providernet_id
        self.shared = shared
        if not self.shared:
            self.tenant_id = tenant_id
        else:
            self.tenant_id = None

    def __repr__(self):
        return "<ProviderNetRange(%s,%s,%s,%s,%s,%s - %s,%s)>" % (
            self.id, self.name, self.description, str(self.shared),
            self.tenant_id, self.providernet_id, self.minimum, self.maximum)


class ProviderNet(model_base.BASEV2, model_base.HasId):
    """Represents provider network configuration data."""
    __tablename__ = 'providernets'

    # user-defined provider network name
    name = sa.Column(sa.String(255), unique=True, nullable=False)

    # user-defined provider network description
    description = sa.Column(sa.String(255), nullable=True)

    # defines the maximum transmit unit on this provider network
    mtu = sa.Column(sa.Integer, default=constants.DEFAULT_MTU, nullable=False)

    # defines the status of the providernet (i.e., whether it is connected to
    # any nodes)
    status = sa.Column(sa.String(16))

    # defines whether the provider network is capable of accepting vlan tagged
    # packets from the tenant.
    vlan_transparent = sa.Column(sa.Boolean, default=False,
                                 server_default=sa.sql.false(),
                                 nullable=False)

    # provider network type
    type = sa.Column(sa.Enum(constants.PROVIDERNET_FLAT,
                             constants.PROVIDERNET_VLAN,
                             constants.PROVIDERNET_VXLAN,
                             constants.PROVIDERNET_GRE,
                             name='providernet_types'),
                     default=constants.PROVIDERNET_FLAT, nullable=False)

    # 1-to-n relationship to provider network segmentation id range table
    ranges = orm.relationship(
        ProviderNetRange,
        backref="providernet",
        cascade="all, delete-orphan")

    def __init__(self, id, name, description, status, type,
                 mtu=constants.DEFAULT_MTU, vlan_transparent=False):
        self.id = id
        self.name = name
        self.description = description
        self.status = status
        self.type = type
        self.mtu = mtu
        self.vlan_transparent = vlan_transparent

    def __repr__(self):
        return "<ProviderNet(%s,%s,%s,%s,%s,%s,%s)>" % (
            self.id, self.name, self.description,
            str(self.status), self.type, self.mtu, self.vlan_transparent)


class ProvidernetIndividualConnectivityTest(object):

    def __init__(self, audit_uuid, providernet_id,
                 providernet_name, providernet_type,
                 segments, extra_data):
        self.audit_uuid = audit_uuid
        self.providernet_id = providernet_id
        self.providernet_type = providernet_type
        self.providernet_name = providernet_name
        self.segments = segments
        self.extra_data = extra_data


class ProviderNetDbMixin(ext_providernet.ProviderNetPluginBase):
    """
    Mixin class to add the provider network extension to the db_plugin_base_v2.
    """
    fm_driver = fm.NoopFmDriver()
    pnet_connectivity_notifier = None
    audit_results = []
    scheduled_audits = []
    raised_alarms = {}
    topic_pnet_connectivity_test_create = topics.get_topic_name(
            topics.PLUGIN,
            topics.PNET_CONNECTIVITY,
            topics.CREATE
    )

    def _get_providernet_by_id(self, context, id):
        try:
            query = self._model_query(context, ProviderNet)
            providernet = query.filter(ProviderNet.id == id).one()
        except exc.NoResultFound:
            raise ext_providernet.ProviderNetNotFoundById(id=id)
        return providernet

    def _get_providernet_by_name(self, context, name):
        try:
            query = self._model_query(context, ProviderNet)
            providernet = query.filter(ProviderNet.name == name).one()
        except exc.NoResultFound:
            raise ext_providernet.ProviderNetNotFoundByName(name=name)
        return providernet

    def get_providernet_by_id(self, context, id):
        try:
            return self._make_providernet_dict(
                self._get_providernet_by_id(context, id))
        except ext_providernet.ProviderNetNotFoundById:
            return None

    def get_providernet_by_name(self, context, name):
        try:
            return self._make_providernet_dict(
                self._get_providernet_by_name(context, name))
        except ext_providernet.ProviderNetNotFoundByName:
            return None

    def _make_providernet_segment_dict(self, providernet, fields=None):
        """
        Return a dictionary of fields relevant for describing a provider
        segment which is all of the provider network (and range) fields that
        are needed to determine how to implement the actual segment on a
        compute node.
        """
        res = {'id': providernet['id'],
               'name': providernet['name'],
               'description': providernet['description'],
               'type': providernet['type'],
               'status': providernet['status'],
               'mtu': providernet['mtu'],
               'vlan_transparent': providernet['vlan_transparent']}
        if providernet['type'] == constants.PROVIDERNET_VXLAN:
            vxlan = providernet['ranges'][0]['vxlan']
            res.update({'vxlan': {'group': vxlan['group'],
                                  'port': vxlan['port'],
                                  'ttl': vxlan['ttl'],
                                  'mode': vxlan['mode']}})
        return self._fields(res, fields)

    def _get_flat_providernet_segment_details(self, context, type, name):
        """
        Find a providernet by name and type.
        """
        with context.session.begin(subtransactions=True):
            query = self._model_query(context, ProviderNet)
            query = (query.
                     filter(ProviderNet.name == name).
                     filter(ProviderNet.type == type))
            providernet = query.one()
            return self._make_providernet_segment_dict(providernet)

    def _get_providernet_segment_details(self, context, type, name, id):
        """
        Find a providernet combination of provider+range+[vxlan] based on the
        segmentation id provided.  This will remove all unrelated ranges.
        """
        with context.session.begin(subtransactions=True):
            query = self._model_query(context, ProviderNet)
            query = (query.
                     join(ProviderNetRange,
                          and_((ProviderNetRange.providernet_id ==
                                ProviderNet.id),
                               and_(ProviderNetRange.minimum <= id,
                                    ProviderNetRange.maximum >= id))).
                     outerjoin(ProviderNetRangeVxLan).
                     filter(ProviderNet.name == name).
                     filter(ProviderNet.type == type))
            query = query.options(contains_eager(ProviderNet.ranges))
            providernet = query.one()
            return self._make_providernet_segment_dict(providernet)

    def get_providernet_segment_details(self, context, type, name, id):
        """
        Find a combination of provider+[range+[vxlan]] based on the
        segmentation id provided.  This will remove all unrelated ranges.
        """
        if type in [constants.PROVIDERNET_FLAT]:
            return self._get_flat_providernet_segment_details(
                context, type, name)
        else:
            return self._get_providernet_segment_details(
                context, type, name, id)

    def check_providernet_id_allowed(self, context, name, id):
        try:
            query = self._model_query(context, ProviderNetRange)
            query = (query.
                     filter(ProviderNet.name == name).
                     filter(ProviderNetRange.providernet_id == ProviderNet.id).
                     filter(ProviderNetRange.minimum <= id).
                     filter(ProviderNetRange.maximum >= id))
            query.one()
        except exc.NoResultFound:
            return False
        return True

    def _make_vxlan_dict(self, vxlan, fields=None):
        res = {'group': vxlan['group'],
               'port': vxlan['port'],
               'ttl': vxlan['ttl'],
               'mode': vxlan['mode']}
        return self._fields(res, fields)

    def _make_providernet_dict(self, providernet, fields=None):
        res = {'id': providernet['id'],
               'name': providernet['name'],
               'description': providernet['description'],
               'type': providernet['type'],
               'status': providernet['status'],
               'mtu': providernet['mtu'],
               'vlan_transparent': providernet['vlan_transparent']}
        res['ranges'] = [self._make_providernet_range_dict(r)
                         for r in providernet['ranges']]
        # filter out redundant fields
        for r in res['ranges']:
            r.pop('providernet_id', None)
            r.pop('providernet_name', None)
            r.pop('providernet_type', None)
        return self._fields(res, fields)

    def _validate_providernet_exists(self, context, name):
        try:
            self._get_providernet_by_name(context, name)
            raise ext_providernet.ProviderNetNameAlreadyExists(name=name)
        except ext_providernet.ProviderNetNotFoundByName:
            pass

    def _validate_providernet_create(self, context, providernet):
        providernet_data = providernet['providernet']
        self._validate_providernet_exists(context, providernet_data['name'])

    def _validate_providernet_update(self, context, providernet_id,
                                     providernet_data):
        if 'mtu' in providernet_data:
            providernet = self._get_providernet_by_id(context, providernet_id)
            pnet_mtu = providernet_data['mtu']
            pnet_name = providernet['name']
            filters = {
                provider.PHYSICAL_NETWORK: pnet_name,
            }
            fields = ['mtu']
            networks = self.get_networks(context, filters=filters,
                                         fields=fields)
            for network in networks:
                if pnet_mtu < network['mtu']:
                    msg = _("Requested MTU %s is too small") % pnet_mtu
                    raise n_exc.InvalidInput(error_message=msg)

    @db_api.retry_if_session_inactive()
    def create_providernet(self, context, providernet):
        providernet_data = providernet['providernet']
        res = {
            'id': providernet_data.get('id') or uuidutils.generate_uuid(),
            'type': providernet_data['type'],
            'name': providernet_data['name'],
            'description': providernet_data['description'],
            'mtu': providernet_data['mtu'],
            'status': constants.PROVIDERNET_DOWN,
            'vlan_transparent': providernet_data['vlan_transparent']}
        self._validate_providernet_create(context, providernet)
        with context.session.begin(subtransactions=True):
            providernet = ProviderNet(**res)
            context.session.add(providernet)
        self._report_providernet_fault(providernet)
        return self._make_providernet_dict(providernet)

    @db_api.retry_if_session_inactive()
    def update_providernet(self, context, id, providernet):
        providernet_data = providernet['providernet']
        self._validate_providernet_update(context, id, providernet_data)
        with context.session.begin(subtransactions=True):
            providernet = self._get_providernet_by_id(context, id)
            providernet.update(providernet_data)
        self.notify_schedule_audit_providernets(context, [id], by_event=True)
        return self._make_providernet_dict(providernet)

    @db_api.retry_if_session_inactive()
    def delete_providernet(self, context, id):
        with context.session.begin(subtransactions=True):
            providernet = self._get_providernet_by_id(context, id)
            context.session.delete(providernet)
            self._clear_providernet_fault(providernet)
            self.schedule_analyse_providernet_connectivity(context, id)

    @db_api.retry_if_session_inactive()
    def get_providernet(self, context, id, fields=None):
        providernet = self._get_providernet_by_id(context, id)
        return self._make_providernet_dict(providernet, fields)

    @db_api.retry_if_session_inactive()
    def get_providernets(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'providernet',
                                          limit, marker)
        return self._get_collection(
            context, ProviderNet, self._make_providernet_dict,
            filters=filters, fields=fields, sorts=sorts, limit=limit,
            marker_obj=marker_obj, page_reverse=page_reverse)

    def get_providernet_required_mtu(self, context, id, new_mtu=None):
        """
        Returns the MTU value required on a physical interface in order to
        support the specified provider network MTU.  See notes regarding
        VXLAN_MTU_OVERHEAD.
        """
        providernet = self.get_providernet(context, id)
        if providernet['type'] != constants.PROVIDERNET_VXLAN:
            # No additional overhead required for any other providernet
            # network type.  VLAN is not considered here because most
            # switches assume an extra 4 bytes are possible over the
            # configured MTU size in order to supported tagged packets.
            overhead = 0
        else:
            overhead = constants.VXLAN_MTU_OVERHEAD
        return (overhead + (new_mtu or providernet['mtu']))

    def get_providernet_types(self, context, filters=None, fields=None):
        return [{'type': constants.PROVIDERNET_FLAT,
                 'description':
                 _('Ethernet network without additional encapsulation')},
                {'type': constants.PROVIDERNET_VLAN,
                 'description':
                 _('802.1q encapsulated Ethernet network')},
                {'type': constants.PROVIDERNET_VXLAN,
                 'description':
                _('Virtual Extensible LAN encapsulated network')},
                ]

    def _get_providernet_range_by_id(self, context, id):
        try:
            query = self._model_query(context, ProviderNetRange)
            providernet_range = query.filter(ProviderNetRange.id == id).one()
        except exc.NoResultFound:
            raise ext_providernet.ProviderNetRangeNotFoundById(id=id)
        return providernet_range

    def get_providernet_range_by_id(self, context, id):
        try:
            return self._make_providernet_range_dict(
                self._get_providernet_range_by_id(context, id))
        except ext_providernet.ProviderNetRangeNotFoundById:
            return None

    def _make_providernet_range_dict(self, providernet_range, fields=None):
        res = {'id': providernet_range['id'],
               'name': providernet_range['name'],
               'description': providernet_range['description'],
               'shared': providernet_range['shared'],
               'tenant_id': providernet_range['tenant_id'],
               'minimum': providernet_range['minimum'],
               'maximum': providernet_range['maximum'],
               'providernet_name': providernet_range['providernet']['name'],
               'providernet_id': providernet_range['providernet']['id'],
               'providernet_type': providernet_range['providernet']['type']}
        if providernet_range['vxlan']:
            res['vxlan'] = self._make_vxlan_dict(
                providernet_range['vxlan'], fields=None)
        return self._fields(res, fields)

    def _validate_providernet_range_overlap(self, context, range):
        try:
            query = self._model_query(context, ProviderNetRange)
            query = (query.
                     filter(ProviderNetRange.providernet_id ==
                            range['providernet_id']).
                     filter(ProviderNetRange.id != range.get('id', '0')).
                     filter(and_(range['minimum'] <=
                                 ProviderNetRange.maximum,
                                 (range['maximum'] >=
                                  ProviderNetRange.minimum))))
            conflict = query.first()
            if conflict:
                raise ext_providernet.ProviderNetRangeOverlaps(
                    id=conflict['id'])
        except exc.NoResultFound:
            return

    def _validate_providernet_range_ttl_mismatch(self, context, range):
        try:
            query = self._model_query(context, ProviderNetRangeVxLan)
            query = (query.
                     join(ProviderNetRange,
                          (ProviderNetRange.id ==
                           ProviderNetRangeVxLan.providernet_range_id)).
                     filter(ProviderNetRange.providernet_id ==
                            range['providernet_id']).
                     filter(ProviderNetRange.id != range.get('id', '0')).
                     filter(ProviderNetRangeVxLan.mode == range['mode']).
                     filter(ProviderNetRangeVxLan.port == range['port']).
                     filter(ProviderNetRangeVxLan.ttl != range['ttl']))
            if validators.is_attr_set(range['group']):
                group = range['group']
                query = query.filter(ProviderNetRangeVxLan.group == group)
            conflict = query.first()
            if conflict:
                raise ext_providernet.ProviderNetRangeMismatchedTTL(
                    id=conflict['id'])
        except exc.NoResultFound:
            return

    def check_providernet_id(self, network_type, id):
        if network_type == constants.PROVIDERNET_FLAT:
            return False
        if network_type == constants.PROVIDERNET_VLAN:
            if (id < constants.MIN_VLAN_TAG or id > constants.MAX_VLAN_TAG):
                return False
            return True
        if network_type == constants.PROVIDERNET_VXLAN:
            if (id < constants.MIN_VXLAN_VNI or id > constants.MAX_VXLAN_VNI):
                return False
            return True
        return False

    def _validate_providernet_range_vlanid(self, context, range):
        if (int(range['minimum']) < constants.MIN_VLAN_TAG or
            int(range['maximum']) < constants.MIN_VLAN_TAG or
            int(range['minimum']) > constants.MAX_VLAN_TAG or
            int(range['maximum']) > constants.MAX_VLAN_TAG):
            raise ext_providernet.ProviderNetVlanIdOutOfRange(
                minimum=range['minimum'],
                maximum=range['maximum'],
                threshold=constants.MAX_VLAN_TAG)

    def _validate_providernet_range_vxlanid(self, context, range):
        if (int(range['minimum']) < constants.MIN_VXLAN_VNI or
            int(range['maximum']) < constants.MIN_VXLAN_VNI or
            int(range['minimum']) > constants.MAX_VXLAN_VNI or
            int(range['maximum']) > constants.MAX_VXLAN_VNI):
            raise ext_providernet.ProviderNetVxlanIdOutOfRange(
                minimum=range['minimum'],
                maximum=range['maximum'],
                threshold=constants.MAX_VXLAN_VNI)

    def _validate_providernet_range_order(self, context, range):
        if (int(range['minimum']) > int(range['maximum'])):
            raise ext_providernet.ProviderNetRangeOutOfOrder(
                minimum=range['minimum'],
                maximum=range['maximum'])

    def _validate_providernet_range_attrs(self, context, providernet, range):
        if providernet['type'] == constants.PROVIDERNET_VXLAN:
            if range['mode'] == constants.PROVIDERNET_VXLAN_DYNAMIC:
                if not validators.is_attr_set(range.get('group')):
                    raise ext_providernet.ProviderNetWithoutMulticastGroup()
            else:
                if validators.is_attr_set(range.get('group')):
                    raise ext_providernet.\
                        ProviderNetNonDynamicWithMulticastGroup()
            if not validators.is_attr_set(range.get('ttl')):
                raise ext_providernet.ProviderNetWithoutTTL()
            if not validators.is_attr_set(range.get('port')):
                raise ext_providernet.ProviderNetWithoutPort()
        else:
            if validators.is_attr_set(range.get('group')):
                raise ext_providernet.ProviderNetWithMulticastGroup()
            if validators.is_attr_set(range.get('ttl')):
                raise ext_providernet.ProviderNetWithTTL()

    def _validate_providernet_range(self, context, providernet, range):
        if providernet.type == constants.PROVIDERNET_FLAT:
            raise ext_providernet.ProviderNetRangeNotAllowedOnFlatNet(
                id=providernet.id)
        self._validate_providernet_range_order(context, range)
        self._validate_providernet_range_attrs(context, providernet, range)
        if providernet.type == constants.PROVIDERNET_VLAN:
            self._validate_providernet_range_vlanid(context, range)
        if providernet.type == constants.PROVIDERNET_VXLAN:
            self._validate_providernet_range_vxlanid(context, range)
            self._validate_providernet_range_ttl_mismatch(context, range)
        self._validate_providernet_range_overlap(context, range)

    def create_providernet_range(self, context, providernet_range):
        range_data = providernet_range['providernet_range']
        providernet = self._get_providernet_by_id(context,
                                                  range_data['providernet_id'])
        self._validate_providernet_range(context, providernet, range_data)
        res = {'id': range_data.get('id') or uuidutils.generate_uuid(),
               'name': range_data['name'],
               'description': range_data['description'],
               'shared': range_data['shared'],
               'minimum': range_data['minimum'],
               'maximum': range_data['maximum'],
               'providernet_id': range_data['providernet_id']}
        if not range_data['shared']:
            res['tenant_id'] = range_data['tenant_id']
        with context.session.begin(subtransactions=True):
            providernet_range = ProviderNetRange(**res)
            context.session.add(providernet_range)
            if providernet['type'] == constants.PROVIDERNET_VXLAN:
                res = {'group': range_data.get('group'),
                       'port': range_data['port'],
                       'ttl': range_data.get('ttl'),
                       'mode': range_data.get('mode'),
                       'providernet_range_id': providernet_range.id}
                vxlan = ProviderNetRangeVxLan(**res)
                context.session.add(vxlan)
        self.notify_schedule_audit_providernets(
            context, [providernet_range['providernet_id']], by_event=True
        )
        return self._make_providernet_range_dict(providernet_range)

    def _add_unchanged_range_attributes(self, updates, existing):
        """
        Adds data for unspecified fields on incoming update requests.  Since
        incoming requests are flat the existing data is also flattened by
        updating the topmost attributes with lower level attributes.
        """
        for key, value in six.iteritems(existing):
            if isinstance(value, dict):
                for subkey, subvalue in six.iteritems(value):
                    updates.setdefault(subkey, subvalue)
            else:
                updates.setdefault(key, value)
        return updates

    @db_api.retry_if_session_inactive()
    def update_providernet_range(self, context, id, providernet_range):
        updated_data = providernet_range['providernet_range']
        with context.session.begin(subtransactions=True):
            providernet_range = self._get_providernet_range_by_id(context, id)
            self._set_connectivity_data_to_unknown_by_pnet_range(
                context, providernet_range
            )
            providernet = self._get_providernet_by_id(
                context, providernet_range['providernet_id'])
            old_data = self._make_providernet_range_dict(providernet_range)
            new_data = self._add_unchanged_range_attributes(updated_data,
                                                            old_data)
            self._validate_providernet_range(context, providernet, new_data)
            providernet_range.update(new_data)
            if providernet_range.vxlan:
                vxlan = {'group': new_data['group'],
                         'port': new_data['port'],
                         'ttl': new_data['ttl'],
                         'mode': new_data['mode']}
                providernet_range.vxlan.update(vxlan)
        self.notify_schedule_audit_providernets(
            context, [providernet_range['providernet_id']], by_event=True
        )
        return self._make_providernet_range_dict(providernet_range)

    @db_api.retry_if_session_inactive()
    def delete_providernet_range(self, context, id):
        with context.session.begin(subtransactions=True):
            providernet_range = self._get_providernet_range_by_id(context, id)
            self._set_connectivity_data_to_unknown_by_pnet_range(
                context, providernet_range
            )
            context.session.delete(providernet_range)
        self.notify_schedule_audit_providernets(
            context, [providernet_range['providernet_id']], by_event=True
        )

    @db_api.retry_if_session_inactive()
    def get_providernet_range(self, context, id, fields=None):
        providernet_range = self._get_providernet_range_by_id(context, id)
        return self._make_providernet_range_dict(providernet_range, fields)

    @db_api.retry_if_session_inactive()
    def get_providernet_ranges(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'providernet_range',
                                          limit, marker)
        return self._get_collection(
            context, ProviderNetRange, self._make_providernet_range_dict,
            filters=filters, fields=fields, sorts=sorts, limit=limit,
            marker_obj=marker_obj, page_reverse=page_reverse)

    def _list_networks_on_providernet(self, context, name,
                                      filters=None, fields=None):
        # Produce a list of bindings for networks
        networks = (context.session.query(
            models_v2.Network.id,
            models_v2.Network.name,
            literal_column("0").label("tenant_vlan_id"),
            ProviderNet.type,
            segments_model.NetworkSegment.segmentation_id,
            ProviderNetRange))
        networks = (networks
            .select_from(models_v2.Network)
            .join(segments_model.NetworkSegment,
                  models_v2.Network.id ==
                  segments_model.NetworkSegment.network_id)
            .join(ProviderNet,
                  segments_model.NetworkSegment
                  .physical_network ==
                  ProviderNet.name)
            .join(ProviderNetRange,
                  and_(ProviderNet.id ==
                       ProviderNetRange.providernet_id,
                       and_(segments_model.NetworkSegment.segmentation_id >=
                            ProviderNetRange.minimum,
                            segments_model.NetworkSegment.segmentation_id <=
                            ProviderNetRange.maximum)))
            .filter(segments_model.NetworkSegment.physical_network ==
                    name))
        # Produce a list of bindings for subnets
        subnets = context.session.query(
            models_v2.Network.id,
            models_v2.Network.name,
            models_v2.Subnet.vlan_id.label("tenant_vlan_id"),
            ProviderNet.type,
            segments_db.SubnetSegment.segmentation_id,
            ProviderNetRange)
        subnets = (subnets
            .select_from(models_v2.Network)
            .join(models_v2.Subnet,
                  models_v2.Network.id ==
                  models_v2.Subnet.network_id)
            .join(segments_db.SubnetSegment,
                  models_v2.Subnet.id ==
                  segments_db.SubnetSegment.subnet_id)
            .join(ProviderNet,
                  (ProviderNet.name ==
                   segments_db.SubnetSegment.physical_network))
            .join(ProviderNetRange,
                  and_(ProviderNet.id ==
                       ProviderNetRange.providernet_id,
                       and_(segments_db.SubnetSegment.segmentation_id >=
                            ProviderNetRange.minimum,
                            segments_db.SubnetSegment.segmentation_id <=
                            ProviderNetRange.maximum)))
            .filter(models_v2.Subnet.vlan_id != 0)
            .filter(segments_db.SubnetSegment.physical_network ==
                    name)
            .distinct(models_v2.Subnet.vlan_id))
        query = networks.union(subnets)
        columns = ['id', 'name', 'vlan_id',
                   'providernet_type', 'segmentation_id', 'range']
        results = []
        for entry in query.order_by(models_v2.Network.id,
                                    "tenant_vlan_id").all():
            range_data = entry[5]
            res = dict((k, entry[i])
                       for i, k in enumerate(columns) if k not in ['range'])
            vxlan = range_data.get('vxlan')
            attrs = self._make_vxlan_dict(vxlan) if vxlan else {}
            res.update({'vxlan': attrs})
            res = self._fields(res, fields)
            results.append(res)
        return results

    @db_api.retry_if_session_inactive()
    def list_networks_on_providernet(self, context, id,
                                     filters=None, fields=None,
                                     sorts=None, limit=None,
                                     marker=None, page_reverse=False):
        results = []
        try:
            # Determine if the id is a UUID or provider network name
            providernet = self._get_providernet_by_id(context, id)
        except ValueError:
            # Query by name to determine if it exists
            providernet = self._get_providernet_by_name(context, id)
        try:
            name = providernet.get("name")
            results = self._list_networks_on_providernet(
                context, name, filters, fields)
        except exc.NoResultFound:
            results = []
        return {"networks": results}

    def is_static_vxlan_segment(self, context, name, segmentation_id):
        """Determines whether a given VXLAN segment is configured as static."""
        segment = self._get_providernet_segment_details(
            context, constants.PROVIDERNET_VXLAN, name, segmentation_id)
        if segment['vxlan']['mode'] == constants.PROVIDERNET_VXLAN_STATIC:
            return True
        return False

    def _report_providernet_fault(self, providernet):
        """
        Generate a fault management alarm condition for provider network status
        """
        LOG.debug("Report provider network fault: "
                  "{}".format(providernet['id']))
        self.fm_driver.report_providernet_fault(providernet['id'])

    def _clear_providernet_fault(self, providernet):
        """
        Clear a fault management alarm condition for provider network status
        """
        LOG.debug("Clear provider network fault: {}".format(providernet['id']))
        self.fm_driver.clear_providernet_fault(providernet['id'])

    def _report_clear_providernet_connectivity_fault(self, providernet_id,
                                                     hostname, segments):
        """
        Generate or clar a fault management alarm condition for
        provider network connectivity status.
        """
        # cache alarms to reduce calls to fm_api
        if self.raised_alarms.get((providernet_id, hostname)) == segments:
            return
        self.raised_alarms[(providernet_id, hostname)] = segments
        if segments:
            LOG.debug("Report provider network connectivity fault: "
                      "{}".format(providernet_id))
            self.fm_driver.report_providernet_connectivity_fault(
                providernet_id, hostname, segments
            )
        else:
            LOG.debug("Clear provider network connectivity fault: "
                      "{}".format(providernet_id))
            self.fm_driver.clear_providernet_connectivity_fault(
                providernet_id, hostname
            )

    def _providernet_vxlan_segment_exists(self, context,
                                          providernet_id, range_id):
        query = context.session.query(ProviderNetRange)
        query = query.filter(
            ProviderNetRange.providernet_id == providernet_id,
            ProviderNetRange.id == range_id,
        )
        return bool(query.count())

    def _providernet_vlan_segment_exists(self, context,
                                         providernet_id, segmentation_id):
        query = context.session.query(ProviderNetRange)
        query = query.filter(
            ProviderNetRange.providernet_id == providernet_id,
            ProviderNetRange.minimum <= segmentation_id,
            ProviderNetRange.maximum >= segmentation_id,
        )
        return bool(query.count())

    def _providernet_segment_exists(self, context,
                                    providernet_id, segmentation_id):
        """
        Return true if providernet has range covering specified segment
        """
        providernet = self.get_providernet_by_id(context, providernet_id)
        if not providernet:
            return False
        elif providernet['type'] == constants.PROVIDERNET_FLAT:
            return True
        elif providernet['type'] == constants.PROVIDERNET_VXLAN:
            return self._providernet_vxlan_segment_exists(context,
                                                          providernet_id,
                                                          segmentation_id)
        elif providernet['type'] == constants.PROVIDERNET_VLAN:
            return self._providernet_vlan_segment_exists(context,
                                                         providernet_id,
                                                         int(segmentation_id))

        # Should never get here, so fail if it does.
        assert False

    def update_connectivity_state_entry(self, context, host_id,
                                        providernet_id, segmentation_id,
                                        master_host_id, test_details,
                                        master_connectivity_state,
                                        audit_uuid):
        """
        Replaces given entry in pnet connectivity table
        """
        res = {
            'host_id': str(host_id),
            'providernet_id': str(providernet_id),
            'segmentation_id': str(segmentation_id),
            'master_host_id': str(master_host_id),
            'test_details': str(test_details),
            'master_connectivity_state': master_connectivity_state,
            'audit_uuid': str(audit_uuid),
            'updated_at': datetime.now()}
        with context.session.begin(subtransactions=True):
            providernet_state = ProviderNetConnectivityState(**res)
            query = context.session.query(ProviderNetConnectivityState)
            query = query.filter(
                ProviderNetConnectivityState.host_id == host_id,
                ProviderNetConnectivityState.providernet_id == providernet_id,
                ProviderNetConnectivityState.segmentation_id ==
                str(segmentation_id),
                ProviderNetConnectivityState.master_host_id == master_host_id,
            )
            # Verify that providernet still has range for segment
            if self._providernet_segment_exists(context, providernet_id,
                                                segmentation_id):
                # only delete if entry already exists
                if query.count():
                    context.session.delete(query.first())
                context.session.add(providernet_state)

    def _find_primary_master(self, context, providernet_id):
        """Returns the id of the master with most connected slaves"""
        with context.session.begin(subtransactions=True):
            query = context.session.query(ProviderNetConnectivityState)
            query = query.filter(
                ProviderNetConnectivityState.providernet_id == providernet_id,
            )
            masters = query.distinct(
                ProviderNetConnectivityState.master_host_id
            ).all()

            # find the master with the highest level of connectivity
            highest_pass_count = -1
            highest_pass_master = None
            for master in masters:
                master_dict = self.get_host(context, master.master_host_id)
                if (master_dict['availability'] != constants.HOST_UP):
                    continue
                count = query.filter(
                    ProviderNetConnectivityState.master_host_id ==
                    master.master_host_id,
                    (ProviderNetConnectivityState.master_connectivity_state ==
                     constants.PROVIDERNET_CONNECTIVITY_PASS),
                ).count()
                if count > highest_pass_count:
                    highest_pass_count = count
                    highest_pass_master = master.master_host_id
        return highest_pass_master

    def _pnet_id_to_master(self, context, pnet_id):
        """Cache pnet IDs to avoid lookups for providernet types"""
        if pnet_id in self._pnet_id_master_mapping:
            return self._pnet_id_master_mapping[pnet_id]
        pnet_master = self._find_primary_master(context, pnet_id)
        self._pnet_id_master_mapping[pnet_id] = pnet_master
        return pnet_master

    def _make_providernet_connectivity_state_dict(
        self, context, providernet_connectivity_state, fields=None
    ):
        state = providernet_connectivity_state.ProviderNetConnectivityState
        host_id = state.host_id
        host_name = providernet_connectivity_state.Host.name
        master_host_id = state.master_host_id
        master_host_name = providernet_connectivity_state.Master.name
        providernet_id = state.providernet_id
        providernet_name = providernet_connectivity_state.ProviderNet.name
        providernet_type = str(providernet_connectivity_state.ProviderNet.type)
        segmentation_id = state.segmentation_id
        status = str(state.master_connectivity_state)
        message = state.test_details
        audit_uuid = state.audit_uuid
        updated_at = str(state.updated_at)
        res = {'host_id': host_id,
               'host_name': host_name,
               'master_host_id': master_host_id,
               'master_host_name': master_host_name,
               'providernet_id': providernet_id,
               'providernet_name': providernet_name,
               'type': providernet_type,
               'segmentation_id': segmentation_id,
               'status': status,
               'message': message,
               'audit_uuid': audit_uuid,
               'updated_at': updated_at}
        if res['type'] == constants.PROVIDERNET_FLAT:
            res.pop('segmentation_id')
        if res['type'] == constants.PROVIDERNET_VXLAN:
            segment_min_max = self._list_segments(
                [self.get_providernet_range_by_id(context,
                                                  res.pop('segmentation_id'))]
            )
            res['segmentation_id'] = segment_min_max
        return self._fields(res, fields)

    def get_providernet_connectivity_tests(self, context,
                                           filters=None, fields=None):
        if not cfg.CONF.pnet_connectivity.pnet_audit_enabled:
            raise ext_providernet.ProviderNetTestingDisabled()
        modified_filters = {}
        if not filters:
            filters = []
        if 'providernet_name' in filters and filters['providernet_name']:
            modified_filters['providernet_id'] = []
            for providernet_name in filters['providernet_name']:
                modified_filters['providernet_id'].append(
                    self.get_providernet_by_name(context,
                                                 providernet_name)['id']
                )
        elif 'providernet_id' in filters and filters['providernet_id']:
            modified_filters['providernet_id'] = filters['providernet_id']
        if 'host_name' in filters and filters['host_name']:
            modified_filters['host_id'] = []
            for host_name in filters['host_name']:
                modified_filters['host_id'].append(
                    self.get_host_uuid(context, host_name)
                )
        elif 'host_id' in filters and filters['host_id']:
            modified_filters['host_id'] = filters['host_id']
        if 'audit_uuid' in filters and filters['audit_uuid']:
            modified_filters['audit_uuid'] = filters['audit_uuid']
        if 'segmentation_id' in filters and filters['segmentation_id']:
            modified_filters['segmentation_id'] = []
            for segmentation_id in filters['segmentation_id']:
                try:
                    modified_filters['segmentation_id'].append(
                        str(int(segmentation_id))
                    )
                except Exception:
                    LOG.exception("segmentation_id {} is not an int".format(
                                  segmentation_id))
                    continue

        self._pnet_id_master_mapping = {}
        query = self.get_providernet_connectivity_query(context)

        if 'providernet_id' in modified_filters:
            query = query.filter(
                ProviderNetConnectivityState.providernet_id.in_(
                    modified_filters['providernet_id']
                )
            )
        if 'host_id' in modified_filters:
            query = query.filter(
                ProviderNetConnectivityState.host_id.in_(
                    modified_filters['host_id']
                )
            )
        if 'audit_uuid' in modified_filters:
            query = query.filter(
                ProviderNetConnectivityState.audit_uuid.in_(
                    modified_filters['audit_uuid']
                )
            )

        if 'segmentation_id' in modified_filters:
            query = query.filter(
                ProviderNetConnectivityState.segmentation_id.in_(
                    modified_filters['segmentation_id']
                )
            )

        results = []
        for result in query:
            master_host_id = result.ProviderNetConnectivityState.master_host_id
            providernet_id = result.ProviderNetConnectivityState.providernet_id
            if (master_host_id == self._pnet_id_to_master(context,
                                                          providernet_id)):
                results.append(
                    self._make_providernet_connectivity_state_dict(context,
                                                                   result,
                                                                   fields)
                )
        return results

    def create_providernet_connectivity_test(self, context,
                                             providernet_connectivity_test):
        if not cfg.CONF.pnet_connectivity.pnet_audit_enabled:
            raise ext_providernet.ProviderNetTestingDisabled()
        # Schedule audits for this providernet
        test = providernet_connectivity_test["providernet_connectivity_test"]
        providernet_id = None
        if 'providernet_name' in test and test['providernet_name']:
            providernet_name = test['providernet_name']
            providernet = self.get_providernet_by_name(context,
                                                       providernet_name)
            providernet_id = providernet['id']
        elif 'providernet_id' in test and test['providernet_id']:
            providernet_id = test['providernet_id']
        if providernet_id:
            if 'segmentation_id' in test and test['segmentation_id']:
                segmentation_ids = [int(test['segmentation_id'])]
            else:
                segmentation_ids = []

            audit_uuid = self.notify_schedule_audit_providernets(
                context, [providernet_id], segmentation_ids
            )
        # Schedule audits for all providernets on this host
        elif 'host_name' in test and test['host_name']:
            host_name = test['host_name']
            host_uuid = self.get_host_uuid(context, host_name)
            providernet_ids = self.get_providernets_on_host(context, host_uuid)
            audit_uuid = self.notify_schedule_audit_providernets(
                context, providernet_ids
            )
        elif 'host_id' in test and test['host_id']:
            host_uuid = test['host_id']
            providernet_ids = self.get_providernets_on_host(context, host_uuid)
            audit_uuid = self.notify_schedule_audit_providernets(
                context, providernet_ids
            )
        else:
            providernets = self.get_providernets(context, fields=["id"])
            providernet_ids = [providernet_details['id'] for
                               providernet_details in providernets]
            audit_uuid = self.notify_schedule_audit_providernets(
                context, providernet_ids
            )
        return {"audit_uuid": audit_uuid}

    def _group_segmentation_id_list(self, segmentation_ids):
        """Takes a list of integers and groups them into ranges"""
        if len(segmentation_ids) < 1:
            return ""
        sorted_segmentation_ids = sorted(
            [int(segmentation_id) for segmentation_id in segmentation_ids]
        )
        grouped_ids = [tuple(g[1]) for g in itertools.groupby(
            enumerate(sorted_segmentation_ids), lambda (i, n): i - n
        )]
        msg = ", ".join(
            [(("%s-%s" % (g[0][1], g[-1][1])) if g[0][1] != g[-1][1]
             else ("%s" % g[0][1])) for g in grouped_ids]
        )
        return msg

    def _list_segments(self, segments):
        """Takes a list of segments, and outputs them as a string"""
        min_max_dict = {}
        msg = ""
        for segment in segments:
            if segment:
                min_max_dict[segment['minimum']] = segment['maximum']
        for minimum, maximum in sorted(six.iteritems(min_max_dict)):
            if minimum == maximum:
                new_msg = str(minimum)
            else:
                new_msg = "%d-%d" % (minimum, maximum)
            if msg:
                msg = "%s, %s" % (msg, new_msg)
            else:
                msg = new_msg
        return msg

    def _segments_to_report(self, context, providernet_id, segments):
        """Returns a string representation of the list of segments"""
        providernet_type = self.get_providernet_by_id(context,
                                                      providernet_id)['type']
        if segments:
            msg = " segmentation ranges "
        else:
            return ""
        if providernet_type == constants.PROVIDERNET_VLAN:
            msg = self._group_segmentation_id_list(segments)
        elif providernet_type == constants.PROVIDERNET_VXLAN:
            msg = self._list_segments(
                [self.get_providernet_range_by_id(context, segment)
                    for segment in segments]
            )
        elif providernet_type == constants.PROVIDERNET_FLAT:
            return "flat"
        return msg

    def _analyse_providernet_connectivity_database(self, context,
                                                   providernet_ids):
        """
        Analyses the providernet connectivity database and raises or clears
         alarms as appropriate based on changes since last analysis.
        """
        # Run test by providernet
        for providernet in providernet_ids:
            primary_master = self._find_primary_master(context, providernet)
            with context.session.begin(subtransactions=True):
                query = context.session.query(ProviderNetConnectivityState)
                failures = query.filter(
                    ProviderNetConnectivityState.providernet_id == providernet,
                    ProviderNetConnectivityState.master_host_id ==
                    primary_master,
                    ProviderNetConnectivityState.master_connectivity_state ==
                    constants.PROVIDERNET_CONNECTIVITY_FAIL,
                ).all()

                # Construct a dictionary mapping hosts to lists of failures
                hosts = self.get_providernet_hosts(context, providernet)
                failures_by_host = {host: [] for host in hosts}
                for failure in failures:
                    host = failure.host_id
                    segment = failure.segmentation_id
                    failures_by_host[host].append(segment)

                # Loop through results and raise alarms
                for host, segments in six.iteritems(failures_by_host):
                    hostname = self.get_hostname(context, host)
                    segments_string = self._segments_to_report(context,
                                                               providernet,
                                                               segments)
                    self._report_clear_providernet_connectivity_fault(
                        providernet, hostname, segments_string
                    )
        # After analysis, remove outdated entries
        self._remove_deprecated_connectivity_state_entries(context)

    def _count_hosts_reporting_entry(self, context, providernet_id,
                                     segmentation_id, audit_uuid):
        """
        Counts the number of compute nodes reporting back for this audit
        """
        with context.session.begin(subtransactions=True):
            query = context.session.query(ProviderNetConnectivityState)
            query = query.filter(
                ProviderNetConnectivityState.providernet_id == providernet_id,
                ProviderNetConnectivityState.segmentation_id ==
                segmentation_id,
                ProviderNetConnectivityState.audit_uuid == audit_uuid,
            ).distinct(ProviderNetConnectivityState.host_id)
            # only delete if exists
            host_count = query.count()
        return host_count

    def schedule_audit_flat_providernet(self, context, audit_uuid,
                                        providernet_id):
        """
        Runs audit for given flat providernet with segmentation ID set to 0
        """
        # list of audits to give to scheduler
        pending_audits = []
        providernet = self.get_providernet_by_id(context, providernet_id)
        if not providernet:
            return pending_audits
        mtu = providernet['mtu']

        audit = ProvidernetIndividualConnectivityTest(
            audit_uuid, providernet_id, providernet['name'],
            constants.PROVIDERNET_FLAT,
            [constants.PROVIDERNET_FLAT], {ext_providernet.MTU: mtu}
        )
        pending_audits.append(audit)
        return pending_audits

    def schedule_audit_vxlan_providernet(self, context, audit_uuid,
                                         providernet_id, batch_size):
        """
        Runs audits for each segmentation ID in given vxlan providernet
        """
        # list of audits to give to scheduler
        pending_audits = []
        # list of tests in audit; when it fills, move to pending audits
        audit_queue = []
        segmentation_ranges = self.get_providernet_ranges(
            context,
            filters={"providernet_id": [providernet_id]},
        )
        providernet = self.get_providernet_by_id(context, providernet_id)
        if not providernet:
            return pending_audits
        mtu = providernet['mtu']

        # Run audit for first segmentation ID in each segmentation range
        for segmentation_range in segmentation_ranges:
            if len(audit_queue) >= batch_size:
                audit = ProvidernetIndividualConnectivityTest(
                    audit_uuid, providernet_id, providernet['name'],
                    constants.PROVIDERNET_VXLAN,
                    audit_queue, {ext_providernet.MTU: mtu}
                )
                pending_audits.append(audit)
                audit_queue = []
            audit_queue.append(segmentation_range)
        if audit_queue:
            audit = ProvidernetIndividualConnectivityTest(
                audit_uuid, providernet_id, providernet['name'],
                constants.PROVIDERNET_VXLAN,
                audit_queue, {ext_providernet.MTU: mtu}
            )
            pending_audits.append(audit)
        return pending_audits

    def schedule_audit_vlan_providernet(self, context, audit_uuid,
                                        providernet_id, batch_size,
                                        segmentation_ids=None):
        """
        Runs audits for batches of segmentation IDs in given vlan providernet
        """
        # list of audits to give to scheduler
        pending_audits = []
        # list of tests in audit; when it fills, move to pending audits
        audit_queue = []
        segmentation_ranges = self.get_providernet_ranges(
            context,
            filters={"providernet_id": [providernet_id]},
            fields=["minimum", "maximum"]
        )
        providernet = self.get_providernet_by_id(context, providernet_id)
        if not providernet:
            return pending_audits
        mtu = providernet['mtu']

        for r in segmentation_ranges:
            for segmentation_id in six.moves.range(r["minimum"],
                                                   r["maximum"] + 1):
                if len(audit_queue) >= batch_size:
                    audit = ProvidernetIndividualConnectivityTest(
                        audit_uuid, providernet_id, providernet['name'],
                        constants.PROVIDERNET_VLAN,
                        audit_queue, {ext_providernet.MTU: mtu}
                    )
                    pending_audits.append(audit)
                    audit_queue = []
                if (not segmentation_ids or
                        segmentation_id in segmentation_ids):
                    audit_queue.append(segmentation_id)
        if audit_queue:
            audit = ProvidernetIndividualConnectivityTest(
                audit_uuid, providernet_id, providernet['name'],
                constants.PROVIDERNET_VLAN,
                audit_queue, {ext_providernet.MTU: mtu}
            )
            pending_audits.append(audit)
        return pending_audits

    def schedule_analyse_providernet_connectivity(self, context,
                                                  providernet_id):
        """
        Schedules analysing the results of connectivity audits for providernet
        """
        # Empty audit is added to signal to analyse results for alarms
        empty_audit = ProvidernetIndividualConnectivityTest(None,
                                                            providernet_id,
                                                            None, None, None,
                                                            None)
        self.scheduled_audits.insert(0, empty_audit)
        self.scheduled_audits.append(empty_audit)

    def schedule_audit_providernets(self, context, providernet_ids,
                                    segmentation_ids=None, audit_uuid=None):
        """
        Calls type-specific providernet-connectivity-audit scheduler
        """
        if not cfg.CONF.pnet_connectivity.pnet_audit_enabled:
            raise ext_providernet.ProviderNetTestingDisabled()
        context.session.expire_all()
        time.sleep(0.1)
        batch_size = cfg.CONF.pnet_connectivity.pnet_audit_batch_size
        if not audit_uuid:
            audit_uuid = uuidutils.generate_uuid()
        for providernet_id in set(providernet_ids):
            providernet = self.get_providernet_by_id(context, providernet_id)
            if not providernet:
                continue
            providernet_type = providernet['type']
            if providernet_type == constants.PROVIDERNET_FLAT:
                self.scheduled_audits.extend(
                    self.schedule_audit_flat_providernet(context, audit_uuid,
                                                         providernet_id)
                )
            elif providernet_type == constants.PROVIDERNET_VXLAN:
                self.scheduled_audits.extend(
                    self.schedule_audit_vxlan_providernet(context, audit_uuid,
                                                          providernet_id,
                                                          batch_size)
                )
            elif providernet_type == constants.PROVIDERNET_VLAN:
                self.scheduled_audits.extend(
                    self.schedule_audit_vlan_providernet(context, audit_uuid,
                                                         providernet_id,
                                                         batch_size,
                                                         segmentation_ids)
                )
            self.schedule_analyse_providernet_connectivity(context,
                                                           providernet_id)
        return audit_uuid

    def _schedule_sequential_providernet_audits(self, context):
        """Schedules audits to be run for all pnet ranges"""
        try:
            providernet_id_dict = self.get_providernets(
                context,
                fields=['id']
            )
            providernet_ids = [providernet['id']
                               for providernet in providernet_id_dict]
            self.schedule_audit_providernets(context, providernet_ids)
        except Exception as e:
            LOG.exception("Unexpected exception in audit, {}".format(e))

    def elect_masters(self, context, providernet_id,
                      compute_hostnames, num_masters):
        """Designate a given number of hosts as masters"""
        masters = compute_hostnames[:num_masters]
        primary_master = self._find_primary_master(context, providernet_id)
        if primary_master:
            primary_master_hostname = self.get_hostname(context,
                                                        primary_master)
            if primary_master_hostname not in masters:
                masters.pop()
                masters.insert(0, primary_master_hostname)
        self._set_connectivity_data_to_unknown_by_new_masters(context,
                                                              providernet_id,
                                                              masters)
        return masters

    def _setup_connectivity_audit(self, context, audit_uuid, hostname,
                                  providernet_id, segmentation_ids,
                                  extra_data):
        """Uses RPC API to call setup_connectivity_audit remotely"""
        providernet = self.get_providernet_by_id(context,
                                                 providernet_id)
        return self.pnet_connectivity_notifier.setup_connectivity_audit(
            context, audit_uuid, hostname,
            (providernet_id, providernet['name'], providernet['type']),
            segmentation_ids, extra_data
        )

    def _start_connectivity_audit(self, context, audit_uuid, masters, hosts,
                                  providernet_id, segmentation_ids,
                                  extra_data):
        """Uses RPC API to call start_connectivity_audit remotely"""
        providernet = self.get_providernet_by_id(context,
                                                 providernet_id)
        self.pnet_connectivity_notifier.start_connectivity_audit(
            context, audit_uuid, masters, hosts,
            (providernet_id, providernet['name'], providernet['type']),
            segmentation_ids, extra_data
        )

    def _teardown_connectivity_audit(self, context, audit_uuid, hostname):
        """
        Uses RPC API to call teardown connectivity_audit remotely,
         and return whether call succeeds.
        """
        try:
            return self.pnet_connectivity_notifier.teardown_connectivity_audit(
                context, audit_uuid, hostname
            )
        except oslo_messaging.MessagingTimeout:
            return False

    def record_audit_results(self, context, audit_results, audit_uuid):
        """Called frpm RPC, write audit results to DB"""
        for audit_result in audit_results:
            hostname, master_hostname, providernet_id, \
                segmentation_id, result, test_details = audit_result
            host_id = self.get_host_uuid(context, hostname)
            master_host_id = self.get_host_uuid(context, master_hostname)
            master_connectivity_state = result
            self.update_connectivity_state_entry(context, host_id,
                                                 providernet_id,
                                                 segmentation_id,
                                                 master_host_id,
                                                 test_details,
                                                 master_connectivity_state,
                                                 audit_uuid)

    def _record_unknown_for_audit(self, context, audit_uuid, providernet_id,
                                  providernet_type, segments, hostname):
        """
        Record unknown result for segment with only one node
        """
        host_id = self.get_host_uuid(context, hostname)
        for segment in segments:
            if providernet_type == constants.PROVIDERNET_VXLAN:
                segmentation_id = str(segment['id'])
            else:
                segmentation_id = str(segment)
            self.update_connectivity_state_entry(
                context, host_id, providernet_id, segmentation_id, host_id,
                "Requires at least 2 nodes to run test for network segment",
                constants.PROVIDERNET_CONNECTIVITY_UNKNOWN, audit_uuid
            )

    def _run_individual_audit(self, context, audit_uuid, providernet_id,
                              providernet_name, providernet_type, segments,
                              extra_data):
        """
        Runs audits for give segmentation IDs
        """
        audit_uuid = audit_uuid
        setup_passed = True
        num_masters = cfg.CONF.pnet_connectivity.pnet_audit_number_of_masters
        timeout = cfg.CONF.pnet_connectivity.pnet_audit_timeout
        compute_hosts = self.get_providernet_host_objects(context,
                                                          providernet_id)
        compute_hostnames = []
        # tuple containing (hostname, link-local-address) pairs
        self.compute_masters_addresses = []
        self.compute_agent_addresses = {}

        for host in compute_hosts:
            if host.availability == constants.HOST_UP:
                compute_hostnames.append(host.name)
        num_hosts = len(compute_hostnames)

        if num_hosts < 1:
            return
        if num_hosts == 1:
            self._record_unknown_for_audit(context, audit_uuid, providernet_id,
                                           providernet_type, segments,
                                           compute_hostnames[0])
            return
        if num_hosts < num_masters:
            num_masters = num_hosts

        compute_masters = self.elect_masters(context, providernet_id,
                                             compute_hostnames, num_masters)

        try:
            for compute_master in compute_masters:
                link_local_address = self._setup_connectivity_audit(
                    context, audit_uuid, compute_master,
                    providernet_id, segments, extra_data
                )
                agent_ips = None
                if providernet_type == constants.PROVIDERNET_VXLAN:
                    # Use the transport layer address instead, but if it not
                    #  available (i.e., in an upgrade) then use the link
                    # local address.  A newer compute node will expect the
                    # transport address but an older compute node will only
                    # be able to handle the link local.
                    agent_ips = l2pop_db.get_agent_ip_by_host(
                        context.session,
                        compute_master,
                        physical_network=providernet_name)
                    self.compute_agent_addresses[compute_master] = agent_ips
                self.compute_masters_addresses.append(
                    (compute_master, link_local_address)
                )
        except oslo_messaging.MessagingTimeout:
            setup_passed = False

        # Add the master agent address for those nodes that support it
        extra_data['agent-ips'] = self.compute_agent_addresses

        # Only run connectivity tests if all masters were setup correctly
        if setup_passed:
            self._start_connectivity_audit(context, audit_uuid,
                                           self.compute_masters_addresses,
                                           compute_hostnames, providernet_id,
                                           segments, extra_data)
            # Wait for results from all hosts for this audit
            # Only check first segment because all are reported together
            start_time = time.time()
            first_segment = segments[0]
            # Check if vxlan
            if providernet_type == constants.PROVIDERNET_VXLAN:
                segmentation_id = str(first_segment['id'])
            else:
                segmentation_id = str(first_segment)
            while self._count_hosts_reporting_entry(context, providernet_id,
                                                    segmentation_id,
                                                    audit_uuid) < num_hosts:
                current_time = time.time()
                if (current_time - start_time) > timeout:
                    LOG.warning("Timed out waiting for results from audit "
                                "%(audit_uuid)s for providernet "
                                "%(providernet_id)s segments "
                                "%(segments)s",
                                {"audit_uuid": audit_uuid,
                                 "providernet_id": providernet_id,
                                 "segments": segments})
                    break
                time.sleep(1)

            # Teardown only masters that have been setup
            teardown_passed = True
            for compute_master, address in self.compute_masters_addresses:
                teardown_passed &= self._teardown_connectivity_audit(
                    context, audit_uuid, compute_master
                )
        else:
            # if setup fails, cast out teardown to all hosts
            self._teardown_connectivity_audit(context, audit_uuid, None)
        # If there is a failure, sleep for timeout for individual audit,
        #  which should give RPC handlers time to finish
        if not setup_passed or not teardown_passed:
            time.sleep(timeout)

    def _run_providernet_connectivity_tests(self, context):
        """Consumes schedules audits and then returns"""
        try:
            while len(self.scheduled_audits) > 0:
                audit = self.scheduled_audits.pop(0)
                if audit.audit_uuid:
                    self._run_individual_audit(context,
                                               audit.audit_uuid,
                                               audit.providernet_id,
                                               audit.providernet_name,
                                               audit.providernet_type,
                                               audit.segments,
                                               audit.extra_data)
                else:
                    # If not, then analyse results
                    self._analyse_providernet_connectivity_database(
                        context, [audit.providernet_id]
                    )
        except Exception as e:
            LOG.error("Running connectivity test failed, {}".format(e))
            return

    def _set_connectivity_data_to_unknown_by_pnet_range(self, context,
                                                        providernet_range):
        """Deprecate all entries for the providernet this range is in"""
        with context.session.begin(subtransactions=True):
            query = context.session.query(ProviderNetConnectivityState)

            # don't update if already outdated
            query = query.filter(
                (ProviderNetConnectivityState.master_connectivity_state !=
                 constants.PROVIDERNET_CONNECTIVITY_UNKNOWN)
            )

            query = query.filter(
                (ProviderNetConnectivityState.providernet_id ==
                 providernet_range.providernet_id)
            )

            state_unknown = {
                ProviderNetConnectivityState.master_connectivity_state:
                    constants.PROVIDERNET_CONNECTIVITY_UNKNOWN,
                ProviderNetConnectivityState.updated_at: datetime.now(),
                ProviderNetConnectivityState.test_details:
                    "Providernet range changes were made for this providernet"
            }
            query.update(state_unknown, synchronize_session='fetch')

    def _set_connectivity_data_to_unknown_by_host(self, context, host_id):
        """Deprecate all entries for host, whether as slave or master"""
        # Filter by host_id or master_hostid
        with context.session.begin(subtransactions=True):
            query = context.session.query(ProviderNetConnectivityState)

            # don't update if already outdated
            query = query.filter(
                (ProviderNetConnectivityState.master_connectivity_state !=
                 constants.PROVIDERNET_CONNECTIVITY_UNKNOWN)
            )

            query = query.filter(
                (ProviderNetConnectivityState.host_id == host_id) |
                (ProviderNetConnectivityState.master_host_id == host_id)
            )

            state_unknown = {
                ProviderNetConnectivityState.master_connectivity_state:
                    constants.PROVIDERNET_CONNECTIVITY_UNKNOWN,
                ProviderNetConnectivityState.updated_at: datetime.now(),
                ProviderNetConnectivityState.test_details:
                    "This host went offline"
            }
            query.update(state_unknown, synchronize_session='fetch')

    def _set_connectivity_data_to_unknown_by_new_masters(self, context,
                                                         providernet_id,
                                                         masters):
        """
        Deprecate all entries for this providernet where the master is not
        one of the masters passed to this function
        """
        # Convert master list from names to IDs
        master_ids = [str(self.get_host_uuid(context, host))
                      for host in masters]

        # Filter by providernet ID, and then check not in new_masters
        with context.session.begin(subtransactions=True):
            query = context.session.query(ProviderNetConnectivityState)

            # don't update if already outdated
            query = query.filter(
                (ProviderNetConnectivityState.master_connectivity_state !=
                 constants.PROVIDERNET_CONNECTIVITY_UNKNOWN)
            )

            query = query.filter(
                (ProviderNetConnectivityState.providernet_id ==
                 providernet_id)
            )

            query = query.filter(
                ProviderNetConnectivityState.master_host_id.notin_(master_ids)
            )

            state_unknown = {
                ProviderNetConnectivityState.master_connectivity_state:
                    constants.PROVIDERNET_CONNECTIVITY_UNKNOWN,
                ProviderNetConnectivityState.updated_at: datetime.now(),
                ProviderNetConnectivityState.test_details:
                    "Master election resulted in this no longer being master"
            }
            query.update(state_unknown, synchronize_session='fetch')

    def _remove_deprecated_connectivity_state_entries(self, context):
        """Remove any entry older than audit interval"""
        interval = cfg.CONF.pnet_connectivity.pnet_audit_interval
        delete_older_than_time = datetime.now() - timedelta(seconds=interval)
        with context.session.begin(subtransactions=True):
            query = context.session.query(ProviderNetConnectivityState)
            query = query.filter(
                (ProviderNetConnectivityState.updated_at <
                 delete_older_than_time),
                (ProviderNetConnectivityState.master_connectivity_state ==
                 constants.PROVIDERNET_CONNECTIVITY_UNKNOWN)
            )
            if query.count():
                query.delete(synchronize_session='fetch')

    def notify_schedule_audit_providernets(self, context, providernet_ids,
                                           segmentation_ids=None,
                                           by_event=False):
        """
        Calls schedule_audit_providernets in main process
        """
        audit_uuid = uuidutils.generate_uuid()
        if not cfg.CONF.pnet_connectivity.pnet_audit_enabled:
            return audit_uuid
        if by_event:
            if not cfg.CONF.pnet_connectivity.pnet_audit_schedule_by_event:
                return audit_uuid

        target = oslo_messaging.Target(
            topic=self.topic_pnet_connectivity_test_create, version='1.0'
        )
        self.client = n_rpc.get_client(target)
        cctxt = self.client.prepare()
        cctxt.cast(context, 'schedule_audit_providernets',
                   providernet_ids=providernet_ids,
                   segmentation_ids=segmentation_ids,
                   audit_uuid=audit_uuid)
        return audit_uuid

    def start_pnet_notify_listener(self):
        """
        Starts listening for notifications
        """
        self.connection = n_rpc.create_connection()
        self.connection.create_consumer(
            self.topic_pnet_connectivity_test_create, [self], fanout=False
        )
        self.connection.consume_in_threads()
