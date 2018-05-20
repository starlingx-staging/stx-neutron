# Copyright 2013 UnitedStack, Inc.
# Copyright 2014 INFN
# All rights reserved.
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
# Copyright (c) 2015 Wind River Systems, Inc.
#

import netaddr
import sqlalchemy as sa
from sqlalchemy import and_

from neutron_lib.db import model_base

from neutron.db import api as db_api
from neutron.db import l3_db
from neutron.db.models import l3 as l3_model
from neutron.db import models_v2
from neutron.extensions import portforwardings
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import orm
from sqlalchemy.orm import exc


LOG = logging.getLogger(__name__)


class PortForwardingRule(model_base.BASEV2, model_base.HasId,
                         model_base.HasProject):

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        nullable=False)

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          nullable=False)

    router = orm.relationship(l3_model.Router,
                              backref=orm.backref("portforwarding_list",
                                                  lazy='joined',
                                                  cascade='delete'))
    outside_port = sa.Column(sa.Integer(), nullable=False)
    inside_addr = sa.Column(sa.String(16), nullable=False)
    inside_port = sa.Column(sa.Integer(), nullable=False)
    protocol = sa.Column(sa.String(16), nullable=False)
    description = sa.Column(sa.String(255), nullable=True)
    __table_args__ = (sa.schema.UniqueConstraint('router_id',
                                                 'protocol',
                                                 'outside_port',
                                                 name='outside_port'),
                      sa.schema.UniqueConstraint('router_id',
                                                 'inside_addr',
                                                 'protocol',
                                                 'inside_port',
                                                 name='inside_port'))


class PortForwardingDbMixin(l3_db.L3_NAT_db_mixin,
                            portforwardings.PortforwardingsPluginBase):
    """Mixin class to support nat rule configuration on router."""
    __native_bulk_support = True

    def _validate_fwds(self, context, router, portfwds):
        query = context.session.query(models_v2.Network).join(models_v2.Port)
        networks = query.filter_by(device_id=router['id'])
        subnets = []
        for network in networks:
            subnets.extend(map(lambda x: x['cidr'], network.subnets))

        ip_addr, ip_net = netaddr.IPAddress, netaddr.IPNetwork
        for portfwd in portfwds:
            ip_str = portfwd['inside_addr']
            valid = any([ip_addr(ip_str) in ip_net(x) for x in subnets])
            if not valid:
                raise portforwardings.InvalidInsideAddress(inside_addr=ip_str)

    @staticmethod
    def _make_extra_portfwd_list(portforwardings):
        return [{'id': portfwd['id'],
                 'outside_port': portfwd['outside_port'],
                 'inside_addr': portfwd['inside_addr'],
                 'inside_port': portfwd['inside_port'],
                 'protocol': portfwd['protocol']
                 }
                for portfwd in portforwardings]

    def _make_portforwarding_rule_dict(self, portforwarding_rule, fields=None):
        res = {'tenant_id': portforwarding_rule['tenant_id'],
               'id': portforwarding_rule['id'],
               'router_id': portforwarding_rule['router_id'],
               'port_id': portforwarding_rule['port_id'],
               'protocol': portforwarding_rule['protocol'],
               'inside_addr': portforwarding_rule['inside_addr'],
               'inside_port': portforwarding_rule['inside_port'],
               'outside_port': portforwarding_rule['outside_port'],
               'description': portforwarding_rule['description']
               }
        return self._fields(res, fields)

    def _get_rule(self, context, id):
        try:
            return self._get_by_id(context, PortForwardingRule, id)
        except exc.NoResultFound:
            raise portforwardings.PortForwardingRuleNotFound(
                                  port_forwarding_rule_id=id)

    def _create_bulk(self, resource, context, request_items):
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        context.session.begin(subtransactions=True)
        try:
            for item in items:
                obj_creator = getattr(self, 'create_%s' % resource)
                objects.append(obj_creator(context, item))
            context.session.commit()
        except Exception:
            context.session.rollback()
            with excutils.save_and_reraise_exception():
                LOG.error("An exception occurred while creating "
                          "the %(resource)s:%(item)s",
                          {'resource': resource, 'item': item})
        return objects

    def create_portforwarding_bulk(self, context, portforwarding):
        return self._create_bulk('portforwarding', context,
                                 portforwarding)

    def _get_port_from_address(self, context, router_id, ip_address):
        """Find the port that is associated to the requested ip_address.  The
        search is constrained to only those ports that are behind the specified
        router.  This ensures that if there are multiple matching IP addresses
        because of overlapping subnets that we find the one that is unique to
        this router (i.e., routers cannot be attached to multiple overlapping
        subnets).
        """
        try:
            subnets = (self._model_query(context,
                                         models_v2.IPAllocation.subnet_id)
                       .select_from(l3_model.Router)
                       .join(l3_model.RouterPort,
                             and_(l3_model.RouterPort.router_id ==
                                  l3_model.Router.id,
                                  l3_model.Router.id == router_id))
                       .join(models_v2.IPAllocation,
                             (models_v2.IPAllocation.port_id ==
                              l3_model.RouterPort.port_id))
                       .group_by(models_v2.IPAllocation.subnet_id))
            query = (self._model_query(context, models_v2.IPAllocation)
                     .filter(models_v2.IPAllocation.subnet_id
                             .in_(subnets.subquery()))
                     .filter(models_v2.IPAllocation.ip_address == ip_address))
            allocation = query.one()
        except exc.NoResultFound:
            raise portforwardings.NoAddressAllocationFound(
                ip_address=ip_address, router_id=router_id)
        try:
            port_db = self._core_plugin._get_port(context, allocation.port_id)
            return port_db
        except exc.NoResultFound:
            raise portforwardings.NoPortFound(portid=allocation.port_id)

    @db_api.retry_if_session_inactive()
    def create_portforwarding(self, context, portforwarding):
        with context.session.begin(subtransactions=True):
            LOG.debug('create_portforwarding ->  portforwarding: %s',
                      portforwarding)

            rule_data = portforwarding['portforwarding']
            router = self._get_router(context, rule_data['router_id'])
            port_db = self._get_port_from_address(
                context, rule_data['router_id'], rule_data['inside_addr'])
            if not port_db.device_owner.startswith('compute:'):
                raise portforwardings.MustAssignRuleToComputePort()
            try:
                    self._validate_fwds(context, router, [rule_data])
                    rule = PortForwardingRule(
                            tenant_id=router['tenant_id'],
                            router_id=rule_data['router_id'],
                            port_id=port_db.id,
                            outside_port=rule_data['outside_port'],
                            inside_addr=rule_data['inside_addr'],
                            inside_port=rule_data['inside_port'],
                            protocol=rule_data['protocol'],
                            description=rule_data['description'])
                    context.session.add(rule)
                    context.session.flush()
                    LOG.debug('router type: %s', router)
                    self.notify_router_updated(context, router['id'])

                    return self._make_portforwarding_rule_dict(rule)
            except db_exc.DBDuplicateEntry as e:
                LOG.info('Exception: %s', e.inner_exception.message)
                if 'outside_port' in e.inner_exception.message:
                    raise portforwardings.DuplicatedOutsidePort(
                        port=(rule_data['protocol'] + ' ' +
                              rule_data['outside_port']))
                if 'inside_port' in e.inner_exception.message:
                    raise portforwardings.DuplicatedInsidePort(
                        port=(rule_data['protocol'] + ' ' +
                              rule_data['inside_port']),
                        address=rule_data['inside_addr'])
                # Re-raise for unknown DB exception
                raise

    @db_api.retry_if_session_inactive()
    def update_portforwarding(self, context, id, portforwarding):
        try:
            rule = portforwarding['portforwarding']
            with context.session.begin(subtransactions=True):
                portforwarding_db = self._get_by_id(context,
                                                    PortForwardingRule, id)

                if 'inside_addr' in rule:
                    router = self._get_router(context,
                                              portforwarding_db['router_id'])
                    self._validate_fwds(context, router, [rule])

                portforwarding_db.update(rule)
                self.notify_router_updated(context,
                                           portforwarding_db['router_id'])

                return self._make_portforwarding_rule_dict(portforwarding_db)
        except db_exc.DBDuplicateEntry as e:
            LOG.info('Exception: %s', e.inner_exception.message)
            protocol = rule.get('protocol', portforwarding_db['protocol'])
            if 'outside_port' in e.inner_exception.message:
                outside_port = rule.get('outside_port',
                                        str(portforwarding_db['outside_port']))
                raise portforwardings.DuplicatedOutsidePort(
                    port=protocol + ' ' + outside_port)
            if 'inside_port' in e.inner_exception.message:
                inside_port = rule.get('inside_port',
                                       str(portforwarding_db['inside_port']))
                inside_addr = rule.get('inside_addr',
                                       str(portforwarding_db['inside_addr']))
                raise portforwardings.DuplicatedInsidePort(
                    port=protocol + ' ' + inside_port,
                    address=inside_addr)
            # Re-raise for unknown DB exception
            raise

    @db_api.retry_if_session_inactive()
    def delete_portforwarding(self, context, id):
        try:
            rule = self.get_portforwarding(context, id)
            router_id = rule['router_id']
            del_context = context.session.query(PortForwardingRule)
            del_context.filter_by(id=id).delete()
            self.notify_router_updated(context, router_id)
        except exc.NoResultFound:
            raise portforwardings.PortForwardingRuleNotFound(
                                  port_forwarding_rule_id=id)

    @db_api.retry_if_session_inactive()
    def get_portforwardings(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'portforwarding',
                                          limit, marker)
        return self._get_collection(context, PortForwardingRule,
                                    self._make_portforwarding_rule_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @db_api.retry_if_session_inactive()
    def get_portforwarding(self, context, id, fields=None):
        rule = self._get_rule(context, id)
        return self._make_portforwarding_rule_dict(rule, fields)

    def _remove_affected_portforwarding_rules(self, context,
                                              router_interface_info):
        subnet_ids = router_interface_info['subnet_ids']
        with context.session.begin(subtransactions=True):
            rule_ids = (self._model_query(context, PortForwardingRule.id)
                        .join(models_v2.IPAllocation,
                              and_(models_v2.IPAllocation.port_id ==
                                   PortForwardingRule.port_id,
                                   models_v2.IPAllocation.ip_address ==
                                   PortForwardingRule.inside_addr))
                        .filter(models_v2.IPAllocation.subnet_id
                                .in_(subnet_ids)))
            count = len(rule_ids.all())
            if count > 0:
                LOG.warning("deleting {} port forwarding rules related to "
                            "subnet ids {}").format(count, subnet_ids)
                rules = (self._model_query(context, PortForwardingRule)
                         .filter(PortForwardingRule.id
                                 .in_(rule_ids.subquery())))
                rules.delete(synchronize_session=False)

    def remove_router_interface(self, context, router_id, interface_info):
        router_interface_info = super(
            PortForwardingDbMixin, self).remove_router_interface(
                context, router_id, interface_info)
        self._remove_affected_portforwarding_rules(
            context, router_interface_info)
        return router_interface_info
