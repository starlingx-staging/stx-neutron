# Copyright 2013 OpenStack Foundation
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

from neutron_lib.db import model_base
from neutron_lib import exceptions as exc

from neutron._i18n import _
from neutron.api.rpc.agentnotifiers import qos_rpc_agent_api
from neutron.common import constants
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.extensions import wrs_tm as ext_qos

import sqlalchemy as sa
from sqlalchemy import orm


class QoSNotFound(exc.NotFound):
    message = _("QoS %(qos_id)s could not be found")


class QoSAlreadyExists(exc.Conflict):
    message = _("QoS policy with name %(name)s already exists")


class QoSPortMappingNotFound(exc.NotFound):
    message = _("QoS mapping for port %(port_id)s could not be found")


class QoSNetworkMappingNotFound(exc.NotFound):
    message = _("QoS mapping for network %(net_id)s could not be found")


class WrsQoS(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    __tablename__ = 'wrs_qoses'
    name = sa.Column(sa.String(255), unique=True, nullable=False)
    description = sa.Column(sa.String(255), nullable=False)
    policies = orm.relationship('WrsQoSPolicy',
                                cascade='all, delete, delete-orphan')
    ports = orm.relationship('WrsPortQoSMapping',
                             cascade='all, delete, delete-orphan')
    networks = orm.relationship('WrsNetworkQoSMapping',
                                cascade='all, delete, delete-orphan')


class WrsQoSPolicy(model_base.BASEV2, model_base.HasId):
    __tablename__ = 'wrs_qos_policies'
    qos_id = sa.Column(sa.String(36),
                       sa.ForeignKey('wrs_qoses.id', ondelete='CASCADE'),
                       nullable=False,
                       primary_key=True)
    type = sa.Column(sa.Enum(constants.TYPE_QOS_DSCP,
                             constants.TYPE_QOS_RATELIMIT,
                             constants.TYPE_QOS_SCHEDULER,
                             name='wrs_qos_types'))
    key = sa.Column(sa.String(255), nullable=False,
                    primary_key=True)
    value = sa.Column(sa.String(255), nullable=False)


class WrsNetworkQoSMapping(model_base.BASEV2):
    __tablename__ = 'wrs_network_qos_mappings'
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id',
                           ondelete='CASCADE'), nullable=False,
                           primary_key=True)
    qos_id = sa.Column(sa.String(36), sa.ForeignKey('wrs_qoses.id',
                       ondelete='CASCADE'), nullable=False, primary_key=True)

    # Add a relationship to the Network model in order to instruct SQLAlchemy
    # to eagerly load qos bindings
    networks = orm.relationship(
        models_v2.Network,
        backref=orm.backref("wrs_qos", lazy='joined', cascade='delete'))


class WrsPortQoSMapping(model_base.BASEV2):
    __tablename__ = 'wrs_port_qos_mappings'
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                        ondelete='CASCADE'), nullable=False, primary_key=True)
    qos_id = sa.Column(sa.String(36), sa.ForeignKey('wrs_qoses.id',
                       ondelete='CASCADE'), nullable=False, primary_key=True)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly load qos bindings
    ports = orm.relationship(
        models_v2.Port,
        backref=orm.backref("wrs_qos", lazy='joined', cascade='delete'))


class QoSDbMixin(ext_qos.QoSPluginBase):

    @property
    def qos_rpc(self):
        if not getattr(self, '_qos_rpc', None):
            self._qos_rpc = qos_rpc_agent_api.QoSAgentNotifyAPI()
        return self._qos_rpc

    def _process_create_qos_for_network(self, context, qos_id, network_id):
        self.create_qos_for_network(context, qos_id, network_id)
        self.qos_rpc.network_qos_updated(context, qos_id, network_id)

    def _process_create_qos_for_port(self, context, qos_id, port_id):
        self.create_qos_for_port(context, qos_id, port_id)
        self.qos_rpc.port_qos_updated(context, qos_id, port_id)

    def _process_delete_qos_for_network(self, context, qos_id, network_id):
        self.delete_qos_for_network(context, network_id)
        self.qos_rpc.network_qos_deleted(context, qos_id, network_id)

    def _process_delete_qos_for_port(self, context, qos_id, port_id):
        self.delete_qos_for_port(context, port_id)
        self.qos_rpc.port_qos_deleted(context, qos_id, port_id)

    def _process_update_mapping_for_network(self, context, mapping):
        self.update_mapping_for_network(context, mapping)
        self.qos_rpc.network_qos_updated(context,
                                         mapping.qos_id,
                                         mapping.network_id)

    def _process_update_mapping_for_port(self, context, mapping):
        self.update_mapping_for_port(context, mapping)
        self.qos_rpc.port_qos_updated(context,
                                      mapping.qos_id,
                                      mapping.port_id)

    def _process_qos_network_update(self, context, network, req_data):
        if ext_qos.QOS not in req_data:
            return
        qos_id = req_data.get(ext_qos.QOS, None)
        mapping = self.get_mapping_for_network(context, network['id'])
        if qos_id and not mapping:
            self._process_create_qos_for_network(context,
                                                 qos_id,
                                                 network['id'])
        elif not qos_id and mapping:
            self._process_delete_qos_for_network(context,
                                                 mapping[0].qos_id,
                                                 network['id'])
        elif qos_id:
            qos_id = req_data[ext_qos.QOS]
            mapping = mapping[0]
            mapping.qos_id = qos_id
            self._process_update_mapping_for_network(context, mapping)

        if qos_id:
            # update network dictionary to include qos policy
            network[ext_qos.QOS] = qos_id

    def _process_qos_port_update(self, context, port, req_data):
        if ext_qos.QOS not in req_data:
            return False

        qos_id = req_data.get(ext_qos.QOS, None)
        mapping = self.get_mapping_for_port(context, port['id'])

        if qos_id and not mapping:
            self._process_create_qos_for_port(context,
                                              qos_id,
                                              port['id'])
        elif not qos_id and mapping:
            self._process_delete_qos_for_port(context,
                                              mapping[0].qos_id,
                                              port['id'])
        elif qos_id:
            qos_id = req_data[ext_qos.QOS]
            mapping = mapping[0]
            mapping.qos_id = qos_id
            self._process_update_mapping_for_port(context, mapping)

        if qos_id:
            # update port dictionary to include qos policy
            port[ext_qos.QOS] = qos_id

        return True

    def _create_qos_dict(self, qos, fields=None):
        res = {'id': qos['id'],
               'tenant_id': qos['tenant_id'],
               'name': qos['name'],
               'description': qos['description'],
               'policies': {}}
        for item in qos.policies:
            res['policies'].setdefault(item['type'], {}).update(
                {item['key']: item['value']})
        return self._fields(res, fields)

    def _db_delete(self, context, item):
        with context.session.begin(subtransactions=True):
            context.session.delete(item)

    def _update_qos(self, context, id, qos):
        self.validate_qos(context, id, qos)
        db = self._get_by_id(context, WrsQoS, id)
        with context.session.begin(subtransactions=True):
            db.policies = []
            for type, policies in six.iteritems(qos['qos']['policies']):
                for k, v in six.iteritems(policies):
                    db.policies.append(
                        WrsQoSPolicy(qos_id=db, type=type, key=k, value=v))
            del qos['qos']['policies']
            db.update(qos['qos'])
        return self._create_qos_dict(db)

    def _delete_qos(self, context, id):
        try:
            self._db_delete(context, self._get_by_id(context, WrsQoS, id))
        except orm.exc.NoResultFound:
            raise QoSNotFound(qos_id=id)

    @db_api.retry_if_session_inactive()
    def create_qos(self, context, qos):
        self.validate_qos(context, id, qos)
        with context.session.begin(subtransactions=True):
            qos_db_item = WrsQoS(name=qos['qos']['name'],
                                 description=qos['qos']['description'],
                                 tenant_id=qos['qos']['tenant_id'])
            for type, policies in six.iteritems(qos['qos']['policies']):
                for k, v in six.iteritems(policies):
                    qos_db_item.policies.append(
                        WrsQoSPolicy(qos_id=qos_db_item.id,
                                     type=type, key=k, value=v))
            context.session.add(qos_db_item)
        return self._create_qos_dict(qos_db_item)

    def create_qos_for_network(self, context, qos_id, network_id):
        with context.session.begin(subtransactions=True):
            db = WrsNetworkQoSMapping(qos_id=qos_id, network_id=network_id)
            context.session.add(db)
        return db.qos_id

    def create_qos_for_port(self, context, qos_id, port_id):
        with context.session.begin(subtransactions=True):
            db = WrsPortQoSMapping(qos_id=qos_id, port_id=port_id)
            context.session.add(db)
        return db.qos_id

    @db_api.retry_if_session_inactive()
    def update_qos(self, context, id, qos):
        result = self._update_qos(context, id, qos)
        qos_item = self._get_by_id(context, WrsQoS, id)
        for port_mapping in qos_item.ports:
            self.qos_rpc.port_qos_updated(context,
                                          id,
                                          port_mapping['port_id'])
        for net_mapping in qos_item.networks:
            self.qos_rpc.network_qos_updated(context,
                                             id,
                                             net_mapping['network_id'])
        return result

    @db_api.retry_if_session_inactive()
    def delete_qos(self, context, id):
        qos_item = self._get_by_id(context, WrsQoS, id)
        for port_mapping in qos_item.ports:
            self.qos_rpc.port_qos_deleted(context,
                                          id,
                                          port_mapping['port_id'])

        for net_mapping in qos_item.networks:
            self.qos_rpc.network_qos_deleted(context,
                                             id,
                                             net_mapping['network_id'])
        self._delete_qos(context, id)

    def delete_qos_for_network(self, context, network_id):
        try:
            self._db_delete(context,
                            self._model_query(context,
                                              WrsNetworkQoSMapping)
                            .filter_by(network_id=network_id).one())
        except orm.exc.NoResultFound:
            raise QoSNetworkMappingNotFound(net_id=network_id)

    def delete_qos_for_port(self, context, port_id):
        try:
            self._db_delete(context,
                            self._model_query(context, WrsPortQoSMapping)
                            .filter_by(port_id=port_id).one())
        except orm.exc.NoResultFound:
            raise QoSPortMappingNotFound(port_id=port_id)

    def get_mapping_for_network(self, context, network_id):
        try:
            with context.session.begin(subtransactions=True):
                return (self._model_query(context, WrsNetworkQoSMapping)
                        .filter_by(network_id=network_id).all())
        except orm.exc.NoResultFound:
            raise QoSNetworkMappingNotFound(net_id=network_id)

    def get_mapping_for_port(self, context, port_id):
        try:
            with context.session.begin(subtransactions=True):
                return self._model_query(context, WrsPortQoSMapping).filter_by(
                    port_id=port_id).all()
        except orm.exc.NoResultFound:
            raise QoSPortMappingNotFound(port_id=port_id)

    @db_api.retry_if_session_inactive()
    def get_qos(self, context, id, fields=None):
        try:
            with context.session.begin(subtransactions=True):
                return self._create_qos_dict(
                    self._get_by_id(context, WrsQoS, id), fields)
        except orm.exc.NoResultFound:
            raise QoSNotFound(qos_id=id)

    @db_api.retry_if_session_inactive()
    def get_qoses(self, context, filters=None, fields=None,
                  sorts=None, limit=None,
                  marker=None, page_reverse=False, default_sg=False):
        marker_obj = self._get_marker_obj(context, 'qos', limit, marker)

        return self._get_collection(context,
                                    WrsQoS,
                                    self._create_qos_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit, marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def update_mapping_for_network(self, context, mapping):
        db = self.get_mapping_for_network(context, mapping.network_id)[0]
        with context.session.begin(subtransactions=True):
            db.update(mapping)

    def update_mapping_for_port(self, context, mapping):
        db = self.get_mapping_for_port(context, mapping.port_id)[0]
        with context.session.begin(subtransactions=True):
            db.update(mapping)

    def _get_qos_by_name(self, context, name):
        query = self._model_query(context, WrsQoS)
        return query.filter(WrsQoS.name == name).one()

    def _validate_qos_exists(self, context, id, qos):
        try:
            if 'name' in qos:
                other = self._get_qos_by_name(context, qos['name'])
                if other['id'] != id:
                    raise QoSAlreadyExists(name=qos['name'])
        except orm.exc.NoResultFound:
            pass

    def _validate_qos_types(self, context, qos):
        if 'policies' not in qos:
            raise ext_qos.QoSValidationError()
        for type, policies in six.iteritems(qos['policies']):
            try:
                validator = getattr(self, 'validate_policy_' + type)
            except AttributeError:
                raise Exception(_('No validator found for type: %s') % type)
            validator(policies)

    def validate_qos(self, context, id, qos):
        qos = qos['qos']
        self._validate_qos_exists(context, id, qos)
        self._validate_qos_types(context, qos)

    def validate_policy_dscp(self, policy):
        try:
            dscp = int(policy[constants.TYPE_QOS_DSCP])
            if dscp < 0 or dscp > 63:
                raise ext_qos.QoSValidationError()
        except ValueError:
            raise ext_qos.QoSValidationError()

    def validate_policy_scheduler(self, policy):
        try:
            weight = int(policy[constants.QOS_SCHEDULER_POLICY_WEIGHT])
            if weight < 0:
                raise ext_qos.QoSValidationError()
        except ValueError:
            raise ext_qos.QoSValidationError()

    def get_policy_for_qos(self, context, qos_id):
        result = {}
        query = context.session.query(WrsQoS)
        results = query.filter_by(id=qos_id)
        for item in results.one().policies:
            result.setdefault(item['type'], {})
            result[item['type']].update({item['key']: item['value']})
        return result

    def get_qos_by_network(self, context, network_id):
        query = context.session.query(WrsNetworkQoSMapping)
        try:
            mapping = query.filter_by(network_id=network_id).one()
            return mapping.qos_id
        except orm.exc.NoResultFound:
            return None

    def get_qos_by_port(self, context, port_id):
        query = context.session.query(WrsPortQoSMapping)
        try:
            mapping = query.filter_by(port_id=port_id).one()
            return mapping.qos_id
        except orm.exc.NoResultFound:
            return None

    def extend_network_dict_qos(self, network_res, network_db):
        # QoS bindings will be retrieved from the sqlalchemy
        # model. As they're loaded eagerly with networks because of the
        # joined load they will not cause an extra query.
        if network_db.wrs_qos:
            # currently only one QoS policy can be mapped
            network_res[ext_qos.QOS] = network_db.wrs_qos[0].qos_id
        return network_res

    def extend_port_dict_qos(self, port_res, port_db):
        # QoS bindings will be retrieved from the sqlalchemy
        # model. As they're loaded eagerly with ports because of the
        # joined load they will not cause an extra query.
        if port_db.wrs_qos:
            # currently only one QoS policy can be mapped
            port_res[ext_qos.QOS] = port_db.wrs_qos[0].qos_id
        return port_res
