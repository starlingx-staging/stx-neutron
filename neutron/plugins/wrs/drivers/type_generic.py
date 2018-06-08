# Copyright (c) 2013 OpenStack Foundation
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
# Copyright (c) 2015 Wind River Systems, Inc.
#

import abc

import six

from neutron_lib import exceptions as exc
from oslo_log import log as logging
from sqlalchemy import and_, or_
from sqlalchemy import asc
from sqlalchemy.orm import exc as sa_exc
from sqlalchemy import sql

from neutron._i18n import _
from neutron.common import exceptions as n_exc
from neutron.db import api as db_api
from neutron.db import providernet_db as pnet_db
from neutron.plugins.ml2 import driver_api as api


LOG = logging.getLogger(__name__)


class GenericProvidernetTypeDriverMixin(object):

    def _get_providernet(self, session, physical_network):
        """A private function to query a provider network by name.  This
        function is used rather than the get_providernet_by_name because we do
        not have access to the 'context' object from within this class.
        """
        with session.begin(subtransactions=True):
            query = (session.query(pnet_db.ProviderNet).
                     filter_by(name=physical_network))
            return query.one()

    def _get_providernet_ranges(self, session):
        """A private function to query all provider network ranges.  This
        function is used rather than the get_providernet_ranges because we do
        not always have access to the 'context' object from within this class.
        """
        ranges = {}
        with session.begin(subtransactions=True):
            query = (session.query(pnet_db.ProviderNetRange).
                     join(pnet_db.ProviderNet).
                     filter(pnet_db.ProviderNet.type == self.get_type()))
            for entry in query.all():
                physical_network = entry['providernet']['name']
                if physical_network not in ranges:
                    ranges[physical_network] = []
                ranges[physical_network].append((entry['minimum'],
                                                 entry['maximum']))
        return ranges

    def _providernet_exists(self, context, physical_network):
        """Determines if a provider network exist as an entry in the
        providernet db table.
        """
        try:
            session = context.session
            providernet = self._get_providernet(session, physical_network)
            if providernet and providernet.type == self.get_type():
                return True
            return False
        except sa_exc.NoResultFound:
            return False


class GenericRangeTypeDriverMixin(GenericProvidernetTypeDriverMixin):
    """
    Manages allocation state for any segmentation id range based type
    drivers.  Only appropriate for WRS based classes that support the concept
    of managed provider networks because of the dependency on
    enforce_segment_precedence().  Subclasses must provide implementations of
    abstract methods in order to operate correctly.  Subclasses must also
    define these instance variables:

        self.model_key
        self.segmentation_key

    """
    @abc.abstractmethod
    def get_segmentation_key(self):
        """
        Return the column name which represents the segmentation id field.
        """
        pass

    @abc.abstractmethod
    def is_valid_segmentation_id(self, value):
        """
        Determines whether a segmentation id is valid for a specific type
        """
        pass

    @abc.abstractmethod
    def get_min_id(self):
        """
        Return the minimum valid segmentation id
        """
        pass

    @abc.abstractmethod
    def get_max_id(self):
        """
        Return the maximum valid segmentation id
        """
        pass

    def get_mtu(self, physical_network):
        session = db_api.get_current_session()
        providernet = self._get_providernet(session, physical_network)
        return providernet.mtu

    def _sync_allocations(self, session=None):
        session = session or db_api.get_current_session()
        with session.begin(subtransactions=True):
            # get existing allocations for all physical networks
            allocations = dict()
            allocs = (session.query(self.model).
                      with_lockmode('update'))
            for alloc in allocs:
                if alloc.physical_network not in allocations:
                    allocations[alloc.physical_network] = set()
                allocations[alloc.physical_network].add(alloc)

            # process segmentation ranges for each configured physical network
            ranges = self._get_providernet_ranges(session)
            for (physical_network, ranges) in ranges.items():
                # determine current configured allocatable segmentation ids for
                # this physical network
                ids = set()
                for id_min, id_max in ranges:
                    ids |= set(six.moves.range(id_min, id_max + 1))

                # remove from table unallocated segmentation ids not currently
                # allocatable
                if physical_network in allocations:
                    for alloc in allocations[physical_network]:
                        try:
                            # see if segmentation id is allocatable
                            segmentation_id = self.get_segmentation_id(alloc)
                            ids.remove(segmentation_id)
                        except KeyError:
                            # it's not allocatable, so check if its allocated
                            if not alloc.allocated:
                                # it's not, so remove it from table
                                LOG.debug("Removing %(type)s %(id)s on "
                                          "physical network "
                                          "%(physical_network)s from pool",
                                          {'type': self.get_type(),
                                           'id': segmentation_id,
                                           'physical_network':
                                           physical_network})
                                session.delete(alloc)
                    del allocations[physical_network]

                # add missing allocatable segments to table
                for segmentation_id in sorted(ids):
                    res = {'physical_network': physical_network,
                           self.segmentation_key: segmentation_id,
                           'allocated': False}
                    alloc = self.model(**res)
                    session.add(alloc)

            # remove from table unallocated segmentation ids for any
            # unconfigured physical networks
            for allocs in allocations.itervalues():
                for alloc in allocs:
                    if not alloc.allocated:
                        segmentation_id = self.get_segmentation_id(alloc)
                        LOG.debug("Removing %(type)s %(id)s on physical "
                                  "network %(physical_network)s from pool",
                                  {'type': self.get_type(),
                                   'id': segmentation_id,
                                   'physical_network':
                                   alloc.physical_network})
                        session.delete(alloc)

    def initialize(self):
        self._sync_allocations()

    def is_partial_segment(self, segment):
        return segment.get(api.SEGMENTATION_ID) is None

    def get_segmentation_id(self, data):
        """
        Return the column data from the database object using the field name
        supplied by get_segmentation_key()
        """
        return getattr(data, self.get_segmentation_key())

    def select_allocation(self, allocations):
        """Select a segment allocation from a set of available free segments.
        This is currently overridden from the default behaviour because some of
        our lab deployments depend on sequential allocations.
        """
        return allocations[0]

    def build_segment_query(self, session, **filters):
        """Enforces that segments are allocated from provider network
        segmentation ranges that are owned by the tenant, and then from shared
        ranges, but never from ranges owned by other tenants.  This method also
        enforces that other provider attributes are used when constraining the
        set of possible segments to be used.
        """
        tenant_id = filters.pop('tenant_id', None)
        vlan_transparent = filters.pop('vlan_transparent', None)
        columns = set(dict(self.model.__table__.columns))
        model_filters = dict((k, filters[k])
                             for k in columns & set(filters.keys()))
        query = (session.query(self.model)
                 .filter_by(**model_filters)
                 .join(pnet_db.ProviderNet,
                       and_(self.model.physical_network ==
                            pnet_db.ProviderNet.name,
                            pnet_db.ProviderNet.type == self.get_type()))
                 .join(pnet_db.ProviderNetRange,
                       and_(pnet_db.ProviderNet.id ==
                            pnet_db.ProviderNetRange.providernet_id,
                            self.model_key >=
                            pnet_db.ProviderNetRange.minimum,
                            self.model_key <=
                            pnet_db.ProviderNetRange.maximum))
                 .filter(or_(pnet_db.ProviderNetRange.tenant_id == tenant_id,
                             (pnet_db.ProviderNetRange.shared ==
                              sql.expression.true()))))
        if vlan_transparent:
            query = (query.filter(pnet_db.ProviderNet.vlan_transparent ==
                                  sql.expression.true()))
        query = (query.order_by(asc(pnet_db.ProviderNetRange.shared),
                                asc(self.model_key)))
        return query

    def validate_provider_segment(self, segment, context=None):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        if physical_network:
            if not self._providernet_exists(context, physical_network):
                msg = (_("physical_network '%(physical_network)s' unknown "
                         " for %(type)s provider network"),
                       {'physical_network': physical_network,
                        'type': self.get_type()})
                raise exc.InvalidInput(error_message=msg)
            if segmentation_id:
                if not self.is_valid_segmentation_id(segmentation_id):
                    msg = (_("segmentation_id out of range (%(min)s through "
                             "%(max)s)") %
                           {'min': self.get_min_id(),
                            'max': self.get_max_id()})
                    raise exc.InvalidInput(error_message=msg)
        elif segmentation_id:
            msg = (_("segmentation_id requires physical_network for %(type)s "
                     "provider network"), {'type': self.get_type()})
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK,
                                     api.SEGMENTATION_ID]:
                msg = (_("%(key)s prohibited for %(type)s provider network"),
                       {'key': key, 'type': self.get_type()})
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, context, segment, **filters):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if physical_network is not None:
            filters['physical_network'] = physical_network
            segmentation_id = segment.get(api.SEGMENTATION_ID)
            if segmentation_id is not None:
                filters[self.segmentation_key] = segmentation_id

        if self.is_partial_segment(segment):
            alloc = self.allocate_partially_specified_segment(
                context, **filters)
            if not alloc:
                raise exc.NoNetworkAvailable()
        else:
            alloc = self.allocate_fully_specified_segment(
                context, **filters)
            if not alloc:
                filters['id'] = filters[self.segmentation_key]
                del filters[self.segmentation_key]
                raise n_exc.SegmentationIdInUse(**filters)

        segmentation_id = getattr(alloc, self.segmentation_key)
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: alloc.physical_network,
                api.SEGMENTATION_ID: segmentation_id}

    def allocate_tenant_segment(self, context, **filters):
        alloc = self.allocate_partially_specified_segment(context, **filters)
        if not alloc:
            self._sync_allocations(context.session)
            return
        segmentation_id = getattr(alloc, self.segmentation_key)
        return {api.NETWORK_TYPE: self.get_type(),
                api.PHYSICAL_NETWORK: alloc.physical_network,
                api.SEGMENTATION_ID: segmentation_id}

    def release_segment(self, context, segment):
        session = context.session
        physical_network = segment[api.PHYSICAL_NETWORK]
        segmentation_id = segment[api.SEGMENTATION_ID]

        ranges = self._get_providernet_ranges(session)
        ranges = ranges.get(physical_network, [])
        inside = any(lo <= segmentation_id <= hi for lo, hi in ranges)
        with session.begin(subtransactions=True):
            query = (session.query(self.model).
                     filter_by(**{'physical_network': physical_network,
                                  self.segmentation_key: segmentation_id}))
            if inside:
                count = query.update({"allocated": False})
                if count:
                    LOG.debug("Releasing %(type) %(id)s on physical "
                              "network %(physical_network)s to pool",
                              {'type': self.get_type(),
                               'id': segmentation_id,
                               'physical_network': physical_network})
            else:
                count = query.delete()
                if count:
                    LOG.debug("Releasing %(type) %(id)s on physical "
                              "network %(physical_network)s outside pool",
                              {'type': self.get_type(),
                               'id': segmentation_id,
                               'physical_network': physical_network})

        if not count:
            LOG.warning("No %(type)s %(id)s found on physical "
                        "network %(physical_network)s",
                        {'type': self.get_type(),
                         'id': segmentation_id,
                         'physical_network': physical_network})

    def update_provider_allocations(self, context):
        self._sync_allocations(context.session)
