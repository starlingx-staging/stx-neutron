#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

import copy
import itertools
import operator

from keystoneauth1 import loading as ks_loading
from oslo_config import cfg

import neutron.agent.agent_extensions_manager
import neutron.agent.linux.interface
import neutron.agent.linux.pd
import neutron.agent.linux.ra
import neutron.agent.ovsdb.api
import neutron.agent.securitygroups_rpc
import neutron.common.cache_utils
import neutron.conf.agent.agent_extensions_manager
import neutron.conf.agent.common
import neutron.conf.agent.dhcp
import neutron.conf.agent.l3.config
import neutron.conf.agent.l3.ha
import neutron.conf.agent.metadata.config as meta_conf
import neutron.conf.agent.ovs_conf
import neutron.conf.agent.xenapi_conf
import neutron.conf.cache_utils
import neutron.conf.common
import neutron.conf.extensions.allowedaddresspairs
import neutron.conf.plugins.ml2.drivers.agent
import neutron.conf.plugins.ml2.drivers.driver_type
import neutron.conf.plugins.ml2.drivers.l2pop
import neutron.conf.plugins.ml2.drivers.linuxbridge
import neutron.conf.plugins.ml2.drivers.macvtap
import neutron.conf.plugins.ml2.drivers.mech_sriov.agent_common
import neutron.conf.plugins.ml2.drivers.ovs_conf
import neutron.conf.quota
import neutron.conf.service
import neutron.conf.services.metering_agent
import neutron.conf.wsgi
import neutron.db.agents_db
import neutron.db.agentschedulers_db
import neutron.db.dvr_mac_db
import neutron.db.extraroute_db
import neutron.db.l3_agentschedulers_db
import neutron.db.l3_dvr_db
import neutron.db.l3_gwmode_db
import neutron.db.l3_hamode_db
import neutron.db.migration.cli
import neutron.db.providernet_db
import neutron.extensions.l3
import neutron.extensions.securitygroup
import neutron.plugins.ml2.config
import neutron.plugins.ml2.drivers.mech_sriov.agent.common.config
import neutron.plugins.wrs.agent.avs.agent
import neutron.plugins.wrs.drivers.mech_vswitch
import neutron.wsgi


NOVA_GROUP = 'nova'

CONF = cfg.CONF

deprecations = {'nova.cafile': [cfg.DeprecatedOpt('ca_certificates_file',
                                                  group=NOVA_GROUP)],
                'nova.insecure': [cfg.DeprecatedOpt('api_insecure',
                                                    group=NOVA_GROUP)],
                'nova.timeout': [cfg.DeprecatedOpt('url_timeout',
                                                   group=NOVA_GROUP)]}

_nova_options = ks_loading.register_session_conf_options(
            CONF, NOVA_GROUP, deprecated_opts=deprecations)


def list_agent_opts():
    return [
        ('agent',
         itertools.chain(
             neutron.conf.agent.common.ROOT_HELPER_OPTS,
             neutron.conf.agent.common.AGENT_STATE_OPTS,
             neutron.conf.agent.common.IPTABLES_OPTS,
             neutron.conf.agent.common.PROCESS_MONITOR_OPTS,
             neutron.conf.agent.common.AVAILABILITY_ZONE_OPTS)
         ),
        ('DEFAULT',
         itertools.chain(
             neutron.conf.agent.common.INTERFACE_DRIVER_OPTS,
             neutron.conf.agent.metadata.config.SHARED_OPTS)
         )
    ]


def list_extension_opts():
    return [
        ('DEFAULT',
         neutron.conf.extensions.allowedaddresspairs
         .allowed_address_pair_opts),
        ('quotas',
         itertools.chain(
             neutron.conf.quota.l3_quota_opts,
             neutron.conf.quota.security_group_quota_opts)
         )
    ]


def list_db_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.db.agents_db.AGENT_OPTS,
             neutron.db.extraroute_db.extra_route_opts,
             neutron.db.l3_gwmode_db.OPTS,
             neutron.db.agentschedulers_db.AGENTS_SCHEDULER_OPTS,
             neutron.db.dvr_mac_db.dvr_mac_address_opts,
             neutron.db.l3_dvr_db.router_distributed_opts,
             neutron.db.l3_agentschedulers_db.L3_AGENTS_SCHEDULER_OPTS,
             neutron.db.l3_hamode_db.L3_HA_OPTS)
         ),
        ('database',
         neutron.db.migration.cli.get_engine_config())
    ]


def list_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.common.core_cli_opts,
             neutron.conf.common.core_opts,
             neutron.conf.wsgi.socket_opts,
             neutron.conf.service.service_opts)
         ),
        (neutron.conf.common.NOVA_CONF_SECTION,
         itertools.chain(
              neutron.conf.common.nova_opts)
         ),
        ('quotas', neutron.conf.quota.core_quota_opts)
    ]


def list_base_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.agent.linux.interface.OPTS,
             neutron.conf.agent.common.INTERFACE_DRIVER_OPTS,
             neutron.conf.agent.ovs_conf.OPTS)
         ),
        ('agent', neutron.conf.agent.common.AGENT_STATE_OPTS),
        ('ovs', neutron.agent.ovsdb.api.OPTS),
    ]


def list_az_agent_opts():
    return [
        ('agent', neutron.conf.agent.common.AVAILABILITY_ZONE_OPTS),
    ]


def list_dhcp_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.agent.dhcp.DHCP_AGENT_OPTS,
             neutron.conf.agent.dhcp.DHCP_OPTS,
             neutron.conf.agent.dhcp.DNSMASQ_OPTS)
         )
    ]


def list_linux_bridge_opts():
    return [
        ('linux_bridge',
         neutron.conf.plugins.ml2.drivers.linuxbridge.bridge_opts),
        ('vxlan',
         neutron.conf.plugins.ml2.drivers.linuxbridge.vxlan_opts),
        ('agent',
         itertools.chain(
             neutron.conf.plugins.ml2.drivers.agent.agent_opts,
             neutron.conf.agent.agent_extensions_manager.
             AGENT_EXT_MANAGER_OPTS)
         ),
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts)
    ]


def list_l3_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             neutron.conf.agent.l3.config.OPTS,
             neutron.conf.service.service_opts,
             neutron.conf.agent.l3.ha.OPTS,
             neutron.agent.linux.pd.OPTS,
             neutron.agent.linux.ra.OPTS)
         ),
        ('agent',
         neutron.conf.agent.agent_extensions_manager.AGENT_EXT_MANAGER_OPTS),
    ]


def list_macvtap_opts():
    return [
        ('macvtap',
         neutron.conf.plugins.ml2.drivers.macvtap.macvtap_opts),
        ('agent',
         neutron.conf.plugins.ml2.drivers.agent.agent_opts),
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts)
    ]


def list_metadata_agent_opts():
    return [
        ('DEFAULT',
         itertools.chain(
             meta_conf.SHARED_OPTS,
             meta_conf.METADATA_PROXY_HANDLER_OPTS,
             meta_conf.UNIX_DOMAIN_METADATA_PROXY_OPTS,
             neutron.conf.cache_utils.cache_opts)
         ),
        ('agent', neutron.conf.agent.common.AGENT_STATE_OPTS)
    ]


def list_metering_agent_opts():
    return [
        ('DEFAULT', neutron.conf.services.metering_agent.metering_agent_opts),
    ]


def list_ml2_conf_opts():
    return [
        ('ml2',
         neutron.plugins.ml2.config.ml2_opts),
        ('ml2_type_flat',
         neutron.conf.plugins.ml2.drivers.driver_type.flat_opts),
        ('ml2_type_vlan',
         neutron.conf.plugins.ml2.drivers.driver_type.vlan_opts),
        ('ml2_type_gre',
         neutron.conf.plugins.ml2.drivers.driver_type.gre_opts),
        ('ml2_type_vxlan',
         neutron.conf.plugins.ml2.drivers.driver_type.vxlan_opts),
        ('ml2_type_geneve',
         neutron.conf.plugins.ml2.drivers.driver_type.geneve_opts),
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts),
        ('l2pop',
         neutron.conf.plugins.ml2.drivers.l2pop.l2_population_options)
    ]


def list_ovs_opts():
    return [
        ('ovs',
         itertools.chain(
             neutron.conf.plugins.ml2.drivers.ovs_conf.ovs_opts,
             neutron.agent.ovsdb.api.OPTS)
         ),
        ('agent',
         itertools.chain(
             neutron.conf.plugins.ml2.drivers.ovs_conf.agent_opts,
             neutron.conf.agent.agent_extensions_manager.
             AGENT_EXT_MANAGER_OPTS)
         ),
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts),
    ]


def list_sriov_agent_opts():
    return [
        ('sriov_nic',
         neutron.conf.plugins.ml2.drivers.mech_sriov.agent_common.
         sriov_nic_opts),
        ('agent',
         neutron.conf.agent.agent_extensions_manager.AGENT_EXT_MANAGER_OPTS)
    ]


def list_auth_opts():
    opt_list = copy.deepcopy(_nova_options)
    opt_list.insert(0, ks_loading.get_auth_common_conf_options()[0])
    # NOTE(mhickey): There are a lot of auth plugins, we just generate
    # the config options for a few common ones
    plugins = ['password', 'v2password', 'v3password']
    for name in plugins:
        for plugin_option in ks_loading.get_auth_plugin_conf_options(name):
            if all(option.name != plugin_option.name for option in opt_list):
                opt_list.append(plugin_option)
    opt_list.sort(key=operator.attrgetter('name'))
    return [(NOVA_GROUP, opt_list)]


def list_xenapi_opts():
    return [
        ('xenapi',
         neutron.conf.agent.xenapi_conf.XENAPI_OPTS)
    ]


def list_pnet_connectivity_opts():
    return [
        ('pnet_connectivity',
         neutron.db.providernet_db.PNET_CONNECTIVITY_OPTS)
    ]


def list_avs_agent_opts():
    return [
        ('securitygroup',
         neutron.conf.agent.securitygroups_rpc.security_group_opts)
    ]


def list_vhost_opts():
    return [
        ('vhost',
         neutron.conf.agent.securitygroups_rpc.security_group_opts)
    ]
