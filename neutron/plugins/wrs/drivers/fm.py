# Copyright (c) 2015 OpenStack Foundation.
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

from fm_api import constants as fm_constants
from fm_api import fm_api
from neutron._i18n import _
from neutron.drivers import fm


class DefaultFmDriver(fm.FmDriver):

    def __init__(self):
        self.fm_api = fm_api.FaultAPIs()

    @staticmethod
    def _get_port_entity_type_id():
        return "{}.{}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                              fm_constants.FM_ENTITY_TYPE_PORT)

    @staticmethod
    def _get_port_entity_instance_id(hostname, port_id):
        return "{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                    hostname,
                                    fm_constants.FM_ENTITY_TYPE_PORT,
                                    port_id)

    @staticmethod
    def _get_interface_entity_type_id():
        return "{}.{}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                              fm_constants.FM_ENTITY_TYPE_INTERFACE)

    @staticmethod
    def _get_interface_entity_instance_id(hostname, interface_id):
        return "{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                    hostname,
                                    fm_constants.FM_ENTITY_TYPE_INTERFACE,
                                    interface_id)

    @staticmethod
    def _get_providernet_entity_type_id():
        return "{}.{}".format(fm_constants.FM_ENTITY_TYPE_SERVICE,
                              fm_constants.FM_ENTITY_TYPE_PROVIDERNET)

    @staticmethod
    def _get_providernet_entity_instance_id(providernet_id, hostname=None):
        ret = ""
        if hostname:
            ret = "{}={}.".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                  hostname)
        ret = "{}{}={}.{}={}".format(ret,
                                     fm_constants.FM_ENTITY_TYPE_SERVICE,
                                     fm_constants.FM_SERVICE_NETWORKING,
                                     fm_constants.FM_ENTITY_TYPE_PROVIDERNET,
                                     providernet_id)
        return ret

    @staticmethod
    def _get_providernet_connectivity_reason(providernet_id, hostname,
                                             segmentation_ranges):
        if segmentation_ranges != "flat":
            msg = _("Communication failure detected over provider network {}"
                    " for ranges {} on host {}").format(providernet_id,
                                                        segmentation_ranges,
                                                        hostname)
        else:
            msg = _("Communication failure detected over provider network {}"
                    " on host {}").format(providernet_id, hostname)
        return msg

    @staticmethod
    def _get_agent_entity_type_id():
        return "{}.{}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                              fm_constants.FM_ENTITY_TYPE_AGENT)

    @staticmethod
    def _get_agent_entity_instance_id(hostname, agent_id):
        return "{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                    hostname,
                                    fm_constants.FM_ENTITY_TYPE_AGENT,
                                    agent_id)

    @staticmethod
    def _get_bgp_peer_entity_type_id():
        return "{}.{}.{}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                 fm_constants.FM_ENTITY_TYPE_AGENT,
                                 fm_constants.FM_ENTITY_TYPE_BGP_PEER)

    @staticmethod
    def _get_bgp_peer_entity_instance_id(host_id, agent_id, bgp_peer_id):
        return "{}={}.{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                          host_id,
                                          fm_constants.FM_ENTITY_TYPE_AGENT,
                                          agent_id,
                                          fm_constants.FM_ENTITY_TYPE_BGP_PEER,
                                          bgp_peer_id)

    @staticmethod
    def _get_ml2_driver_entity_type_id():
        return "{}.{}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                              fm_constants.FM_ENTITY_TYPE_ML2DRIVER)

    @staticmethod
    def _get_ml2_driver_entity_instance_id(hostname, driver):
        return "{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                    hostname,
                                    fm_constants.FM_ENTITY_TYPE_ML2DRIVER,
                                    driver)

    @staticmethod
    def _get_fault_severity(severity):
        """Map a fault driver severity to an FM API severity"""
        map = {fm.FM_SEVERITY_CRITICAL:
               fm_constants.FM_ALARM_SEVERITY_CRITICAL,
               fm.FM_SEVERITY_MAJOR:
               fm_constants.FM_ALARM_SEVERITY_MAJOR,
               fm.FM_SEVERITY_MINOR:
               fm_constants.FM_ALARM_SEVERITY_MINOR,
               fm.FM_SEVERITY_CLEAR:
               fm_constants.FM_ALARM_SEVERITY_CLEAR}
        return map[severity]

    def report_port_state_fault(self, hostname, port_id, severity):
        entity_type_id = self._get_port_entity_type_id()
        entity_instance_id = self._get_port_entity_instance_id(hostname,
                                                               port_id)
        fm_severity = self._get_fault_severity(severity)

        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_NETWORK_PORT,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=entity_type_id,
            entity_instance_id=entity_instance_id,
            severity=fm_severity,
            reason_text=_("'Data' Port failed."),
            alarm_type=fm_constants.FM_ALARM_TYPE_4,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_29,
            proposed_repair_action=_("Check cabling and far-end port "
                                     "configuration and status on adjacent "
                                     "equipment."),
            service_affecting=True)
        self.fm_api.set_fault(fault)

    def clear_port_state_fault(self, hostname, port_id):
        entity_instance_id = self._get_port_entity_instance_id(hostname,
                                                               port_id)
        self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_PORT,
                                entity_instance_id)

    def get_port_state_faults(self, hostname):
        return self.fm_api.get_faults_by_id(
            fm_constants.FM_ALARM_ID_NETWORK_PORT)

    def report_interface_state_fault(self, hostname, interface_id, severity):
        entity_type_id = self._get_interface_entity_type_id()
        entity_instance_id = \
            self._get_interface_entity_instance_id(hostname, interface_id)

        fm_severity = self._get_fault_severity(severity)

        if fm_severity == fm_constants.FM_ALARM_SEVERITY_CRITICAL:
            reason_text = _("'Data' Interface failed.")
        else:
            reason_text = _("'Data' Interface degraded.")

        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_NETWORK_INTERFACE,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=entity_type_id,
            entity_instance_id=entity_instance_id,
            severity=fm_severity,
            reason_text=reason_text,
            alarm_type=fm_constants.FM_ALARM_TYPE_4,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_29,
            proposed_repair_action=_("Check cabling and far-end port "
                                     "configuration and status on adjacent "
                                     "equipment."),
            service_affecting=True)
        self.fm_api.set_fault(fault)

    def clear_interface_state_fault(self, hostname, interface_id):
        entity_instance_id = \
            self._get_interface_entity_instance_id(hostname, interface_id)
        self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_INTERFACE,
                                entity_instance_id)

    def get_interface_state_faults(self, hostname):
        return self.fm_api.get_faults_by_id(
            fm_constants.FM_ALARM_ID_NETWORK_INTERFACE)

    def report_providernet_fault(self, providernet_id):
        entity_type_id = self._get_providernet_entity_type_id()
        entity_instance_id = \
            self._get_providernet_entity_instance_id(providernet_id)

        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_NETWORK_PROVIDERNET,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=entity_type_id,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
            reason_text=_("No enabled compute host with connectivity "
                          "to provider network."),
            alarm_type=fm_constants.FM_ALARM_TYPE_7,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_55,
            proposed_repair_action=_("Enable compute hosts with required "
                                     "provider network connectivity."),
            service_affecting=True)
        self.fm_api.set_fault(fault)

    def clear_providernet_fault(self, providernet_id):
        """
        Clear a fault management alarm condition for provider network status
        """
        entity_instance_id = \
            self._get_providernet_entity_instance_id(providernet_id)
        self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_PROVIDERNET,
                                entity_instance_id)

    def report_providernet_connectivity_fault(self, providernet_id, hostname,
                                              segmentation_ranges):
        entity_type_id = self._get_providernet_entity_type_id()
        entity_instance_id = \
            self._get_providernet_entity_instance_id(providernet_id, hostname)
        reason_text = self._get_providernet_connectivity_reason(
            providernet_id, hostname, segmentation_ranges)

        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_NETWORK_PROVIDERNET_CONNECTIVITY,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=entity_type_id,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
            reason_text=reason_text,
            alarm_type=fm_constants.FM_ALARM_TYPE_7,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_55,
            proposed_repair_action=_("Check neighbour switch port VLAN"
                                     " assignments."),
            service_affecting=True)
        self.fm_api.set_fault(fault)

    def clear_providernet_connectivity_fault(self, providernet_id, hostname):
        """
        Clear a fault management alarm condition for connectivity
         for a providernet.
        """
        entity_instance_id = \
            self._get_providernet_entity_instance_id(providernet_id, hostname)
        alarm_id = fm_constants.FM_ALARM_ID_NETWORK_PROVIDERNET_CONNECTIVITY
        self.fm_api.clear_fault(alarm_id, entity_instance_id)

    def report_agent_fault(self, hostname, agent_id):
        """
        Generate a fault management alarm condition for agent alive
        """
        entity_type_id = self._get_agent_entity_type_id()
        entity_instance_id = self._get_agent_entity_instance_id(hostname,
                                                                agent_id)

        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_NETWORK_AGENT,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=entity_type_id,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
            reason_text=_("Networking Agent not responding."),
            alarm_type=fm_constants.FM_ALARM_TYPE_7,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_55,
            proposed_repair_action=(
                _("If condition persists, attempt to clear issue by "
                  "administratively locking and unlocking the Host.")),
            service_affecting=True)
        self.fm_api.set_fault(fault)

    def clear_agent_fault(self, hostname, agent_id):
        """
        Clear a fault management alarm condition for agent alive
        """
        entity_instance_id = self._get_agent_entity_instance_id(hostname,
                                                                agent_id)
        self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_AGENT,
                                entity_instance_id)
        self.fm_api.clear_all("%s.bgp-peer" % entity_instance_id)

    def report_bgp_peer_down_fault(self, host_id, agent_id, bgp_peer_id):
        """
        Generate a fault management alarm condition for BGP peer down
        """
        entity_type_id = self._get_bgp_peer_entity_type_id()
        entity_instance_id = self._get_bgp_peer_entity_instance_id(host_id,
                                                                   agent_id,
                                                                   bgp_peer_id)
        reason_text = (_("Dynamic routing agent %(agent_id)s lost connectivity"
                         " to peer %(bgp_peer_id)s.") %
                       {"agent_id": agent_id, "bgp_peer_id": bgp_peer_id})

        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_NETWORK_BGP_PEER,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=entity_type_id,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
            reason_text=reason_text,
            alarm_type=fm_constants.FM_ALARM_TYPE_7,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_55,
            proposed_repair_action=(
                _("If condition persists, fix connectivity to peer.")),
            service_affecting=True,
            suppression=True)
        self.fm_api.set_fault(fault)

    def clear_bgp_peer_down_fault(self, host_id, agent_id, bgp_peer_id):
        """
        Clear a fault management alarm condition for BGP peer down
        """
        entity_instance_id = self._get_bgp_peer_entity_instance_id(host_id,
                                                                   agent_id,
                                                                   bgp_peer_id)
        self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_BGP_PEER,
                                entity_instance_id)

    def report_ml2_driver_fault(self, hostname, driver, reason):
        """
        Generate a fault management alarm condition for ML2 driver
        audit failure
        """
        entity_type_id = self._get_ml2_driver_entity_type_id()
        entity_instance_id = self._get_ml2_driver_entity_instance_id(hostname,
                                                                    driver)
        fault = fm_api.Fault(
            alarm_id=fm_constants.FM_ALARM_ID_NETWORK_ML2_DRIVER,
            alarm_state=fm_constants.FM_ALARM_STATE_SET,
            entity_type_id=entity_type_id,
            entity_instance_id=entity_instance_id,
            severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
            reason_text=reason,
            alarm_type=fm_constants.FM_ALARM_TYPE_3,
            probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_55,
            proposed_repair_action=(
                _("Monitor and if condition persists, "
                  "contact next level of support.")),
            service_affecting=True)
        self.fm_api.set_fault(fault)

    def clear_ml2_driver_fault(self, hostname, driver):
        """
        Clear a fault management alarm condition for agent alive
        """
        entity_instance_id = self._get_ml2_driver_entity_instance_id(hostname,
                                                                    driver)
        self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_ML2_DRIVER,
                                entity_instance_id)
