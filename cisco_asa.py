"""
https://docs.nautobot.com/projects/core/en/stable/development/jobs/

"""

from .discover_utils import utils
import ipaddress
import re
import uuid

# Job
from nautobot.apps.jobs import (
    Job,
    register_jobs,
    ObjectVar,
    StringVar,
    BooleanVar,
    MultiObjectVar,
)

# DCIM
from nautobot.dcim.choices import (
    InterfaceTypeChoices
)
from nautobot.dcim.models import (
    Location,
    DeviceType,
    Platform,
    Device,
    Interface,
)
from nautobot.ipam.models import Prefix, IPAddress

# Extras
from nautobot.extras.models import Role, SecretsGroup
from nautobot.vpn.models import (
    VPN,
    VPNProfile,
    VPNPhase1Policy,
    VPNPhase2Policy,
    VPNProfilePhase1PolicyAssignment,
    VPNProfilePhase2PolicyAssignment,
    VPNTunnel,
    VPNTunnelEndpoint,
)

name = "Discovery"

ASA_DYNAMIC_SPLIT_DOMAIN_COMMAND = (
    "show running-config all | include anyconnect-custom-data "
    "dynamic-split-include-domains dynamic-split-domain"
)


class OnboardCiscoASA(Job):
    class Meta:
        name = "Onboarding: Cisco ASA"
        description = """
            Discovers initial information for Cisco ASA/FP devices by connecting via SSH and running various show commands.
        """
        has_sensitive_variables = False
        soft_time_limit = 86400
        time_limit = 86410

    location = ObjectVar(required=True, label="Location", model=Location,
                         description="Assigned Location for the onboarded device.")

    devices = StringVar(
        label="IP Address/FQDN",
        required=True,
        description="IP Address/DNS Name of the device to onboard, specify in a comma separated list for multiple devices.",
    )

    credentials = ObjectVar(
        model=SecretsGroup,
        required=True,
        description="SecretsGroup for Device connection credentials.",
    )

    platform = ObjectVar(
        label="Platform",
        description="Device platform. Define ONLY to override auto-recognition of platform.",
        model=Platform,
        required=False,
    )

    role = ObjectVar(
        label="Role",
        description="Device role. Define ONLY to override auto-recognition of role.",
        model=Role,
        required=False,
    )
    device_type = ObjectVar(
        label="Device Type",
        description="Device type. Define ONLY to override auto-recognition of type.",
        model=DeviceType,
        required=False,
    )

    debug = BooleanVar(
        label="Debug",
        description="If enabled provide more detailed logs",
        default=False,
    )

    def run(self, *args, **kwargs):
        self.nos = "cisco_asa"
        self.debug = kwargs["debug"]
        self.util = utils(logger=self.logger, debug=self.debug)
        creds = self.util.parse_credentials(kwargs["credentials"])

        self.username = creds["username"]
        self.password = creds["password"]
        self.credentials = kwargs["credentials"]
        self.devices = kwargs["devices"].replace(" ", "").split(",")
        self.location = kwargs["location"]
        if self.debug:
            self.logger.debug("Parsed until platform")
        self.platform = kwargs["platform"]
        self.device_type = kwargs["device_type"]
        self.role = kwargs["role"]
        self.util.prefetch_device_types("Cisco")

        self.commands = [
            "show interface detail",
            "show failover",
            "show version",
            "show run all tunnel-group",
            "show run tunnel-group",
            "show run group-policy",
            "show run access-list",
            "show run object",
            "show run object-group",
            "show run crypto ikev1",
            "show run crypto ikev2",
            "show run crypto ipsec",
            "show run crypto map",
            "show run all crypto isakmp",
            ASA_DYNAMIC_SPLIT_DOMAIN_COMMAND,
        ]

        for device in self.devices:
            self._discover(device=device)

    def _discover(self, device: str):

        parsed_results = self.util.parse_asa_cli(
            username=self.username,
            password=self.password,
            address=device,
            commands=self.commands,
        )
        hostname = self.util.nautobot_hostname(
            parsed_results["show version"]["version"]["hostname"]
        )
        if parsed_results["show failover"]:
            failover_data = parsed_results["show failover"].get("failover", {})
            if failover_data.get("failover_enabled") and failover_data.get("failover_unit") == "Secondary":
                hostname = self.util.next_name(hostname)

        if not self.device_type:
            self.device_type = self.util.get_device_type(
                model=parsed_results["show version"]["version"]["device_type"])

        if not self.platform:
            self.platform = self.util.get_platform(
                name="cisco_asa", network_driver="cisco_asa", manufacturer=self.util.get_manufacturer("Cisco"))

        if not self.role:
            self.role = self.util.network_role

        nb_host = self.util.get_device(
            name=hostname,
            device_type=self.device_type,
            location=self.location,
            platform=self.platform,
            serial=parsed_results["show version"]["version"]["serial_number"],
            role=self.role,
        )

        for iface_name, iface in parsed_results["show interface detail"]["interfaces"].items():
            iface_name = self.util.real_interface_name(iface_name)
            if iface.get("ipv4", False):
                if iface['ipv4']['ip'] == device:
                    if self.debug:
                        self.logger.debug(
                            f"Found Mgmt Address: {iface['ipv4']['ip']}")
                    nb_iface = self.util.get_interface(
                        device=nb_host,
                        name=iface_name,
                        interface_type=self.util.guess_interface_type_from_name(
                            name=iface_name),
                    )
                    ip_int = ipaddress.ip_interface(
                        iface['ipv4']['with_prefixlen'])

                    if ip_int.is_global:
                        nb_tag = self.util.get_tag(name="EXTERNAL", content_types=[
                                                   self.util.get_content_type(Interface)], color="aa1409")
                        if "EXTERNAL" not in [x for x in nb_iface.tags.values_list("name", flat=True)]:
                            nb_iface.tags.add(nb_tag)
                            self.logger.info(
                                f"{hostname}: Tagged 'EXTERNAL' to interface {nb_iface.name}")

                    nb_address = self.util.get_or_create_address(
                        str(ip_int.with_prefixlen), interface=nb_iface)
                    nb_iface.add_ip_addresses(nb_address)
                    if nb_host.primary_ip4 != nb_address:
                        nb_host.primary_ip4 = nb_address
                        nb_host.validated_save()
                    break


class CiscoASA(Job):
    class Meta:
        name = "Discovery: Cisco ASA"
        description = """
            Discovers additional information for Cisco ASA/FP devices by connecting via SSH and running various show commands.
        """
        has_sensitive_variables = False
        soft_time_limit = 86400
        time_limit = 86410

    device = MultiObjectVar(
        model=Device,
        query_params={"platform": "cisco_asa"},
        required=False,
        description="Select a specific device or leave empty for all ASA devices.",
    )

    credentials = ObjectVar(
        model=SecretsGroup,
        required=True,
        description="SecretsGroup for Device connection credentials.",
    )

    debug = BooleanVar(
        label="Debug",
        description="If enabled provide more detailed logs",
        default=False,
    )

    def run(self, *args, **kwargs):
        self.nos = "cisco_asa"

        self.debug = kwargs["debug"]
        self.util = utils(logger=self.logger, debug=self.debug)
        creds = self.util.parse_credentials(kwargs["credentials"])
        self.username = creds["username"]
        self.password = creds["password"]
        self.credentials = kwargs["credentials"]
        self.devices = kwargs["device"]
        self.util.prefetch_device_types("Cisco")

        self.commands = [
            "show interface detail",
            "show failover",
            "show version",
            "show run all tunnel-group",
            "show run tunnel-group",
            "show run group-policy",
            "show run access-list",
            "show run object",
            "show run object-group",
            "show run crypto ikev1",
            "show run crypto ikev2",
            "show run crypto ipsec",
            "show run crypto map",
            "show run all crypto isakmp",
            ASA_DYNAMIC_SPLIT_DOMAIN_COMMAND,
        ]

        self.platforms = Platform.objects.filter(network_driver=self.nos)

        if not self.devices:
            for platform in self.platforms:
                for device in Device.objects.filter(platform=platform):
                    self._discover(host=device)
        else:
            for device in self.devices:
                self._discover(host=device)

    def _discover(self, host: Device):

        parsed_results = self.util.parse_asa_cli(
            username=self.username,
            password=self.password,
            address=str(ipaddress.ip_interface(host.primary_ip4).ip),
            commands=self.commands,
        )

        if self.debug:
            self.logger.debug(
                f"{host.name}: Parsed commands: {sorted(parsed_results.keys())}")

        if host.primary_ip4:
            if self.debug:
                self.logger.debug(
                    f"{host.name}: Gather information from device. ")

            vpn_command_outputs = {}

            for cmd in parsed_results.keys():
                # if cmd in parsed_results:
                parsed = parsed_results[cmd]
                if self.debug:
                    self.logger.debug(f"{host.name}: Processing '{cmd}'")
                match cmd:

                    case "show failover":
                        if parsed:
                            failover_data = parsed.get("failover", {})
                            if failover_data.get("failover_enabled"):

                                nb_drg = self.util.get_device_redundancy_group(
                                    name=host.name[:-1])

                                if nb_drg and host.device_redundancy_group != nb_drg:
                                    self.logger.info(
                                        (f"{host.name}: added to device redundancy group {nb_drg.name}"))
                                    host.device_redundancy_group = nb_drg

                    case "show version":
                        changed = False

                        if host.serial != parsed["version"]["serial_number"]:
                            host.serial = parsed["version"]["serial_number"]
                            self.logger.info(
                                (f"{host.name}: updated serial# {host.serial}"))
                            changed = True

                        nb_version = self.util.get_version(
                            version=parsed["version"]["asa_version"],
                            platform=host.platform,
                        )

                        nb_image = self.util.get_software_image(
                            version=nb_version,
                            imagename=parsed["version"]["system_image"],
                        )

                        if nb_image:
                            self.util.associate_image_to_device_type(
                                host.device_type, nb_image)

                        if nb_version and nb_image and host.software_version != nb_version:
                            host.software_version = nb_version
                            changed = True

                        if changed:
                            host.validated_save()

                    case "show interface detail":
                        real_interfaces = [self.util.real_interface_name(
                            x).lower() for x in parsed["interfaces"].keys()]
                        self.util.prune_interfaces(
                            device=host, interfaces=real_interfaces)

                        for name, iface in parsed["interfaces"].items():
                            name = self.util.real_interface_name(name)
                            changed = False
                            nb_iface = self.util.get_interface(
                                device=host,
                                name=name,
                                interface_type=self.util.guess_interface_type_from_name(
                                    name=name),
                            )

                            if "." in name:
                                nb_parent = self.util.get_interface(
                                    device=host,
                                    name=name.split(".")[0],
                                    interface_type=self.util.guess_interface_type_from_name(
                                        name=name.split(".")[0]),
                                )
                                if nb_iface.parent_interface != nb_parent:
                                    if nb_iface.type != InterfaceTypeChoices.TYPE_VIRTUAL:
                                        nb_iface.type = InterfaceTypeChoices.TYPE_VIRTUAL
                                        self.logger.info(
                                            (f"{host.name}: changed {name} type to virtual"))
                                        changed = True
                                    nb_iface.parent_interface = nb_parent
                                    changed = True
                                    self.logger.info(
                                        (f"{host.name}: set {name} parent interface to {nb_parent.name}"))

                            if "name" in iface:
                                if nb_iface.description != iface["name"]:
                                    nb_iface.description = iface["name"]
                                    changed = True
                                    self.logger.info(
                                        (f"{host.name}: Updating {name} Description to: '{iface['name']}'"))

                            if "admin_status" in iface:
                                if nb_iface.enabled != iface["admin_status"]:
                                    nb_iface.enabled = iface["admin_status"]
                                    changed = True
                                    self.logger.info(
                                        (f"{host.name}: Updating {name} Admin status to: {iface['admin_status']}"))

                            if "mac_address" in iface:
                                if nb_iface.mac_address != self.util.extract_mac(iface["mac_address"]):
                                    nb_iface.mac_address = self.util.extract_mac(
                                        iface["mac_address"])
                                    changed = True
                                    self.logger.info(
                                        (f"{host.name}: Updating {name} MAC Address to: {self.util.extract_mac( iface['mac_address'])}"))

                            if "mtu" in iface:
                                if nb_iface.mtu != int(iface["mtu"]):
                                    nb_iface.mtu = int(iface["mtu"])
                                    changed = True
                                    self.logger.info(
                                        (f"{host.name}: Updating {name} MTU to: {iface['mtu']}"))

                            if "ipv4" in iface:

                                ip_int = ipaddress.ip_interface(
                                    iface['ipv4']['with_prefixlen'])

                                if ip_int.is_global:
                                    nb_tag = self.util.get_tag(
                                        name="EXTERNAL",
                                        content_types=[
                                            self.util.get_content_type(Interface)],
                                        color="aa1409",
                                    )
                                    if "EXTERNAL" not in [x for x in nb_iface.tags.values_list("name", flat=True)]:
                                        nb_iface.tags.add(nb_tag)
                                        self.logger.info(
                                            f"{host.name}: Tagged 'EXTERNAL' to interface {nb_iface.name}")

                                nb_address = self.util.get_or_create_address(
                                    address_with_cidr=str(ip_int.with_prefixlen), interface=nb_iface)
                                if nb_address:
                                    try:
                                        nb_iface.ip_addresses.add(nb_address)
                                        nb_location = self.util.get_validated_location(
                                            host.location)
                                        nb_address.parent.locations.add(
                                            nb_location)
                                    except Exception as e:
                                        if self.debug:
                                            self.logger.debug(
                                                f"{host.name}: {e}")

                            if changed:
                                nb_iface.validated_save()

                    case "show run tunnel-group" | "show run all tunnel-group" | "show run group-policy" | "show run access-list" | "show run object" | "show run object-group" | "show run crypto ikev1" | "show run crypto ikev2" | "show run crypto ipsec" | "show run crypto map" | "show run all crypto isakmp" | "show running-config all | include anyconnect-custom-data dynamic-split-include-domains dynamic-split-domain":
                        if isinstance(parsed, dict):
                            vpn_command_outputs[cmd] = parsed

                    case "show bgp all summary":
                        pass

            self._sync_vpn_models(
                host=host, command_outputs=vpn_command_outputs)

            if self.debug:
                vpn_cmds = sorted(vpn_command_outputs.keys())
                self.logger.debug(
                    f"{host.name}: VPN command outputs collected: {vpn_cmds}")

    def _safe_int(self, value):
        try:
            return int(str(value))
        except Exception:
            return None

    def _safe_role(self, role_obj):
        if not role_obj:
            return None
        try:
            if Role.objects.filter(pk=role_obj.pk).exists():
                return role_obj
        except Exception:
            return None
        return None

    def _role_by_name(self, role_name: str):
        if not role_name:
            return None
        return Role.objects.filter(name__iexact=role_name).order_by("id").first()

    def _preferred_endpoint_role(self, preferred_name: str, fallback_role: Role = None):
        preferred = self._role_by_name(preferred_name)
        if preferred:
            return preferred
        return self._safe_role(fallback_role)

    def _resolve_existing_ipaddress(self, ip_text: str):
        ip_value = str(ip_text or "").strip()
        if not ip_value:
            return None

        try:
            ip_obj = ipaddress.ip_address(ip_value)
            ip_value = str(ip_obj)
        except Exception:
            return None

        existing = IPAddress.objects.filter(
            host=ip_value).order_by("id").first()
        if existing:
            return existing

        mask_length = 32 if ip_obj.version == 4 else 128
        return IPAddress.objects.filter(host=ip_value, mask_length=mask_length).order_by("id").first()

    def _has_parent_prefix_for_ip(self, ip_text: str):
        ip_value = str(ip_text or "").strip()
        if not ip_value:
            return False

        try:
            ip_addr = ipaddress.ip_address(ip_value)
        except Exception:
            return False

        for prefix in Prefix.objects.only("prefix"):
            try:
                network = ipaddress.ip_network(
                    str(prefix.prefix), strict=False)
            except Exception:
                continue
            if network.version != ip_addr.version:
                continue
            if ip_addr in network:
                return True
        return False

    def _resolve_or_create_ipaddress_with_parent(self, ip_text: str):
        ip_value = str(ip_text or "").strip()
        if not ip_value:
            return None

        existing = self._resolve_existing_ipaddress(ip_value)
        if existing:
            return existing

        try:
            return self.util.get_or_create_address(address=f"{ip_value}/32")
        except Exception:
            return None

    def _extract_command_text(self, parsed) -> str:
        if not isinstance(parsed, dict):
            return str(parsed or "")

        raw_text = parsed.get("raw", "")
        if raw_text:
            return raw_text

        lines = []

        def _walk(value):
            if isinstance(value, dict):
                if "line" in value and isinstance(value["line"], str):
                    lines.append(value["line"])
                elif "statement" in value and isinstance(value["statement"], str):
                    lines.append(value["statement"])
                elif "setting" in value and isinstance(value["setting"], str):
                    lines.append(value["setting"])
                else:
                    for nested in value.values():
                        _walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    _walk(nested)

        _walk(parsed)
        return "\n".join(lines)

    def _command_text(self, command_outputs: dict, command: str) -> str:
        parsed = command_outputs.get(command, "")
        if isinstance(parsed, dict):
            return self._extract_command_text(parsed)
        return str(parsed or "")

    def _parse_anyconnect_split_domains(self, raw_output: str) -> list:
        split_domains = []
        seen_domains = set()
        pattern = re.compile(
            r"^\s*anyconnect-custom-data\s+dynamic-split-include-domains\s+"
            r"dynamic-split-domain(?:\s+value)?\s+(.+?)\s*$",
            re.IGNORECASE,
        )

        for line in str(raw_output or "").splitlines():
            match = pattern.match(line)
            if not match:
                continue

            for domain in match.group(1).split(","):
                normalized_domain = domain.strip()
                if not normalized_domain or normalized_domain in seen_domains:
                    continue
                seen_domains.add(normalized_domain)
                split_domains.append(normalized_domain)

        return split_domains

    def _sync_anyconnect_local_context(self, host: Device, split_domains: list) -> bool:
        original_context = host.local_config_context_data
        if not isinstance(original_context, dict):
            original_context = {}

        context = dict(original_context)
        existing_anyconnect = context.get("anyconnect")
        if isinstance(existing_anyconnect, dict):
            anyconnect_context = dict(existing_anyconnect)
        else:
            anyconnect_context = {}

        anyconnect_context["split-domains"] = list(split_domains or [])
        context["anyconnect"] = anyconnect_context

        if context == original_context:
            return False

        host.local_config_context_data = context
        if hasattr(host, "has_local_config_context_data") and host.has_local_config_context_data is not True:
            host.has_local_config_context_data = True
        host.validated_save()
        return True

    def _parse_ikev1_policies_structured(self, parsed: dict) -> dict:
        policies = {}
        if not isinstance(parsed, dict):
            return policies

        for policy in parsed.get("ikev1_policies", []) or []:
            priority = str(policy.get("priority", "")).strip()
            if not priority:
                continue
            policies.setdefault(priority, {})
            for key in ["authentication", "encryption", "hash", "group", "lifetime"]:
                value = policy.get(key)
                if value:
                    policies[priority][key] = str(value).strip()

        for line_entry in parsed.get("ikev1_policy_lines", []) or []:
            priority = str(line_entry.get("priority", "")).strip()
            setting = str(line_entry.get("setting", "")).strip()
            if not priority or not setting:
                continue
            policies.setdefault(priority, {})
            parts = setting.split(None, 1)
            if len(parts) == 2:
                policies[priority][parts[0]] = parts[1]

        return policies

    def _parse_isakmp_policies_structured(self, parsed: dict) -> dict:
        policies = {}
        if not isinstance(parsed, dict):
            return policies

        for policy in parsed.get("isakmp_policies", []) or []:
            priority = str(policy.get("priority", "")).strip()
            if not priority:
                continue
            policies.setdefault(priority, {})
            for key in ["authentication", "encryption", "hash", "group", "lifetime"]:
                value = policy.get(key)
                if value:
                    policies[priority][key] = str(value).strip()

        for line_entry in parsed.get("isakmp_policy_lines", []) or []:
            priority = str(line_entry.get("priority", "")).strip()
            setting = str(line_entry.get("setting", "")).strip()
            if not priority or not setting:
                continue
            policies.setdefault(priority, {})
            parts = setting.split(None, 1)
            if len(parts) == 2:
                policies[priority][parts[0]] = parts[1]

        for entry in parsed.get("isakmp_entries", []) or []:
            setting = str(entry.get("setting", "")).strip()
            if not setting:
                continue
            m_policy = re.match(r"^policy\s+(\d+)\s+(.+)$", setting)
            if not m_policy:
                continue
            priority = m_policy.group(1)
            remainder = m_policy.group(2).strip()
            policies.setdefault(priority, {})
            parts = remainder.split(None, 1)
            if len(parts) == 2:
                policies[priority][parts[0]] = parts[1]

        return policies

    def _parse_ikev2_policies_structured(self, parsed: dict) -> dict:
        policies = {}
        if not isinstance(parsed, dict):
            return policies

        for policy in parsed.get("ikev2_policies", []) or []:
            priority = str(policy.get("priority", "")).strip()
            if not priority:
                continue
            policies.setdefault(priority, {})
            field_map = {
                "encryption": "encryption",
                "integrity": "integrity",
                "prf": "prf",
                "group": "group",
                "lifetime": "lifetime",
            }
            for source_key, target_key in field_map.items():
                value = policy.get(source_key)
                if value:
                    policies[priority][target_key] = str(value).strip()

        for line_entry in parsed.get("ikev2_policy_lines", []) or []:
            priority = str(line_entry.get("priority", "")).strip()
            setting = str(line_entry.get("setting", "")).strip()
            if not priority or not setting:
                continue
            policies.setdefault(priority, {})
            parts = setting.split(None, 1)
            if len(parts) == 2:
                policies[priority][parts[0]] = parts[1]

        return policies

    def _parse_transform_sets_structured(self, parsed: dict) -> dict:
        transform_sets = {}
        if not isinstance(parsed, dict):
            return transform_sets

        for entry in parsed.get("transform_sets", []) or []:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            transforms = str(entry.get("transforms", "")).strip()
            transform_set = transform_sets.setdefault(
                name, {"transforms": "", "mode": ""})

            if transforms.lower().startswith("mode "):
                mode = transforms.split(None, 1)[1].strip() if len(
                    transforms.split(None, 1)) == 2 else ""
                if mode:
                    transform_set["mode"] = mode
                continue

            if not transforms:
                encryption = str(entry.get("encryption", "")).strip()
                integrity = str(entry.get("integrity", "")).strip()
                transforms = " ".join(
                    [x for x in [encryption, integrity] if x]).strip()
            if transforms:
                transform_set["transforms"] = transforms

        for entry in parsed.get("transform_set_modes", []) or []:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            transform_sets.setdefault(name, {"transforms": "", "mode": ""})
            mode = str(entry.get("mode", "")).strip()
            if mode:
                transform_sets[name]["mode"] = mode

        return transform_sets

    def _parse_ipsec_proposals_structured(self, parsed: dict) -> dict:
        proposals = {}
        if not isinstance(parsed, dict):
            return proposals

        for entry in parsed.get("proposals", []) or []:
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            proposal = proposals.setdefault(name, {})

            encryption = str(entry.get("encryption", "")).strip()
            integrity = str(entry.get("integrity", "")).strip()
            if encryption:
                proposal.setdefault("encryption", [])
                if encryption not in proposal["encryption"]:
                    proposal["encryption"].append(encryption)
            if integrity:
                proposal.setdefault("integrity", [])
                if integrity not in proposal["integrity"]:
                    proposal["integrity"].append(integrity)

        return proposals

    def _parse_tunnel_groups(self, raw_output: str) -> dict:
        tunnel_groups = {}
        current_name = None
        current_section = None

        for line in raw_output.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue

            m_type = re.match(
                r"^tunnel-group\s+(\S+)\s+type\s+(\S+)", stripped)
            if m_type:
                current_name = m_type.group(1)
                tunnel_groups.setdefault(current_name, {
                    "type": m_type.group(2),
                    "general_attributes": {},
                    "ipsec_attributes": {},
                    "other_attributes": {},
                })
                continue

            m_section = re.match(
                r"^tunnel-group\s+(\S+)\s+(general|ipsec|webvpn)-attributes", stripped)
            if m_section:
                current_name = m_section.group(1)
                section_name = m_section.group(2)
                tunnel_groups.setdefault(current_name, {
                    "type": "",
                    "general_attributes": {},
                    "ipsec_attributes": {},
                    "other_attributes": {},
                })
                if section_name == "general":
                    current_section = "general_attributes"
                elif section_name == "ipsec":
                    current_section = "ipsec_attributes"
                else:
                    current_section = "other_attributes"
                continue

            m_inline = re.match(
                r"^tunnel-group\s+(\S+)\s+([a-zA-Z0-9_-]+)\s+(.+)$", stripped)
            if m_inline and "attributes" not in stripped:
                tg_name = m_inline.group(1)
                key = m_inline.group(2)
                value = m_inline.group(3)
                tunnel_groups.setdefault(tg_name, {
                    "type": "",
                    "general_attributes": {},
                    "ipsec_attributes": {},
                    "other_attributes": {},
                })
                tunnel_groups[tg_name]["other_attributes"][key] = value
                continue

            if current_name and line.startswith(" "):
                parts = stripped.strip().split(None, 1)
                if len(parts) == 2 and current_section:
                    tunnel_groups[current_name][current_section][parts[0]] = parts[1]

        return tunnel_groups

    def _parse_group_policies(self, raw_output: str) -> dict:
        group_policies = {}
        current_name = None
        in_attributes = False

        for line in raw_output.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue

            m_policy = re.match(r"^group-policy\s+(\S+)\s+internal", stripped)
            if m_policy:
                current_name = m_policy.group(1)
                group_policies.setdefault(current_name, {"attributes": {}})
                in_attributes = False
                continue

            m_attr_section = re.match(
                r"^group-policy\s+(\S+)\s+attributes", stripped)
            if m_attr_section:
                current_name = m_attr_section.group(1)
                group_policies.setdefault(current_name, {"attributes": {}})
                in_attributes = True
                continue

            if current_name and in_attributes and line.startswith(" "):
                parts = stripped.strip().split(None, 1)
                if len(parts) == 2:
                    group_policies[current_name]["attributes"][parts[0]] = parts[1]

        return group_policies

    def _parse_ikev1_policies(self, raw_output: str) -> dict:
        policies = {}
        current = None

        for line in raw_output.splitlines():
            stripped = line.rstrip()
            m_policy = re.match(
                r"^crypto ikev1 policy\s+(\d+)(?:\s+(.+))?$", stripped)
            if not m_policy:
                m_policy = re.match(
                    r"^crypto isakmp policy\s+(\d+)(?:\s+(.+))?$", stripped)
            if m_policy:
                current = m_policy.group(1)
                policies.setdefault(current, {})
                inline_rest = (m_policy.group(2) or "").strip()
                if inline_rest:
                    policies[current]["inline"] = inline_rest
                continue

            if current and stripped and not stripped.startswith("crypto "):
                key_value = stripped.strip().split(None, 1)
                if len(key_value) == 2:
                    policies[current][key_value[0]] = key_value[1]

        return policies

    def _parse_ikev2_policies(self, raw_output: str) -> dict:
        policies = {}
        current = None

        for line in raw_output.splitlines():
            stripped = line.rstrip()
            m_policy = re.match(
                r"^crypto ikev2 policy\s+(\d+)(?:\s+(.+))?$", stripped)
            if m_policy:
                current = m_policy.group(1)
                policies.setdefault(current, {})
                inline_rest = (m_policy.group(2) or "").strip()
                if inline_rest:
                    policies[current]["inline"] = inline_rest
                continue

            if current and stripped and not stripped.startswith("crypto "):
                key_value = stripped.strip().split(None, 1)
                if len(key_value) == 2:
                    policies[current][key_value[0]] = key_value[1]

        return policies

    def _parse_transform_sets(self, raw_output: str) -> dict:
        transform_sets = {}
        current_name = None

        for line in raw_output.splitlines():
            stripped = line.rstrip()
            m_ts = re.match(
                r"^crypto ipsec ikev\d transform-set\s+(\S+)\s+(.+)$", stripped)
            if m_ts:
                current_name = m_ts.group(1)
                transform_sets.setdefault(current_name, {
                    "transforms": "",
                    "mode": "",
                })

                ts_remainder = (m_ts.group(2) or "").strip()
                if ts_remainder.startswith("mode "):
                    transform_sets[current_name]["mode"] = ts_remainder.replace(
                        "mode ", "", 1).strip()
                elif ts_remainder:
                    transform_sets[current_name]["transforms"] = ts_remainder
                continue

            if current_name and stripped and not stripped.startswith("crypto "):
                m_mode = re.match(r"^mode\s+(\S+)", stripped.strip())
                if m_mode:
                    transform_sets[current_name]["mode"] = m_mode.group(1)

        return transform_sets

    def _parse_ikev2_ipsec_proposals(self, raw_output: str) -> dict:
        proposals = {}
        current_name = None

        for line in raw_output.splitlines():
            stripped = line.rstrip()
            m_proposal = re.match(
                r"^crypto ipsec ikev2 ipsec-proposal\s+(\S+)", stripped)
            if m_proposal:
                current_name = m_proposal.group(1)
                proposals.setdefault(current_name, {})
                continue

            if current_name and stripped and not stripped.startswith("crypto "):
                key_value = stripped.strip().split(None, 1)
                if len(key_value) == 2:
                    key = key_value[0]
                    value = key_value[1]
                    if key not in proposals[current_name]:
                        proposals[current_name][key] = []
                    proposals[current_name][key].append(value)

        return proposals

    def _parse_crypto_maps(self, raw_output: str) -> dict:
        map_interfaces = {}
        map_entries = {}

        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            m_iface = re.match(
                r"^crypto map\s+(\S+)\s+interface\s+(\S+)$", stripped)
            if m_iface:
                map_interfaces[m_iface.group(1)] = m_iface.group(2)
                continue

            m_entry = re.match(
                r"^crypto map\s+(\S+)\s+(\d+)\s+(.+)$", stripped)
            if not m_entry:
                continue

            map_name = m_entry.group(1)
            sequence = m_entry.group(2)
            remainder = m_entry.group(3)
            key = f"{map_name}:{sequence}"

            map_entries.setdefault(key, {
                "map_name": map_name,
                "sequence": sequence,
                "match_address": None,
                "peers": [],
                "transform_sets": [],
                "ikev2_proposals": [],
                "ike_version": None,
                "pfs_group": None,
                "lifetime_seconds": None,
            })

            if remainder.startswith("match address "):
                map_entries[key]["match_address"] = remainder.replace(
                    "match address ", "", 1)
            elif remainder.startswith("set peer "):
                peers = remainder.replace("set peer ", "", 1).split()
                for peer in peers:
                    if peer and peer not in map_entries[key]["peers"]:
                        map_entries[key]["peers"].append(peer)
            elif remainder.startswith("set ikev1 transform-set "):
                transforms = remainder.replace(
                    "set ikev1 transform-set ", "", 1).split()
                map_entries[key]["ike_version"] = "v1"
                for transform in transforms:
                    if transform not in map_entries[key]["transform_sets"]:
                        map_entries[key]["transform_sets"].append(transform)
            elif remainder.startswith("set ikev2 ipsec-proposal "):
                proposals = remainder.replace(
                    "set ikev2 ipsec-proposal ", "", 1).split()
                map_entries[key]["ike_version"] = "v2"
                for proposal in proposals:
                    if proposal not in map_entries[key]["ikev2_proposals"]:
                        map_entries[key]["ikev2_proposals"].append(proposal)
            elif remainder.startswith("set pfs"):
                pfs_value = remainder.replace("set pfs", "", 1).strip()
                map_entries[key]["pfs_group"] = pfs_value or "enabled"
            elif remainder.startswith("set security-association lifetime seconds "):
                map_entries[key]["lifetime_seconds"] = remainder.replace(
                    "set security-association lifetime seconds ", "", 1).strip()

        return {
            "interfaces": map_interfaces,
            "entries": map_entries,
        }

    def _parse_global_vpn_settings(self, isakmp_raw: str, ikev2_raw: str) -> dict:
        settings = {
            "nat_traversal": False,
            "keepalive_enabled": False,
            "keepalive_interval": None,
            "keepalive_retries": None,
            "extra_options": [],
        }

        if re.search(r"crypto isakmp nat-traversal", isakmp_raw):
            settings["nat_traversal"] = True

        keepalive_match = re.search(
            r"crypto isakmp keepalive\s+(?:threshold\s+)?(\d+)(?:\s+(?:retry\s+)?(\d+))?", isakmp_raw)
        if keepalive_match:
            settings["keepalive_enabled"] = True
            settings["keepalive_interval"] = self._safe_int(
                keepalive_match.group(1))
            settings["keepalive_retries"] = self._safe_int(
                keepalive_match.group(2))

        ikev2_keepalive = re.search(
            r"crypto ikev2 keepalive\s+(?:threshold\s+)?(\d+)(?:\s+(?:retry\s+)?(\d+))?", ikev2_raw)
        if ikev2_keepalive and not settings["keepalive_enabled"]:
            settings["keepalive_enabled"] = True
            settings["keepalive_interval"] = self._safe_int(
                ikev2_keepalive.group(1))
            settings["keepalive_retries"] = self._safe_int(
                ikev2_keepalive.group(2))

        for line in (isakmp_raw + "\n" + ikev2_raw).splitlines():
            stripped = line.strip()
            if stripped.startswith("crypto isakmp") or stripped.startswith("crypto ikev2"):
                settings["extra_options"].append(stripped)

        return settings

    def _extract_keepalive_values(self, text: str):
        if not text:
            return None, None

        m = re.search(
            r"(?:threshold\s+)?(\d+)(?:\s+(?:retry\s+)?(\d+))?", str(text), re.IGNORECASE)
        if not m:
            return None, None
        return self._safe_int(m.group(1)), self._safe_int(m.group(2))

    def _keepalive_from_tunnel_group(self, tunnel_group_data: dict):
        attr_dicts = [
            tunnel_group_data.get("ipsec_attributes", {}),
            tunnel_group_data.get("general_attributes", {}),
            tunnel_group_data.get("other_attributes", {}),
        ]

        for attrs in attr_dicts:
            for key, value in attrs.items():
                key_text = str(key).lower()
                value_text = str(value)
                combined_text = f"{key_text} {value_text.lower()}"
                if "keepalive" not in combined_text:
                    continue
                interval, retries = self._extract_keepalive_values(
                    combined_text)
                enabled = interval is not None or retries is not None
                return {
                    "keepalive_enabled": enabled,
                    "keepalive_interval": interval,
                    "keepalive_retries": retries,
                }

        return {
            "keepalive_enabled": False,
            "keepalive_interval": None,
            "keepalive_retries": None,
        }

    def _is_ip_address(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except Exception:
            return False

    def _parse_asa_acl_address_spec(self, tokens: list, index: int):
        if index >= len(tokens):
            return None, index

        token = tokens[index].lower()
        if token in ["any", "any4", "any6"]:
            return {"kind": "any", "prefix": "0.0.0.0/0"}, index + 1

        if token == "host" and index + 1 < len(tokens):
            host_ip = tokens[index + 1]
            if self._is_ip_address(host_ip):
                return {"kind": "host", "prefix": f"{host_ip}/32"}, index + 2
            return {"kind": "host", "raw": host_ip}, index + 2

        if token == "object" and index + 1 < len(tokens):
            return {"kind": "object", "name": tokens[index + 1]}, index + 2

        if token == "object-group" and index + 1 < len(tokens):
            return {"kind": "object-group", "name": tokens[index + 1]}, index + 2

        if token == "interface" and index + 1 < len(tokens):
            return {"kind": "interface", "name": tokens[index + 1]}, index + 2

        if index + 1 < len(tokens):
            network_ip = tokens[index]
            mask = tokens[index + 1]
            if self._is_ip_address(network_ip) and self._is_ip_address(mask):
                try:
                    network = ipaddress.ip_network(
                        f"{network_ip}/{mask}", strict=False)
                    return {"kind": "subnet", "prefix": str(network)}, index + 2
                except Exception:
                    pass

        return {"kind": "raw", "value": tokens[index]}, index + 1

    def _parse_access_list_protected_prefixes(self, access_list_output):
        acl_entries = {}

        if isinstance(access_list_output, dict):
            for entry in access_list_output.get("access_list_extended", []) or []:
                acl_name = str(entry.get("acl_name", "")).strip()
                action = str(entry.get("action", "")).strip().lower()
                protocol = str(entry.get("protocol", "")).strip().lower()
                statement = str(entry.get("statement", "")).strip()
                if not acl_name or not statement:
                    continue

                tokens = statement.split()
                if not tokens:
                    continue

                src_spec, next_index = self._parse_asa_acl_address_spec(
                    tokens, 0)
                dst_spec, _ = self._parse_asa_acl_address_spec(
                    tokens, next_index)
                if not src_spec or not dst_spec:
                    continue

                acl_entries.setdefault(acl_name, []).append(
                    {
                        "action": action,
                        "protocol": protocol,
                        "source": src_spec,
                        "destination": dst_spec,
                        "line": f"access-list {acl_name} extended {action} {protocol} {statement}",
                    }
                )

            if acl_entries:
                return acl_entries

        raw_output = self._extract_command_text(access_list_output) if isinstance(
            access_list_output, dict) else str(access_list_output or "")

        for line in str(raw_output or "").splitlines():
            stripped = line.strip()
            if not stripped.startswith("access-list "):
                continue

            m = re.match(
                r"^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.+)$",
                stripped,
                re.IGNORECASE,
            )
            if not m:
                continue

            acl_name = m.group(1)
            action = m.group(2).lower()
            protocol = m.group(3).lower()
            remainder = m.group(4).strip()
            tokens = remainder.split()
            if not tokens:
                continue

            src_spec, next_index = self._parse_asa_acl_address_spec(tokens, 0)
            dst_spec, _ = self._parse_asa_acl_address_spec(tokens, next_index)
            if not src_spec or not dst_spec:
                continue

            acl_entries.setdefault(acl_name, []).append(
                {
                    "action": action,
                    "protocol": protocol,
                    "source": src_spec,
                    "destination": dst_spec,
                    "line": stripped,
                }
            )

        return acl_entries

    def _network_prefix_from_ip_mask(self, ip_value: str, mask_value: str):
        if not self._is_ip_address(ip_value) or not self._is_ip_address(mask_value):
            return None
        try:
            return str(ipaddress.ip_network(f"{ip_value}/{mask_value}", strict=False))
        except Exception:
            return None

    def _add_unique(self, items: list, value):
        if value is None:
            return
        if value not in items:
            items.append(value)

    def _parse_object_networks(self, object_output):
        object_networks = {}

        def _ensure(name: str):
            return object_networks.setdefault(
                name,
                {
                    "prefixes": [],
                    "ranges": [],
                    "fqdns": [],
                },
            )

        if isinstance(object_output, dict):
            for entry in object_output.get("object_network_headers", []) or []:
                name = str(entry.get("name", "")).strip()
                if name:
                    _ensure(name)

            host_keys = [
                "object_network_host_entries",
                "object_network_host_with_desc_entries",
                "object_network_hosts",
            ]
            for key in host_keys:
                for entry in object_output.get(key, []) or []:
                    name = str(entry.get("name", "")).strip()
                    host = str(entry.get("host", "")).strip()
                    if not name or not self._is_ip_address(host):
                        continue
                    obj = _ensure(name)
                    self._add_unique(obj["prefixes"], f"{host}/32")

            subnet_keys = [
                "object_network_subnet_entries",
                "object_network_subnet_with_desc_entries",
                "object_network_subnets",
            ]
            for key in subnet_keys:
                for entry in object_output.get(key, []) or []:
                    name = str(entry.get("name", "")).strip()
                    network = str(entry.get("network", "")).strip()
                    mask = str(entry.get("mask", "")).strip()
                    if not name:
                        continue
                    prefix = self._network_prefix_from_ip_mask(network, mask)
                    if not prefix:
                        continue
                    obj = _ensure(name)
                    self._add_unique(obj["prefixes"], prefix)

            range_keys = [
                "object_network_range_entries",
                "object_network_ranges",
            ]
            for key in range_keys:
                for entry in object_output.get(key, []) or []:
                    name = str(entry.get("name", "")).strip()
                    start = str(entry.get("start", "")).strip()
                    end = str(entry.get("end", "")).strip()
                    if not name or not start or not end:
                        continue
                    obj = _ensure(name)
                    self._add_unique(obj["ranges"], f"{start}-{end}")

            fqdn_keys = [
                "object_network_fqdn_entries",
                "object_network_fqdns",
            ]
            for key in fqdn_keys:
                for entry in object_output.get(key, []) or []:
                    name = str(entry.get("name", "")).strip()
                    fqdn = str(entry.get("fqdn", "")).strip()
                    if not name or not fqdn:
                        continue
                    obj = _ensure(name)
                    self._add_unique(obj["fqdns"], fqdn)

        raw_output = self._extract_command_text(object_output) if isinstance(
            object_output, dict) else str(object_output or "")
        current_name = None
        for line in raw_output.splitlines():
            stripped = line.rstrip()
            m_obj = re.match(r"^object\s+network\s+(\S+)$", stripped)
            if m_obj:
                current_name = m_obj.group(1)
                _ensure(current_name)
                continue

            if not current_name or not line.startswith(" "):
                continue

            text = stripped.strip()
            m_host = re.match(r"^host\s+(\S+)$", text)
            if m_host and self._is_ip_address(m_host.group(1)):
                self._add_unique(_ensure(current_name)[
                                 "prefixes"], f"{m_host.group(1)}/32")
                continue

            m_subnet = re.match(r"^subnet\s+(\S+)\s+(\S+)$", text)
            if m_subnet:
                prefix = self._network_prefix_from_ip_mask(
                    m_subnet.group(1), m_subnet.group(2))
                if prefix:
                    self._add_unique(_ensure(current_name)["prefixes"], prefix)
                continue

            m_range = re.match(r"^range\s+(\S+)\s+(\S+)$", text)
            if m_range:
                self._add_unique(_ensure(current_name)[
                                 "ranges"], f"{m_range.group(1)}-{m_range.group(2)}")
                continue

            m_fqdn = re.match(r"^fqdn\s+\S+\s+(.+)$", text)
            if m_fqdn:
                self._add_unique(_ensure(current_name)[
                                 "fqdns"], m_fqdn.group(1).strip())

        return object_networks

    def _parse_object_groups(self, object_group_output):
        object_groups = {}

        def _ensure(name: str):
            return object_groups.setdefault(name, {"members": []})

        def _add_member(name: str, member: dict):
            group = _ensure(name)
            if member not in group["members"]:
                group["members"].append(member)

        if isinstance(object_group_output, dict):
            for entry in object_group_output.get("object_group_headers", []) or []:
                if str(entry.get("group_type", "")).strip().lower() != "network":
                    continue
                name = str(entry.get("name", "")).strip()
                if name:
                    _ensure(name)

            host_keys = [
                "object_group_network_host_entries",
                "object_group_network_host_with_desc_entries",
                "object_group_network_hosts",
            ]
            for key in host_keys:
                for entry in object_group_output.get(key, []) or []:
                    name = str(entry.get("name", "")).strip()
                    host = str(entry.get("host", "")).strip()
                    if name and self._is_ip_address(host):
                        _add_member(
                            name, {"kind": "host", "prefix": f"{host}/32"})

            subnet_keys = [
                "object_group_network_subnet_entries",
                "object_group_network_subnet_with_desc_entries",
                "object_group_network_subnets",
            ]
            for key in subnet_keys:
                for entry in object_group_output.get(key, []) or []:
                    name = str(entry.get("name", "")).strip()
                    network = str(entry.get("network", "")).strip()
                    mask = str(entry.get("mask", "")).strip()
                    prefix = self._network_prefix_from_ip_mask(network, mask)
                    if name and prefix:
                        _add_member(name, {"kind": "subnet", "prefix": prefix})

            object_keys = [
                "object_group_network_object_entries",
                "object_group_network_object_with_desc_entries",
                "object_group_network_member_entries",
                "object_group_network_member_with_desc_entries",
                "object_group_network_objects",
                "object_group_network_members",
            ]
            for key in object_keys:
                for entry in object_group_output.get(key, []) or []:
                    name = str(entry.get("name", "")).strip()
                    object_name = str(entry.get("object_name", "")).strip()
                    if name and object_name:
                        _add_member(
                            name, {"kind": "object", "name": object_name})

            group_keys = [
                "object_group_network_group_object_entries",
                "object_group_network_group_object_with_desc_entries",
                "object_group_network_group_objects",
            ]
            for key in group_keys:
                for entry in object_group_output.get(key, []) or []:
                    name = str(entry.get("name", "")).strip()
                    group_name = str(entry.get("group_name", "")).strip()
                    if name and group_name:
                        _add_member(
                            name, {"kind": "object-group", "name": group_name})

        raw_output = self._extract_command_text(object_group_output) if isinstance(
            object_group_output, dict) else str(object_group_output or "")
        current_name = None
        for line in raw_output.splitlines():
            stripped = line.rstrip()
            m_group = re.match(r"^object-group\s+network\s+(\S+)$", stripped)
            if m_group:
                current_name = m_group.group(1)
                _ensure(current_name)
                continue

            if not current_name or not line.startswith(" "):
                continue

            text = stripped.strip()
            m_host = re.match(r"^network-object\s+host\s+(\S+)$", text)
            if m_host and self._is_ip_address(m_host.group(1)):
                _add_member(current_name, {
                            "kind": "host", "prefix": f"{m_host.group(1)}/32"})
                continue

            m_subnet = re.match(r"^network-object\s+(\S+)\s+(\S+)$", text)
            if m_subnet:
                prefix = self._network_prefix_from_ip_mask(
                    m_subnet.group(1), m_subnet.group(2))
                if prefix:
                    _add_member(current_name, {
                                "kind": "subnet", "prefix": prefix})
                continue

            m_object = re.match(
                r"^(?:network-object\s+object|object)\s+(\S+)$", text)
            if m_object:
                _add_member(current_name, {
                            "kind": "object", "name": m_object.group(1)})
                continue

            m_group_obj = re.match(r"^group-object\s+(\S+)$", text)
            if m_group_obj:
                _add_member(current_name, {
                            "kind": "object-group", "name": m_group_obj.group(1)})

        return object_groups

    def _resolve_acl_spec_to_prefixes(self, spec: dict, object_networks: dict, object_groups: dict, seen_groups=None):
        if not spec:
            return []

        seen_groups = seen_groups or set()
        kind = str(spec.get("kind", "")).lower()

        if kind in ["any", "host", "subnet"] and spec.get("prefix"):
            return [str(spec.get("prefix"))]

        if kind == "object":
            object_name = str(spec.get("name", "")).strip()
            if not object_name:
                return []
            object_data = object_networks.get(object_name, {})
            return list(object_data.get("prefixes", []))

        if kind == "object-group":
            group_name = str(spec.get("name", "")).strip()
            if not group_name or group_name in seen_groups:
                return []

            resolved = []
            next_seen = set(seen_groups)
            next_seen.add(group_name)
            for member in object_groups.get(group_name, {}).get("members", []):
                for prefix in self._resolve_acl_spec_to_prefixes(member, object_networks, object_groups, next_seen):
                    self._add_unique(resolved, prefix)
            return resolved

        return []

    def _build_protected_prefix_map(self, crypto_maps: dict, access_list_output, object_networks: dict, object_groups: dict):
        acl_entries = self._parse_access_list_protected_prefixes(
            access_list_output)
        protected_map = {}

        for entry_key, entry in (crypto_maps or {}).get("entries", {}).items():
            acl_name = (entry.get("match_address") or "").strip()
            if not acl_name:
                continue

            matched_entries = []
            for parsed_acl_name, parsed_entries in acl_entries.items():
                if parsed_acl_name.lower() == acl_name.lower():
                    matched_entries = [
                        parsed for parsed in parsed_entries
                        if str(parsed.get("action", "permit")).lower() == "permit"
                    ]
                    break

            if matched_entries:
                resolved_entries = []
                for parsed in matched_entries:
                    source_prefixes = self._resolve_acl_spec_to_prefixes(
                        parsed.get("source"),
                        object_networks,
                        object_groups,
                    )
                    destination_prefixes = self._resolve_acl_spec_to_prefixes(
                        parsed.get("destination"),
                        object_networks,
                        object_groups,
                    )

                    resolved_entries.append(
                        {
                            **parsed,
                            "source_prefixes": source_prefixes,
                            "destination_prefixes": destination_prefixes,
                            "source_resolved": bool(source_prefixes),
                            "destination_resolved": bool(destination_prefixes),
                        }
                    )

                protected_map[entry_key] = {
                    "match_address": acl_name,
                    "entries": resolved_entries,
                }

        return protected_map

    def _build_vpn_data(self, command_outputs: dict) -> dict:
        ikev1_raw = (
            self._command_text(command_outputs, "show run crypto ikev1")
            + "\n"
            + self._command_text(command_outputs, "show run all crypto isakmp")
        )
        ikev2_raw = (
            self._command_text(command_outputs, "show run crypto ikev2")
            + "\n"
            + self._command_text(command_outputs, "show run all crypto isakmp")
        )
        ipsec_config_raw = self._command_text(
            command_outputs, "show run crypto ipsec")

        ikev1_struct = self._parse_ikev1_policies_structured(
            command_outputs.get("show run crypto ikev1", {}))
        isakmp_struct = self._parse_isakmp_policies_structured(
            command_outputs.get("show run all crypto isakmp", {}))
        ikev1_policies = dict(ikev1_struct)
        for priority, policy in isakmp_struct.items():
            merged = ikev1_policies.setdefault(priority, {})
            merged.update(policy)
        if not ikev1_policies:
            ikev1_policies = self._parse_ikev1_policies(ikev1_raw)

        ikev2_policies = self._parse_ikev2_policies_structured(
            command_outputs.get("show run crypto ikev2", {}))
        if not ikev2_policies:
            ikev2_policies = self._parse_ikev2_policies(ikev2_raw)

        transform_sets = self._parse_transform_sets_structured(
            command_outputs.get("show run crypto ipsec", {}))
        if not transform_sets:
            transform_sets = self._parse_transform_sets(ipsec_config_raw)

        ikev2_ipsec_proposals = self._parse_ipsec_proposals_structured(
            command_outputs.get("show run crypto ipsec", {}))
        if not ikev2_ipsec_proposals:
            ikev2_ipsec_proposals = self._parse_ikev2_ipsec_proposals(
                ipsec_config_raw)

        tunnel_group_text = self._command_text(
            command_outputs, "show run all tunnel-group")
        if not tunnel_group_text.strip():
            tunnel_group_text = self._command_text(
                command_outputs, "show run tunnel-group")

        crypto_maps = self._parse_crypto_maps(
            self._command_text(command_outputs, "show run crypto map")
        )
        object_networks = self._parse_object_networks(
            command_outputs.get("show run object", {})
        )
        object_groups = self._parse_object_groups(
            command_outputs.get("show run object-group", {})
        )
        protected_prefixes = self._build_protected_prefix_map(
            crypto_maps=crypto_maps,
            access_list_output=command_outputs.get("show run access-list", {}),
            object_networks=object_networks,
            object_groups=object_groups,
        )

        return {
            "tunnel_groups": self._parse_tunnel_groups(tunnel_group_text),
            "group_policies": self._parse_group_policies(self._command_text(command_outputs, "show run group-policy")),
            "ikev1_policies": ikev1_policies,
            "ikev2_policies": ikev2_policies,
            "ikev2_ipsec_proposals": ikev2_ipsec_proposals,
            "transform_sets": transform_sets,
            "crypto_maps": crypto_maps,
            "object_networks": object_networks,
            "object_groups": object_groups,
            "protected_prefixes": protected_prefixes,
            "global_settings": self._parse_global_vpn_settings(
                self._command_text(
                    command_outputs, "show run all crypto isakmp"),
                self._command_text(command_outputs, "show run crypto ikev2"),
            ),
        }

    def _resolve_encapsulation(self, tunnel_type: str = "", ike_version: str = ""):
        choices = VPNTunnel._meta.get_field("encapsulation").choices
        if not choices:
            return None

        normalized_tunnel_type = (tunnel_type or "").lower()
        normalized_ike = (ike_version or "").lower()

        if "ipsec" in normalized_tunnel_type or normalized_ike in ["v1", "v2"]:
            for choice_value, choice_label in choices:
                if "ipsec" in str(choice_value).lower() or "ipsec" in str(choice_label).lower():
                    return choice_value

        if "gre" in normalized_tunnel_type:
            for choice_value, choice_label in choices:
                if "gre" in str(choice_value).lower() or "gre" in str(choice_label).lower():
                    return choice_value

        return None

    def _normalize_token(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", (value or "").lower())

    def _field_choices(self, model, field_name: str):
        try:
            return list(model._meta.get_field(field_name).choices or [])
        except Exception:
            return []

    def _field_accepts_multiple_values(self, model, field_name: str) -> bool:
        try:
            field = model._meta.get_field(field_name)
        except Exception:
            return False

        internal_type = ""
        try:
            internal_type = field.get_internal_type()
        except Exception:
            internal_type = ""

        if internal_type in ["ArrayField", "JSONField"]:
            return True

        return False

    def _coerce_choice_values_for_field(self, model, field_name: str, values: list):
        if not values:
            return []
        if self._field_accepts_multiple_values(model, field_name):
            return values
        return values[0]

    def _pick_choice(self, model, field_name: str, token: str):
        normalized_token = self._normalize_token(token)
        for choice_value, choice_label in self._field_choices(model, field_name):
            value_norm = self._normalize_token(str(choice_value))
            label_norm = self._normalize_token(str(choice_label))
            if normalized_token == value_norm or normalized_token == label_norm:
                return choice_value
            if normalized_token in value_norm or normalized_token in label_norm:
                return choice_value
        return None

    def _pick_choice_list(self, model, field_name: str, tokens: list):
        values = []
        for token in tokens:
            choice_value = self._pick_choice(model, field_name, token)
            if choice_value and choice_value not in values:
                values.append(choice_value)
        return values

    def _canonical_crypto_token(self, token: str):
        normalized = self._normalize_token(token)
        if not normalized:
            return None

        if normalized in ["aes", "aescbc"]:
            return "aes"

        m_aes = re.match(r"aes(?:cbc)?(\d{3})$", normalized)
        if m_aes:
            return f"aes{m_aes.group(1)}"

        if normalized in ["3des", "des3", "tripledes"]:
            return "3des"
        if normalized == "des":
            return "des"

        if normalized in ["sha", "sha1"]:
            return "sha1"
        m_sha = re.match(r"sha(\d+)$", normalized)
        if m_sha:
            return f"sha{m_sha.group(1)}"

        if normalized == "md5":
            return "md5"

        if normalized.isdigit():
            return normalized

        return normalized

    def _resolve_integrity_enum_values(self, model, field_name: str, canonical_tokens: list):
        resolved = []
        for token in canonical_tokens:
            candidate = None
            if token == "md5":
                candidate = "MD5"
            elif token in ["sha", "sha1"]:
                candidate = "SHA1"
            elif token == "sha256":
                candidate = "SHA256"
            elif token == "sha384":
                candidate = "SHA384"
            elif token == "sha512":
                candidate = "SHA512"

            if candidate:
                choice_value = self._pick_choice(model, field_name, candidate)
                if choice_value and choice_value not in resolved:
                    resolved.append(choice_value)

        return resolved

    def _resolve_encryption_enum_values(self, model, field_name: str, canonical_tokens: list):
        resolved = []
        for token in canonical_tokens:
            candidates = []

            if token == "des":
                candidates = ["DES"]
            elif token == "3des":
                candidates = ["3DES"]
            elif token in ["aes", "aes128"]:
                candidates = ["AES-128-CBC"]
            elif token == "aes128gcm":
                candidates = ["AES-128-GCM"]
            elif token in ["aes128cbc", "aes128"]:
                candidates = ["AES-128-CBC"]
            elif token == "aes192gcm":
                candidates = ["AES-192-GCM"]
            elif token in ["aes192cbc", "aes192"]:
                candidates = ["AES-192-CBC"]
            elif token == "aes256gcm":
                candidates = ["AES-256-GCM"]
            elif token in ["aes256cbc", "aes256"]:
                candidates = ["AES-256-CBC"]
            elif token == "aesgcm":
                candidates = ["AES-256-GCM", "AES-128-GCM"]
            elif token in ["aesgcm128", "aes128gcm"]:
                candidates = ["AES-128-GCM"]
            elif token in ["aesgcm192", "aes192gcm"]:
                candidates = ["AES-192-GCM"]
            elif token in ["aesgcm256", "aes256gcm"]:
                candidates = ["AES-256-GCM"]

            for candidate in candidates:
                choice_value = self._pick_choice(model, field_name, candidate)
                if choice_value and choice_value not in resolved:
                    resolved.append(choice_value)

        return resolved

    def _best_effort_values_without_choices(self, field_name: str, canonical_tokens: list):
        field_name_lower = (field_name or "").lower()

        if "encryption" in field_name_lower:
            mapping = {
                "des": "DES",
                "3des": "3DES",
                "aes": "AES-128-CBC",
                "aes128": "AES-128-CBC",
                "aes192": "AES-192-CBC",
                "aes256": "AES-256-CBC",
                "aes128cbc": "AES-128-CBC",
                "aes192cbc": "AES-192-CBC",
                "aes256cbc": "AES-256-CBC",
                "aesgcm": "AES-256-GCM",
                "aesgcm128": "AES-128-GCM",
                "aesgcm192": "AES-192-GCM",
                "aesgcm256": "AES-256-GCM",
                "aes128gcm": "AES-128-GCM",
                "aes192gcm": "AES-192-GCM",
                "aes256gcm": "AES-256-GCM",
            }
            values = []
            for token in canonical_tokens:
                value = mapping.get(token)
                if value and value not in values:
                    values.append(value)
            return values

        if "integrity" in field_name_lower:
            mapping = {
                "md5": "MD5",
                "sha": "SHA1",
                "sha1": "SHA1",
                "sha256": "SHA256",
                "sha384": "SHA384",
                "sha512": "SHA512",
            }
            values = []
            for token in canonical_tokens:
                value = mapping.get(token)
                if value and value not in values:
                    values.append(value)
            return values

        if "group" in field_name_lower:
            values = []
            for token in canonical_tokens:
                if token.isdigit() and token not in values:
                    values.append(token)
            return values

        return []

    def _resolve_algorithm_enum_values(self, model, field_name: str, canonical_tokens: list):
        field_name_lower = (field_name or "").lower()
        if "integrity" in field_name_lower:
            return self._resolve_integrity_enum_values(model, field_name, canonical_tokens)
        if "encryption" in field_name_lower:
            return self._resolve_encryption_enum_values(model, field_name, canonical_tokens)
        return []

    def _resolve_choice_or_raw_list(self, model, field_name: str, tokens: list):
        canonical_tokens = []
        for token in tokens:
            canonical = self._canonical_crypto_token(token)
            if canonical and canonical not in canonical_tokens:
                canonical_tokens.append(canonical)

        if not canonical_tokens:
            return []

        field_choices = self._field_choices(model, field_name)
        if not field_choices:
            best_effort_values = self._best_effort_values_without_choices(
                field_name=field_name,
                canonical_tokens=canonical_tokens,
            )
            if best_effort_values:
                return self._coerce_choice_values_for_field(
                    model,
                    field_name,
                    best_effort_values,
                )
            return self._coerce_choice_values_for_field(
                model,
                field_name,
                canonical_tokens,
            )

        explicit_enum_values = self._resolve_algorithm_enum_values(
            model, field_name, canonical_tokens)
        if explicit_enum_values:
            return self._coerce_choice_values_for_field(
                model, field_name, explicit_enum_values)

        choice_values = self._pick_choice_list(
            model, field_name, canonical_tokens)
        if choice_values:
            return self._coerce_choice_values_for_field(
                model, field_name, choice_values)

        return []

    def _sanitize_choice_field_value(self, model, field_name: str, value):
        if value is None:
            return None

        if isinstance(value, str):
            value_items = [x.strip() for x in value.split(",") if x.strip()]
            if len(value_items) > 1:
                resolved_values = self._resolve_choice_or_raw_list(
                    model,
                    field_name,
                    value_items,
                )
                return resolved_values if resolved_values else value

            choice_value = self._pick_choice(model, field_name, value)
            if choice_value:
                return choice_value

            resolved_values = self._resolve_choice_or_raw_list(
                model,
                field_name,
                [value],
            )
            if resolved_values:
                return resolved_values

            return value

        if isinstance(value, (list, tuple, set)):
            resolved_values = self._resolve_choice_or_raw_list(
                model,
                field_name,
                [str(item) for item in value],
            )
            return resolved_values if resolved_values else value

        return value

    def _sanitize_policy_choice_fields(self, policy, model, field_names: list):
        updated = False
        for field_name in field_names:
            current_value = getattr(policy, field_name, None)
            sanitized_value = self._sanitize_choice_field_value(
                model, field_name, current_value)

            if isinstance(current_value, (list, tuple, set)) and sanitized_value is None:
                sanitized_value = []

            if sanitized_value != current_value:
                setattr(policy, field_name, sanitized_value)
                updated = True

        return updated

    def _split_crypto_tokens(self, value: str):
        return [x for x in re.split(r"[\s,]+", (value or "").strip()) if x]

    def _extract_crypto_tokens_from_text(self, text: str):
        tokens = self._split_crypto_tokens((text or "").lower())
        results = {
            "encryption": [],
            "integrity": [],
            "groups": [],
        }
        for token in tokens:
            normalized = token.strip().strip(",")
            if any(x in normalized for x in ["aes", "des", "chacha"]):
                cleaned = normalized.replace("esp-", "")
                if cleaned not in results["encryption"]:
                    results["encryption"].append(cleaned)
            if any(x in normalized for x in ["sha", "md5"]):
                cleaned = normalized.replace("esp-", "").replace("-hmac", "")
                if cleaned not in results["integrity"]:
                    results["integrity"].append(cleaned)
            if normalized.isdigit():
                if normalized not in results["groups"]:
                    results["groups"].append(normalized)
            else:
                m_group = re.match(r"group(\d+)", normalized)
                if m_group:
                    group_value = m_group.group(1)
                    if group_value not in results["groups"]:
                        results["groups"].append(group_value)
        return results

    def _extract_pfs_tokens(self, value: str):
        if not value:
            return []

        parsed_tokens = self._extract_crypto_tokens_from_text(value)
        tokens = list(parsed_tokens["groups"])
        if tokens:
            return tokens

        cleaned = str(value).strip().lower()
        if cleaned == "enabled":
            return []

        for token in self._split_crypto_tokens(cleaned):
            m_group = re.match(r"group(\d+)", token)
            if m_group:
                tokens.append(m_group.group(1))
            elif token.isdigit():
                tokens.append(token)

        return list(dict.fromkeys(tokens))

    def _resolve_ike_version_choice(self, version_hint: str):
        if not version_hint:
            return None
        if "1" in version_hint:
            return self._pick_choice(VPNPhase1Policy, "ike_version", "v1")
        if "2" in version_hint:
            return self._pick_choice(VPNPhase1Policy, "ike_version", "v2")
        return None

    def _phase1_defaults_from_policy(self, host: Device, policy_data: dict, version_hint: str):
        defaults = {
            "description": f"Discovered from {host.name} {version_hint.upper()} policy",
        }

        ike_version = self._resolve_ike_version_choice(version_hint)
        if ike_version:
            defaults["ike_version"] = ike_version

        lifetime = self._safe_int(policy_data.get("lifetime"))
        if lifetime is not None:
            defaults["lifetime_seconds"] = lifetime

        policy_text = "\n".join(
            [f"{key} {value}" for key, value in policy_data.items()])
        parsed_tokens = self._extract_crypto_tokens_from_text(policy_text)

        if "lifetime_seconds" not in defaults:
            inline_lifetime = re.search(
                r"lifetime(?:\s+seconds)?\s+(\d+)", policy_text)
            if inline_lifetime:
                lifetime_inline = self._safe_int(inline_lifetime.group(1))
                if lifetime_inline is not None:
                    defaults["lifetime_seconds"] = lifetime_inline

        encryption_tokens = []
        if policy_data.get("encryption"):
            encryption_tokens.extend(
                self._split_crypto_tokens(policy_data.get("encryption")))
        encryption_tokens.extend(parsed_tokens["encryption"])
        if encryption_tokens:
            values = self._resolve_choice_or_raw_list(
                VPNPhase1Policy, "encryption_algorithm", encryption_tokens)
            if values:
                defaults["encryption_algorithm"] = values

        integrity_tokens = list(parsed_tokens["integrity"])
        if policy_data.get("integrity"):
            integrity_tokens.extend(
                self._split_crypto_tokens(policy_data.get("integrity")))
        if policy_data.get("hash"):
            integrity_tokens.extend(
                self._split_crypto_tokens(policy_data.get("hash")))
        if integrity_tokens:
            values = self._resolve_choice_or_raw_list(
                VPNPhase1Policy, "integrity_algorithm", integrity_tokens)
            if values:
                defaults["integrity_algorithm"] = values

        group_tokens = list(parsed_tokens["groups"])
        if policy_data.get("group"):
            group_tokens.extend(
                self._split_crypto_tokens(policy_data.get("group")))
        if group_tokens:
            values = self._resolve_choice_or_raw_list(
                VPNPhase1Policy, "dh_group", group_tokens)
            if values:
                defaults["dh_group"] = values

        if policy_data.get("authentication"):
            auth_tokens = self._split_crypto_tokens(
                policy_data.get("authentication"))
            if any("pre" in token or "psk" in token for token in auth_tokens):
                auth_value = self._pick_choice(
                    VPNPhase1Policy, "authentication_method", "psk")
                if auth_value:
                    defaults["authentication_method"] = auth_value

        if "authentication_method" not in defaults and "2" in (version_hint or ""):
            auth_value = self._pick_choice(
                VPNPhase1Policy, "authentication_method", "psk")
            if auth_value:
                defaults["authentication_method"] = auth_value

        return defaults

    def _phase2_defaults_from_transform_set(self, host: Device, ts_name: str, ts_data: dict):
        defaults = {
            "description": f"Discovered from {host.name} transform-set {ts_name}: {ts_data.get('transforms', '')}",
        }
        parsed_tokens = self._extract_crypto_tokens_from_text(
            ts_data.get("transforms", ""))
        encryption_tokens = parsed_tokens["encryption"]
        integrity_tokens = parsed_tokens["integrity"]

        if encryption_tokens:
            values = self._resolve_choice_or_raw_list(
                VPNPhase2Policy, "encryption_algorithm", encryption_tokens)
            if values:
                defaults["encryption_algorithm"] = values
        if integrity_tokens:
            values = self._resolve_choice_or_raw_list(
                VPNPhase2Policy, "integrity_algorithm", integrity_tokens)
            if values:
                defaults["integrity_algorithm"] = values

        pfs_tokens = self._extract_pfs_tokens(ts_data.get("pfs_group", ""))
        if pfs_tokens:
            values = self._resolve_choice_or_raw_list(
                VPNPhase2Policy, "pfs_group", pfs_tokens)
            if values:
                defaults["pfs_group"] = values

        return defaults

    def _phase2_defaults_from_proposal(self, host: Device, proposal_name: str, proposal_data: dict):
        defaults = {
            "description": f"Discovered from {host.name} ikev2 ipsec-proposal {proposal_name}",
        }
        encryption_tokens = []
        integrity_tokens = []
        lifetime_value = None

        for key, values in proposal_data.items():
            key_norm = key.lower()
            for value in values:
                tokens = self._split_crypto_tokens(value)
                parsed_tokens = self._extract_crypto_tokens_from_text(
                    f"{key} {value}")
                if "encrypt" in key_norm:
                    encryption_tokens.extend(tokens)
                if "integrity" in key_norm:
                    integrity_tokens.extend(tokens)
                encryption_tokens.extend(parsed_tokens["encryption"])
                integrity_tokens.extend(parsed_tokens["integrity"])
                if "lifetime" in key_norm and not lifetime_value:
                    lifetime_value = self._safe_int(
                        tokens[0] if tokens else None)

        encryption_tokens = list(dict.fromkeys(encryption_tokens))
        integrity_tokens = list(dict.fromkeys(integrity_tokens))

        if encryption_tokens:
            values = self._resolve_choice_or_raw_list(
                VPNPhase2Policy, "encryption_algorithm", encryption_tokens)
            if values:
                defaults["encryption_algorithm"] = values
        if integrity_tokens:
            values = self._resolve_choice_or_raw_list(
                VPNPhase2Policy, "integrity_algorithm", integrity_tokens)
            if values:
                defaults["integrity_algorithm"] = values
        if lifetime_value is not None:
            defaults["lifetime"] = lifetime_value

        return defaults

    def _friendly_tunnel_name(self, host: Device, entry: dict, tunnel_group_name: str, peer_value: str = ""):
        peer = (peer_value or tunnel_group_name or "unknown-peer").strip()
        map_name = str(entry.get("map_name", "map")).strip() or "map"
        sequence = str(entry.get("sequence", "0")).strip() or "0"
        raw_name = f"{host.name} | {peer} | {map_name}:{sequence}"
        safe_name = re.sub(r"\s+", " ", raw_name)
        return safe_name[:255]

    def _ensure_local_endpoint(self, host: Device, profile: VPNProfile, source_interface: Interface = None):
        safe_role = self._preferred_endpoint_role(
            "Hub", fallback_role=host.role)

        if source_interface:
            endpoint_defaults = {
                "device": host,
                "vpn_profile": profile,
                "role": safe_role,
                "source_interface": source_interface,
                "source_ipaddress": None,
            }
            return self._upsert_endpoint(
                lookup={"source_interface": source_interface},
                defaults=endpoint_defaults,
            )

        if host.primary_ip4:
            primary_ip = str(host.primary_ip4).split("/")[0]
            endpoint_defaults = {
                "device": host,
                "vpn_profile": profile,
                "role": safe_role,
                "source_ipaddress": None,
                "source_fqdn": primary_ip,
            }
            return self._upsert_endpoint(
                lookup={"source_fqdn": primary_ip, "device": host},
                defaults=endpoint_defaults,
            )

        endpoint_defaults = {
            "device": host,
            "vpn_profile": profile,
            "role": safe_role,
            "source_fqdn": host.name,
        }
        return self._upsert_endpoint(
            lookup={"device": host, "vpn_profile": profile,
                    "source_fqdn": host.name},
            defaults=endpoint_defaults,
        )

    def _candidate_remote_peers(self, tunnel_group_name: str, tunnel_group_data: dict, entry: dict):
        candidates = []
        for peer in entry.get("peers", []):
            if peer:
                candidates.append(peer)

        attr_dicts = [
            tunnel_group_data.get("general_attributes", {}),
            tunnel_group_data.get("ipsec_attributes", {}),
            tunnel_group_data.get("other_attributes", {}),
        ]
        for attrs in attr_dicts:
            for value in attrs.values():
                for token in self._split_crypto_tokens(str(value)):
                    if self._is_ip_address(token) or "." in token:
                        candidates.append(token)

        if tunnel_group_name:
            candidates.append(tunnel_group_name)

        cleaned = []
        for candidate in candidates:
            normalized = candidate.strip().strip(",")
            if not normalized:
                continue
            if normalized.lower() in ["defaultragroup", "defaultl2lgroup"]:
                continue
            if normalized not in cleaned:
                cleaned.append(normalized)
        return cleaned

    def _resolve_device_interface(self, host: Device, interface_hint: str):
        if not interface_hint:
            return None

        normalized_hint = self.util.real_interface_name(interface_hint).strip()

        by_name = Interface.objects.filter(
            device=host,
            name__iexact=normalized_hint,
        ).first()
        if by_name:
            return by_name

        by_description = Interface.objects.filter(
            device=host,
            description__iexact=interface_hint.strip(),
        ).first()
        if by_description:
            return by_description

        return self.util.get_interface(
            device=host,
            name=normalized_hint,
            interface_type=self.util.guess_interface_type_from_name(
                name=normalized_hint
            ),
        )

    def _build_endpoint_name(self, defaults: dict, lookup: dict) -> str:
        device = defaults.get("device")
        profile = defaults.get("vpn_profile")
        source_interface = defaults.get(
            "source_interface") or lookup.get("source_interface")
        source_ip = defaults.get(
            "source_ipaddress") or lookup.get("source_ipaddress")
        source_fqdn = defaults.get("source_fqdn") or lookup.get("source_fqdn")

        if source_interface:
            endpoint_id = source_interface.name
        elif source_ip:
            endpoint_id = str(source_ip).split("/")[0]
        elif source_fqdn:
            endpoint_id = str(source_fqdn)
        elif device:
            endpoint_id = device.name
        else:
            endpoint_id = "endpoint"

        scope = profile.name if profile else (
            device.name if device else "remote")
        raw_name = f"{scope}-{endpoint_id}"
        safe_name = re.sub(r"[^A-Za-z0-9_.:-]", "-", raw_name)
        safe_name = safe_name.strip("-_.:")
        if not safe_name:
            return f"endpoint-{uuid.uuid4().hex[:12]}"
        return safe_name[:100]

    def _ensure_non_null_endpoint_name(self, values: dict, lookup: dict):
        existing_name = values.get("name")
        if isinstance(existing_name, str):
            normalized_name = existing_name.strip()
        elif existing_name is None:
            normalized_name = ""
        else:
            normalized_name = str(existing_name).strip()

        if not normalized_name:
            normalized_name = self._build_endpoint_name(
                defaults=values,
                lookup=lookup,
            )

        if not normalized_name:
            normalized_name = f"endpoint-{uuid.uuid4().hex[:12]}"

        values["name"] = normalized_name[:100]

    def _derive_endpoint_source_fqdn(self, values: dict, lookup: dict) -> str:
        source_fqdn = values.get("source_fqdn") or lookup.get("source_fqdn")
        if source_fqdn:
            return str(source_fqdn).strip()[:255]

        source_interface = values.get(
            "source_interface") or lookup.get("source_interface")
        if source_interface:
            parent = getattr(source_interface, "parent", None)
            if parent and getattr(parent, "name", None):
                return f"{parent.name} {source_interface.name}"[:255]
            return str(source_interface.name)[:255]

        source_ip = values.get(
            "source_ipaddress") or lookup.get("source_ipaddress")
        if source_ip:
            return str(source_ip).split("/")[0][:255]

        device = values.get("device") or lookup.get("device")
        if device and getattr(device, "name", None):
            return str(device.name)[:255]

        return f"endpoint-{uuid.uuid4().hex[:12]}"

    def _upsert_endpoint(self, lookup: dict, defaults: dict):
        defaults = dict(defaults)
        if defaults.get("source_interface"):
            defaults["source_fqdn"] = self._derive_endpoint_source_fqdn(
                defaults, lookup)
            defaults["source_ipaddress"] = None
        elif defaults.get("source_fqdn"):
            defaults["source_ipaddress"] = None
        elif defaults.get("source_ipaddress"):
            defaults["source_fqdn"] = str(
                defaults.get("source_ipaddress")).split("/")[0]
            defaults["source_ipaddress"] = None
        else:
            defaults["source_fqdn"] = self._derive_endpoint_source_fqdn(
                defaults, lookup)
        self._ensure_non_null_endpoint_name(defaults, lookup)

        queryset = VPNTunnelEndpoint.objects.filter(**lookup)
        endpoint = queryset.order_by("id").first()

        if queryset.count() > 1:
            self.logger.warning(
                f"Multiple VPNTunnelEndpoint matches for {lookup}; updating first match {endpoint.id}"
            )

        if endpoint:
            if not endpoint.name:
                endpoint.name = self._build_endpoint_name(
                    defaults={
                        "device": endpoint.device,
                        "vpn_profile": endpoint.vpn_profile,
                        "source_interface": endpoint.source_interface,
                        "source_ipaddress": endpoint.source_ipaddress,
                        "source_fqdn": endpoint.source_fqdn,
                    },
                    lookup=lookup,
                ) or f"endpoint-{uuid.uuid4().hex[:12]}"
            changed = False
            for key, value in defaults.items():
                if getattr(endpoint, key) != value:
                    setattr(endpoint, key, value)
                    changed = True
            if changed:
                try:
                    endpoint.validated_save()
                except Exception as ex:
                    error_text = str(ex).lower()
                    if "source ip address must be assigned to source interface" in error_text:
                        source_ip = endpoint.source_ipaddress
                        self.logger.warning(
                            f"VPNTunnelEndpoint source_ipaddress '{source_ip}' requires source_interface; falling back to source_fqdn."
                        )
                        endpoint.source_ipaddress = None
                        if source_ip and not endpoint.source_fqdn:
                            endpoint.source_fqdn = str(source_ip).split("/")[0]
                        if not endpoint.name:
                            endpoint.name = self._build_endpoint_name(
                                defaults={
                                    "device": endpoint.device,
                                    "vpn_profile": endpoint.vpn_profile,
                                    "source_interface": endpoint.source_interface,
                                    "source_ipaddress": endpoint.source_ipaddress,
                                    "source_fqdn": endpoint.source_fqdn,
                                },
                                lookup=lookup,
                            )
                        endpoint.validated_save()
                    elif "role" in defaults:
                        endpoint.role = None
                        endpoint.validated_save()
                    elif "null value in column \"source_fqdn\"" in error_text:
                        endpoint.source_fqdn = self._derive_endpoint_source_fqdn(
                            {
                                "device": endpoint.device,
                                "source_interface": endpoint.source_interface,
                                "source_ipaddress": endpoint.source_ipaddress,
                                "source_fqdn": endpoint.source_fqdn,
                            },
                            lookup,
                        )
                        endpoint.source_ipaddress = None
                        endpoint.validated_save()
                    else:
                        raise
            return endpoint

        create_data = {**lookup, **defaults}
        if create_data.get("source_interface"):
            create_data["source_fqdn"] = self._derive_endpoint_source_fqdn(
                create_data, lookup)
            create_data["source_ipaddress"] = None
        elif create_data.get("source_fqdn"):
            create_data["source_ipaddress"] = None
        elif create_data.get("source_ipaddress"):
            create_data["source_fqdn"] = str(
                create_data.get("source_ipaddress")).split("/")[0]
            create_data["source_ipaddress"] = None
        else:
            create_data["source_fqdn"] = self._derive_endpoint_source_fqdn(
                create_data, lookup)
        self._ensure_non_null_endpoint_name(create_data, lookup)
        try:
            endpoint = VPNTunnelEndpoint.objects.create(**create_data)
        except Exception as ex:
            error_text = str(ex).lower()
            if "source ip address must be assigned to source interface" in error_text and create_data.get("source_ipaddress"):
                source_ip = create_data.get("source_ipaddress")
                self.logger.warning(
                    f"VPNTunnelEndpoint source_ipaddress '{source_ip}' requires source_interface; falling back to source_fqdn."
                )
                create_data["source_ipaddress"] = None
                create_data["source_fqdn"] = create_data.get("source_fqdn") or str(
                    source_ip).split("/")[0]
                self._ensure_non_null_endpoint_name(create_data, lookup)
                endpoint = VPNTunnelEndpoint.objects.create(**create_data)
            elif "null value in column \"name\"" in error_text:
                self.logger.warning(
                    "VPNTunnelEndpoint create attempted with null name; regenerating name and retrying create."
                )
                self._ensure_non_null_endpoint_name(create_data, lookup)
                if not create_data.get("name"):
                    create_data["name"] = f"endpoint-{uuid.uuid4().hex[:12]}"
                endpoint = VPNTunnelEndpoint.objects.create(**create_data)
            elif "null value in column \"source_fqdn\"" in error_text:
                self.logger.warning(
                    "VPNTunnelEndpoint create attempted with null source_fqdn; regenerating source_fqdn and retrying create."
                )
                create_data["source_fqdn"] = self._derive_endpoint_source_fqdn(
                    create_data, lookup)
                create_data["source_ipaddress"] = None
                endpoint = VPNTunnelEndpoint.objects.create(**create_data)
            else:
                raise
        return endpoint

    def _ensure_remote_endpoint(self, profile: VPNProfile, role: Role, peer_value: str):
        safe_role = self._preferred_endpoint_role("Peer", fallback_role=role)
        if not peer_value:
            return None

        if self._is_ip_address(peer_value):
            peer_ip = self._resolve_or_create_ipaddress_with_parent(peer_value)
            if peer_ip:
                peer_address = str(peer_ip).split("/")[0]
                return self._upsert_endpoint(
                    lookup={"source_fqdn": peer_address},
                    defaults={
                        "vpn_profile": profile,
                        "role": safe_role,
                        "source_ipaddress": None,
                        "source_fqdn": peer_address,
                    },
                )

            self.logger.warning(
                f"Peer '{peer_value}' cannot be represented as source_ipaddress (missing IPAddress or parent Prefix); falling back to source_fqdn."
            )
            return self._upsert_endpoint(
                lookup={"source_fqdn": peer_value},
                defaults={
                    "vpn_profile": profile,
                    "role": safe_role,
                    "source_fqdn": peer_value,
                },
            )

        return self._upsert_endpoint(
            lookup={"source_fqdn": peer_value},
            defaults={
                "vpn_profile": profile,
                "role": safe_role,
                "source_fqdn": peer_value,
            },
        )

    def _ensure_endpoint_has_name(self, endpoint):
        if not endpoint:
            return endpoint
        if endpoint.name:
            return endpoint

        endpoint.name = self._build_endpoint_name(
            defaults={
                "device": endpoint.device,
                "vpn_profile": endpoint.vpn_profile,
                "source_interface": endpoint.source_interface,
                "source_ipaddress": endpoint.source_ipaddress,
                "source_fqdn": endpoint.source_fqdn,
            },
            lookup={},
        )
        endpoint.validated_save()
        return endpoint

    def _reconcile_tunnel_endpoints(self, host: Device):
        tunnels = VPNTunnel.objects.filter(
            vpn__name__startswith=f"{host.name}-")
        repaired = 0

        for tunnel in tunnels:
            changed = False

            if not tunnel.endpoint_a and tunnel.vpn_profile:
                endpoint_a = self._ensure_local_endpoint(
                    host=host,
                    profile=tunnel.vpn_profile,
                    source_interface=None,
                )
                if endpoint_a:
                    tunnel.endpoint_a = endpoint_a
                    changed = True

            if not tunnel.endpoint_z and tunnel.vpn_profile:
                peer_hint = None
                if tunnel.vpn and tunnel.vpn.vpn_id:
                    peer_hint = str(tunnel.vpn.vpn_id)
                elif tunnel.name and "-sa-" in tunnel.name:
                    peer_hint = tunnel.name.split(
                        "-sa-", 1)[1].replace("-", ":")

                if peer_hint:
                    endpoint_z = self._ensure_remote_endpoint(
                        profile=tunnel.vpn_profile,
                        role=host.role,
                        peer_value=peer_hint,
                    )
                    if endpoint_z:
                        tunnel.endpoint_z = endpoint_z
                        changed = True

            if tunnel.endpoint_a:
                self._ensure_endpoint_has_name(tunnel.endpoint_a)
            if tunnel.endpoint_z:
                self._ensure_endpoint_has_name(tunnel.endpoint_z)

            if changed:
                tunnel.validated_save()
                repaired += 1

        if self.debug and repaired:
            self.logger.debug(
                f"{host.name}: Reconciled endpoints on {repaired} tunnels"
            )

    def _ensure_phase1_policy(self, host: Device, name: str, description: str, lifetime: int = None):
        defaults = {
            "description": description,
        }
        if lifetime is not None:
            defaults["lifetime_seconds"] = lifetime
        policy, _ = VPNPhase1Policy.objects.update_or_create(
            name=name,
            defaults=defaults,
        )
        return policy

    def _ensure_phase2_policy(self, host: Device, name: str, description: str, lifetime: int = None):
        defaults = {
            "description": description,
        }
        if lifetime is not None:
            defaults["lifetime"] = lifetime
        policy, _ = VPNPhase2Policy.objects.update_or_create(
            name=name,
            defaults=defaults,
        )
        return policy

    def _sync_vpn_models(self, host: Device, command_outputs: dict):
        if not command_outputs:
            if self.debug:
                self.logger.debug(
                    f"{host.name}: VPN sync skipped - no VPN command outputs present")
            return

        split_domains = self._parse_anyconnect_split_domains(
            self._command_text(
                command_outputs, ASA_DYNAMIC_SPLIT_DOMAIN_COMMAND)
        )
        self._sync_anyconnect_local_context(host, split_domains)

        vpn_data = self._build_vpn_data(command_outputs)
        tunnel_groups = vpn_data["tunnel_groups"]
        group_policies = vpn_data["group_policies"]
        ikev1_policies = vpn_data["ikev1_policies"]
        ikev2_policies = vpn_data["ikev2_policies"]
        ikev2_ipsec_proposals = vpn_data["ikev2_ipsec_proposals"]
        transform_sets = vpn_data["transform_sets"]
        crypto_maps = vpn_data["crypto_maps"]
        object_networks = vpn_data.get("object_networks", {})
        object_groups = vpn_data.get("object_groups", {})
        protected_prefixes = vpn_data.get("protected_prefixes", {})
        global_settings = vpn_data["global_settings"]

        if self.debug:
            self.logger.debug(
                f"{host.name}: VPN parse summary tunnel_groups={len(tunnel_groups)} group_policies={len(group_policies)} "
                f"ikev1_policies={len(ikev1_policies)} ikev2_policies={len(ikev2_policies)} "
                f"ikev2_ipsec_proposals={len(ikev2_ipsec_proposals)} transform_sets={len(transform_sets)} "
                f"crypto_maps={len(crypto_maps['entries'])} object_networks={len(object_networks)} "
                f"object_groups={len(object_groups)} protected_prefix_maps={len(protected_prefixes)}"
            )

        if not tunnel_groups and not crypto_maps["entries"]:
            if self.debug:
                self.logger.debug(
                    f"{host.name}: No VPN configuration detected")
            return

        phase1_policy_objects = []
        for priority, policy_data in sorted(ikev1_policies.items(), key=lambda x: int(x[0])):
            defaults = self._phase1_defaults_from_policy(
                host=host,
                policy_data=policy_data,
                version_hint="v1",
            )
            defaults["description"] = f"Discovered from {host.name} IKEv1 policy {priority}"
            policy, _ = VPNPhase1Policy.objects.update_or_create(
                name=f"{host.name}-ikev1-policy-{priority}",
                defaults=defaults,
            )
            if self._sanitize_policy_choice_fields(
                policy,
                VPNPhase1Policy,
                ["encryption_algorithm", "integrity_algorithm", "dh_group"],
            ):
                policy.validated_save()
            phase1_policy_objects.append((int(priority), policy))

        for priority, policy_data in sorted(ikev2_policies.items(), key=lambda x: int(x[0])):
            defaults = self._phase1_defaults_from_policy(
                host=host,
                policy_data=policy_data,
                version_hint="v2",
            )
            defaults["description"] = f"Discovered from {host.name} IKEv2 policy {priority}"
            policy, _ = VPNPhase1Policy.objects.update_or_create(
                name=f"{host.name}-ikev2-policy-{priority}",
                defaults=defaults,
            )
            if self._sanitize_policy_choice_fields(
                policy,
                VPNPhase1Policy,
                ["encryption_algorithm", "integrity_algorithm", "dh_group"],
            ):
                policy.validated_save()
            phase1_policy_objects.append((int(priority), policy))

        if not phase1_policy_objects:
            fallback_phase1 = self._ensure_phase1_policy(
                host=host,
                name=f"{host.name}-phase1-default",
                description=f"Default/discovered Phase1 policy for {host.name}",
                lifetime=None,
            )
            phase1_policy_objects.append((100, fallback_phase1))

        phase2_policy_objects = {}
        for ts_name, ts_data in transform_sets.items():
            defaults = self._phase2_defaults_from_transform_set(
                host=host,
                ts_name=ts_name,
                ts_data=ts_data,
            )
            policy, _ = VPNPhase2Policy.objects.update_or_create(
                name=f"{host.name}-phase2-{ts_name}",
                defaults=defaults,
            )
            if self._sanitize_policy_choice_fields(
                policy,
                VPNPhase2Policy,
                ["encryption_algorithm", "integrity_algorithm", "pfs_group"],
            ):
                policy.validated_save()
            phase2_policy_objects[ts_name] = policy

        for proposal_name, proposal_data in ikev2_ipsec_proposals.items():
            defaults = self._phase2_defaults_from_proposal(
                host=host,
                proposal_name=proposal_name,
                proposal_data=proposal_data,
            )
            policy, _ = VPNPhase2Policy.objects.update_or_create(
                name=f"{host.name}-phase2-proposal-{proposal_name}",
                defaults=defaults,
            )
            if self._sanitize_policy_choice_fields(
                policy,
                VPNPhase2Policy,
                ["encryption_algorithm", "integrity_algorithm", "pfs_group"],
            ):
                policy.validated_save()
            phase2_policy_objects[proposal_name] = policy

        if self.debug:
            phase1_populated = 0
            for _, policy in phase1_policy_objects:
                if getattr(policy, "encryption_algorithm", None) or getattr(policy, "integrity_algorithm", None):
                    phase1_populated += 1

            phase2_populated = 0
            for policy in phase2_policy_objects.values():
                if getattr(policy, "encryption_algorithm", None) or getattr(policy, "integrity_algorithm", None):
                    phase2_populated += 1

            self.logger.debug(
                f"{host.name}: policy algorithm population phase1={phase1_populated}/{len(phase1_policy_objects)} "
                f"phase2={phase2_populated}/{len(phase2_policy_objects)}"
            )

        if not phase2_policy_objects:
            default_phase2 = self._ensure_phase2_policy(
                host=host,
                name=f"{host.name}-phase2-default",
                description=f"Default/discovered Phase2 policy for {host.name}",
                lifetime=None,
            )
            phase2_policy_objects["default"] = default_phase2

        for tunnel_group_name, tunnel_group_data in tunnel_groups.items():
            group_policy_name = tunnel_group_data["general_attributes"].get(
                "default-group-policy")
            profile_key = group_policy_name or tunnel_group_name
            profile_name = f"{host.name}-{profile_key}"

            tunnel_group_keepalive = self._keepalive_from_tunnel_group(
                tunnel_group_data=tunnel_group_data,
            )

            keepalive_enabled = global_settings["keepalive_enabled"]
            keepalive_interval = global_settings["keepalive_interval"]
            keepalive_retries = global_settings["keepalive_retries"]
            if tunnel_group_keepalive["keepalive_enabled"]:
                keepalive_enabled = True
                keepalive_interval = tunnel_group_keepalive["keepalive_interval"]
                keepalive_retries = tunnel_group_keepalive["keepalive_retries"]

            profile_defaults = {
                "description": f"Discovered from {host.name} tunnel-group {tunnel_group_name}",
                "keepalive_enabled": keepalive_enabled,
                "keepalive_interval": keepalive_interval,
                "keepalive_retries": keepalive_retries,
                "nat_traversal": global_settings["nat_traversal"],
                "extra_options": {
                    "group_policy": group_policies.get(group_policy_name, {}),
                    "tunnel_group": tunnel_group_data,
                    "crypto_options": global_settings["extra_options"],
                },
                "role": self._safe_role(host.role),
            }
            profile, _ = VPNProfile.objects.update_or_create(
                name=profile_name,
                defaults=profile_defaults,
            )

            VPNProfilePhase1PolicyAssignment.objects.filter(
                vpn_profile=profile).exclude(
                vpn_phase1_policy__in=[policy for _,
                                       policy in phase1_policy_objects]
            ).delete()
            for weight, phase1_policy in phase1_policy_objects:
                VPNProfilePhase1PolicyAssignment.objects.update_or_create(
                    vpn_profile=profile,
                    vpn_phase1_policy=phase1_policy,
                    defaults={"weight": weight},
                )

            matching_entries = []
            for entry in crypto_maps["entries"].values():
                peers = [peer.lower() for peer in entry["peers"]]
                if tunnel_group_name.lower() in peers:
                    matching_entries.append(entry)

            if not matching_entries:
                matching_entries = [{
                    "map_name": "tunnel-group",
                    "sequence": "0",
                    "match_address": None,
                    "peers": [tunnel_group_name],
                    "transform_sets": [],
                    "ikev2_proposals": [],
                    "pfs_group": None,
                    "lifetime_seconds": None,
                }]

            assigned_phase2 = []
            for entry in matching_entries:
                entry_key = f"{entry['map_name']}:{entry['sequence']}"
                for transform_name in entry["transform_sets"]:
                    if transform_name in phase2_policy_objects:
                        assigned_phase2.append(
                            phase2_policy_objects[transform_name])
                for proposal_name in entry["ikev2_proposals"]:
                    if proposal_name in phase2_policy_objects:
                        assigned_phase2.append(
                            phase2_policy_objects[proposal_name])

            if not assigned_phase2:
                assigned_phase2 = list(phase2_policy_objects.values())

            assigned_phase2 = list(dict.fromkeys(assigned_phase2))

            VPNProfilePhase2PolicyAssignment.objects.filter(
                vpn_profile=profile).exclude(
                vpn_phase2_policy__in=assigned_phase2
            ).delete()
            for index, phase2_policy in enumerate(assigned_phase2, start=10):
                VPNProfilePhase2PolicyAssignment.objects.update_or_create(
                    vpn_profile=profile,
                    vpn_phase2_policy=phase2_policy,
                    defaults={"weight": index},
                )

            vpn, _ = VPN.objects.update_or_create(
                name=f"{host.name}-{tunnel_group_name}",
                defaults={
                    "description": f"Discovered from {host.name} tunnel-group {tunnel_group_name}",
                    "vpn_id": tunnel_group_name,
                    "vpn_profile": profile,
                    "role": self._safe_role(host.role),
                },
            )

            for entry in matching_entries:
                source_interface = None
                map_name = entry["map_name"]
                entry_key = f"{entry['map_name']}:{entry['sequence']}"
                source_interface_name = crypto_maps["interfaces"].get(map_name)
                if source_interface_name:
                    source_interface = self._resolve_device_interface(
                        host=host,
                        interface_hint=source_interface_name,
                    )

                endpoint_a = self._ensure_local_endpoint(
                    host=host,
                    profile=profile,
                    source_interface=source_interface,
                )

                endpoint_z = None
                local_ip = str(ipaddress.ip_interface(
                    host.primary_ip4).ip) if host.primary_ip4 else None
                peer_candidates = []
                peer_candidates.extend(self._candidate_remote_peers(
                    tunnel_group_name=tunnel_group_name,
                    tunnel_group_data=tunnel_group_data,
                    entry=entry,
                ))

                for peer in peer_candidates:
                    if local_ip and peer == local_ip:
                        continue
                    endpoint_z = self._ensure_remote_endpoint(
                        profile=profile,
                        role=host.role,
                        peer_value=peer,
                    )
                    if endpoint_z:
                        break

                if endpoint_z and not endpoint_a:
                    endpoint_a = self._ensure_local_endpoint(
                        host=host,
                        profile=profile,
                        source_interface=source_interface,
                    )

                if not endpoint_a or not endpoint_z:
                    if self.debug:
                        self.logger.debug(
                            f"{host.name}: Skipping tunnel create for {entry_key} due to missing endpoints (a={bool(endpoint_a)} z={bool(endpoint_z)})"
                        )
                    continue

                primary_peer = None
                if endpoint_z and endpoint_z.source_fqdn:
                    primary_peer = endpoint_z.source_fqdn
                elif entry.get("peers"):
                    primary_peer = entry["peers"][0]
                else:
                    primary_peer = tunnel_group_name

                tunnel_name = self._friendly_tunnel_name(
                    host=host,
                    entry=entry,
                    tunnel_group_name=tunnel_group_name,
                    peer_value=primary_peer,
                )
                encapsulation = self._resolve_encapsulation(
                    tunnel_type=tunnel_group_data.get("type", ""),
                    ike_version=entry.get("ike_version", ""),
                )
                tunnel_defaults = {
                    "description": f"Discovered from {host.name} crypto map {entry['map_name']} {entry['sequence']}",
                    "tunnel_id": f"{entry['map_name']}:{entry['sequence']}",
                    "status": self.util.status_active,
                    "vpn_profile": profile,
                    "vpn": vpn,
                    "role": self._safe_role(host.role),
                    "endpoint_a": endpoint_a,
                    "endpoint_z": endpoint_z,
                }
                if encapsulation:
                    tunnel_defaults["encapsulation"] = encapsulation

                for transform_name in entry["transform_sets"]:
                    if transform_name in phase2_policy_objects:
                        phase2_policy = phase2_policy_objects[transform_name]
                        phase2_defaults = {}
                        pfs_values = self._resolve_choice_or_raw_list(
                            VPNPhase2Policy,
                            "pfs_group",
                            self._extract_pfs_tokens(
                                entry.get("pfs_group") or ""),
                        )
                        if pfs_values:
                            phase2_defaults["pfs_group"] = pfs_values
                        lifetime_seconds = self._safe_int(
                            entry.get("lifetime_seconds"))
                        if lifetime_seconds is not None:
                            phase2_defaults["lifetime"] = lifetime_seconds
                        if phase2_defaults:
                            for key, value in phase2_defaults.items():
                                setattr(phase2_policy, key, value)
                            self._sanitize_policy_choice_fields(
                                phase2_policy,
                                VPNPhase2Policy,
                                ["encryption_algorithm",
                                    "integrity_algorithm", "pfs_group"],
                            )
                            phase2_policy.validated_save()

                for proposal_name in entry["ikev2_proposals"]:
                    if proposal_name in phase2_policy_objects:
                        phase2_policy = phase2_policy_objects[proposal_name]
                        proposal_defaults = {}
                        pfs_values = self._resolve_choice_or_raw_list(
                            VPNPhase2Policy,
                            "pfs_group",
                            self._extract_pfs_tokens(
                                entry.get("pfs_group") or ""),
                        )
                        if pfs_values:
                            proposal_defaults["pfs_group"] = pfs_values
                        lifetime_seconds = self._safe_int(
                            entry.get("lifetime_seconds"))
                        if lifetime_seconds is not None:
                            proposal_defaults["lifetime"] = lifetime_seconds
                        if proposal_defaults:
                            for key, value in proposal_defaults.items():
                                setattr(phase2_policy, key, value)
                            self._sanitize_policy_choice_fields(
                                phase2_policy,
                                VPNPhase2Policy,
                                ["encryption_algorithm",
                                    "integrity_algorithm", "pfs_group"],
                            )
                            phase2_policy.validated_save()

                VPNTunnel.objects.update_or_create(
                    name=tunnel_name, defaults=tunnel_defaults)

        self._reconcile_tunnel_endpoints(host=host)

        stale_tunnels = VPNTunnel.objects.filter(
            vpn__name__startswith=f"{host.name}-"
        ).filter(
            endpoint_a__isnull=True
        ) | VPNTunnel.objects.filter(
            vpn__name__startswith=f"{host.name}-"
        ).filter(
            endpoint_z__isnull=True
        )
        stale_count = stale_tunnels.count()
        if stale_count:
            stale_tunnels.delete()
            if self.debug:
                self.logger.debug(
                    f"{host.name}: Removed {stale_count} stale one-sided tunnels"
                )


register_jobs(OnboardCiscoASA, CiscoASA)
