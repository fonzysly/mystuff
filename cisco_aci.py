"""
https://docs.nautobot.com/projects/core/en/stable/development/jobs/

"""

from .discover_utils import utils
from .aci_client import AciApi, InterfaceObject, MemberObject
from django.contrib.contenttypes.models import ContentType
from nautobot.apps.jobs import Job, register_jobs
from nautobot.dcim.models import Platform
from nautobot.ipam.models import Prefix
from django.core.exceptions import ValidationError, ObjectDoesNotExist
import napalm
from ipaddress import ip_network, ip_address, ip_interface
import re
from io import StringIO


# Tenant
from nautobot.tenancy.models import Tenant, TenantGroup
# IPAM

from nautobot.ipam.models import (
    IPAddress,
    IPAddressToInterface,
    Prefix,
    VRF,
    VLAN,
    VLANGroup,
    Namespace,
)
from nautobot.ipam.choices import PrefixTypeChoices, IPAddressTypeChoices

# Job
from nautobot.apps.jobs import (
    Job,
    ObjectVar,
    BooleanVar,
    MultiObjectVar,
)

# DCIM
from nautobot.dcim.choices import (
    InterfaceTypeChoices,
    InterfaceModeChoices,
    DeviceRedundancyGroupFailoverStrategyChoices,
)
from nautobot.dcim.models import (
    Platform,
    Device,
    Interface,
    Cable,
    PowerPort,
    VirtualChassis,
    Controller,
    Location,
    DeviceRedundancyGroup,
    ControllerManagedDeviceGroup,
    InventoryItem,
    Manufacturer,
)

# BGP
from nautobot_bgp_models.models import (
    BGPRoutingInstance,
)

# Extras
from nautobot.extras.models import (
    SecretsGroup,
    Status,
    ExternalIntegration,
    Role,
    Tag,
    CustomField,
)
from nautobot.extras.choices import (
    CustomFieldTypeChoices,
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)


name = "Discovery"
IGNORE_TENANTS = ["infra", "common"]
BUBBLE_TENANTS = ["DRTEST", "Elevance_Bubble"]
BUBBLE_NAMESPACE = "DR Bubble"


# TODO: Move constants to externa_integration extra_config data
# TODO: Add BGP Peering discovery


class CiscoACI(Job):
    class Meta:
        name = "Discovery: Cisco ACI"
        description = """
            Discovers additional information for Cisco ACI fabric via API calls.
        """
        has_sensitive_variables = False
        soft_time_limit = 86400
        time_limit = 86410

    apic = ObjectVar(
        model=Controller,
        query_params={"platform": "cisco_aci"},
        display_field="name",
        required=True,
        label="ACI APIC",
    )

    discover_l1 = BooleanVar(
        label="Layer-1 Discovery",
        required=False,
        description="If enabled, will discover Devices and their Interfaces.",
        default=True,
    )
    discover_l2 = BooleanVar(
        label="Layer-2 Discovery",
        required=False,
        description="If enabled, will create and map VLANs to interfaces.",
        default=True,
    )

    discover_l3 = BooleanVar(
        label="Layer-3 Discovery",
        required=False,
        description="If enabled, will IPAddress and Prefixes.",
        default=True,
    )

    discover_neighbors = BooleanVar(
        label="CDP/LLDP Discovery",
        required=False,
        description="If enabled, will discover CDP/LLDP neighbors during Layer-1 discovery and create Cables between devices.",
        default=True,
    )

    debug = BooleanVar(
        label="Verbose Logging",
        required=False,
        description="If enabled provide more detailed logs for debugging.",
        default=False,
    )

    def run(
        self, apic, discover_neighbors, discover_l1, discover_l2, discover_l3, debug
    ):
        self.apic = apic
        self.ndo_tenants = []
        self.concerns = []
        try:
            self.device_site = self.apic.location
        except Exception as e:
            self.logger.error(
                "Controller location not set, Controller's Location is required."
            )
            return

        self.debug = debug
        self.discover_neighbors = discover_neighbors

        if not self.apic.external_integration:
            raise Exception(
                "ExternalIntegration was not found on specified Controller."
            )
        if not self.apic.external_integration.secrets_group:
            raise Exception(
                f"SecretsGroup not found on {self.apic.external_integration}"
            )

        self.logger.info(
            f"Running Cisco ACI Discovery Job for {self.apic.name}")

        self.util = utils(logger=self.logger, debug=self.debug)

        self.username = self.apic.external_integration.secrets_group.get_secret_value(
            access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
            secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME,
        )

        try:
            self.password = (
                self.apic.external_integration.secrets_group.get_secret_value(
                    access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                    secret_type=SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
                )
            )

        except Exception as e:
            self.password = None

        try:
            self.private_key = (
                self.apic.external_integration.secrets_group.get_secret_value(
                    access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                    secret_type=SecretsGroupSecretTypeChoices.TYPE_KEY,
                )
            )
        except Exception as e:
            self.private_key = None

        self.mso_tag = self.util.get_tag(
            name="NDO-MSO",
            content_types=self.util.get_taggable_types(),
            color="987980",
            description="Nexus Dashboard Orchestrator MSO Managed",
        )

        self.conn = AciApi(
            username=self.username,
            password=self.password,
            private_key=self.private_key,
            base_uri=self.apic.external_integration.remote_url,
            verify=self.apic.external_integration.verify_ssl,
            debug=self.debug,
        )

        self.setup_custom_fields()

        self.load_tenants()
        self.cleanup_old_vlans()
        if discover_l1 or discover_neighbors:
            self.logger.info("Starting Layer 1 Discovery")
            self.load_devices()
            self.load_interfaces()

        if discover_l2:
            self.logger.info("Starting Layer 2 Discovery")
            self.load_epgs()

        if discover_l3:
            self.logger.info("Starting Layer 3 Discovery")
            self.load_vrfs()
            self.load_prefixes()
            self.load_ipaddresses()
        if self.concerns:
            output = StringIO()
            # Write header
            output.write("ACI Discovery Concerns Report\n")
            output.write("=" * 30 + "\n\n")
            output.write(f"Controller: {self.apic.name}\n\n")
            for concern in self.concerns:
                output.write(f"{concern}\n")

            # Create FileProxy object with .txt extension
            self.create_file(
                f'{self.apic.name}_discovery_concerns.txt', output.getvalue())

            # Log creation of file
            self.logger.info("Created concerns report file")

    def setup_custom_fields(self):
        self.cf_node_id = self.ensure_cf(
            label="ACI Node ID",
            type=CustomFieldTypeChoices.TYPE_INTEGER,
            models=[Device],
            description="ACI Node ID for Cisco ACI devices.",
        )
        self.cf_pod_id = self.ensure_cf(
            label="ACI Pod ID",
            type=CustomFieldTypeChoices.TYPE_INTEGER,
            models=[Device],
            description="ACI Pod ID for Cisco ACI devices.",
        )
        self.cf_ap = self.ensure_cf(
            label="ACI AppProfile",
            type=CustomFieldTypeChoices.TYPE_TEXT,
            models=[VLAN],
            description="ACI AppProfile Name for ACI Bridge Domains",
        )
        self.cf_epg = self.ensure_cf(
            label="ACI EPG",
            type=CustomFieldTypeChoices.TYPE_TEXT,
            models=[VLAN],
            description="ACI EPG Name for ACI Bridge Domains",
        )
        self.cf_bd = self.ensure_cf(
            label="ACI BD",
            type=CustomFieldTypeChoices.TYPE_TEXT,
            models=[VLAN],
            description="ACI Bridge Domains",
        )
        self.cf_tenant = self.ensure_cf(
            label="ACI Tenant",
            type=CustomFieldTypeChoices.TYPE_TEXT,
            models=[VLAN],
            description="ACI Tenant Name for ACI Bridge Domains",
        )

    def cleanup_old_vlans(self):
        groups = ["HLB", "DFW", "DC-Stretched"]
        for group in groups:

            aci_vlans = VLAN.objects.filter(
                vlan_group__name=group, _custom_field_data__aci_bd__regex='\w+')
            for vlan in aci_vlans:
                # Check if VLAN is tagged on any interfaces that are NOT ACI devices
                params = {
                    "tagged_vlans": vlan,
                    f"device___custom_field_data__{self.cf_node_id}__gt": 0,
                }
                ifaces = Interface.objects.filter(**params)

                if not ifaces:
                    prefixes = Prefix.objects.filter(vlan=vlan)
                    for prefix in prefixes:
                        prefix.vlan = None
                        prefix.validated_save()
                        self.logger.info(
                            f"Prefix {prefix.prefix} VLAN removed from {vlan.vid}."
                        )
                    try:
                        self.logger.info(
                            f"Deleting VLAN {vlan.vid} from {group}.")
                        vlan.delete()

                    except Exception as e:
                        self.logger.error(
                            f"Error deleting VLAN {vlan.vid}: {e}")
                        continue
            try:
                vlg = VLANGroup.objects.get(name=group)
                if not vlg.vlans.all():
                    vlg.delete()
                    self.logger.info(f"Empty VLAN Group {group} deleted.")
            except ObjectDoesNotExist:
                continue

    def tenant_name(self, name):
        """Return tenant name."""
        if name in self.ndo_tenants:
            return f"NDO:{name}"
        return f"{self.apic.name}:{name}"

    def load_tenants(self):
        """Load tenants from ACI."""

        tenant_list = self.conn.get_tenants()
        if self.debug:
            self.logger.debug(f'{{"tenants": {tenant_list}}}')
        for _tenant in tenant_list:
            if _tenant["name"] not in IGNORE_TENANTS:
                if ":msc" in _tenant.get("annotation").lower():  # pylint: disable=simplifiable-if-statement
                    self.ndo_tenants.append(_tenant["name"])
                    tags = [self.mso_tag]
                else:
                    tags = []
                _ = self.util.get_tenant(
                    name=self.tenant_name(_tenant["name"]),
                    description=_tenant["description"],
                    tags=tags,
                    tenant_group=self.util.get_tenant_group(
                        name=self.apic.name),
                )

    def load_vrfs(self):
        """Load VRFs from ACI."""
        self.vrfs = []
        vrf_list = self.conn.get_vrfs(tenant="all")
        if self.debug:
            self.logger.debug(f'{{"VRFs": {vrf_list}}}')
        for _vrf in vrf_list:
            vrf_name = _vrf["name"]
            vrf_tenant = _vrf["tenant"]
            vrf_description = _vrf.get("description", "")
            if vrf_name in ["inb", "oob"] or vrf_tenant not in BUBBLE_TENANTS:
                namespace = "Global"
            else:
                namespace = BUBBLE_NAMESPACE
            if _vrf["tenant"] not in IGNORE_TENANTS:
                new_vrf = self.util.get_vrf(
                    name=vrf_name,
                    namespace=self.util.get_namespace(namespace),
                    description=vrf_description,
                    tenant=self.util.get_tenant(self.tenant_name(vrf_tenant)),
                )
                self.vrfs.append(new_vrf)

    # pylint: disable-next=too-many-branches

    def load_ipaddresses(self):
        """Load IPAddresses from ACI. Retrieves controller IPs, OOB Mgmt IP of leaf/spine, and Bridge Domain subnet IPs."""
        node_dict = self.conn.get_nodes()
        if self.debug:
            self.logger.debug(f'{{"nodes": {node_dict}}}')
        # Leaf/Spine management IP addresses
        mgmt_tenant = "mgmt"
        for node in node_dict.values():
            if node.get("oob_ip") and "mgmt" not in IGNORE_TENANTS:
                if node.get("subnet"):
                    subnet = node["subnet"]
                else:
                    subnet = ip_interface(
                        node["oob_ip"]).network.with_prefixlen
                tenant_name = self.tenant_name(mgmt_tenant)
                prefix, created = Prefix.objects.get_or_create(
                    prefix=subnet,
                    namespace=Namespace.objects.get(name="Global"),
                    defaults={
                        "tenant": Tenant.objects.get(name=tenant_name),
                        "status": Status.objects.get(name="Active"),
                        "type": PrefixTypeChoices.TYPE_NETWORK,
                    },
                )

                prefix.locations.add(self.device_site)
                prefix.vrfs.add(
                    VRF.objects.get(
                        name="oob", tenant=Tenant.objects.get(name=tenant_name)
                    )
                )
                if created:
                    self.logger.info(
                        f"Prefix {prefix.prefix} created for Tenant {tenant_name}."
                    )
                device = Device.objects.get(
                    name=self.util.nautobot_hostname(node["name"])
                )
                iface, created = Interface.objects.get_or_create(
                    device=device,
                    name="mgmt0",
                    defaults={
                        "type": InterfaceTypeChoices.TYPE_1GE_FIXED,
                        "status": Status.objects.get(name="Active"),
                        "mgmt_only": True,
                    },
                )
                if created:
                    self.logger.info(
                        f"Interface {iface.name} created for Device {device.name}."
                    )
                dns_name = self.util.dns_lookup(node["oob_ip"].split("/")[0])
                desired_dns_name = dns_name or ""
                new_ipaddress, created = IPAddress.objects.get_or_create(
                    address=node["oob_ip"],
                    namespace=prefix.namespace,
                    defaults={
                        "tenant": prefix.tenant,
                        "status": Status.objects.get(name="Active"),
                        "type": IPAddressTypeChoices.TYPE_HOST,
                        "dns_name": desired_dns_name,
                    },
                )
                if device.primary_ip4 != new_ipaddress:
                    device.primary_ip4 = new_ipaddress
                    device.save()
                if new_ipaddress.dns_name != desired_dns_name:
                    new_ipaddress.dns_name = desired_dns_name
                    new_ipaddress.save()
                if new_ipaddress not in iface.ip_addresses.all():
                    iface.add_ip_addresses(ip_addresses=[new_ipaddress])
                if created:
                    self.logger.info(
                        f"IPAddress {new_ipaddress.address} created for Tenant {new_ipaddress.tenant}."
                    )

        controller_dict = self.conn.get_controllers()
        if self.debug:
            self.logger.debug(f'{{"controllers": {controller_dict}}}')
        # Controller IP addresses
        for controller in controller_dict.values():
            if controller.get("oob_ip") and "mgmt" not in IGNORE_TENANTS:
                if controller.get("subnet"):
                    subnet = controller["subnet"]
                else:
                    subnet = ip_interface(
                        node["oob_ip"]).network.with_prefixlen
                tenant_name = self.tenant_name(mgmt_tenant)
                prefix, created = Prefix.objects.get_or_create(
                    prefix=subnet,
                    namespace=Namespace.objects.get(name="Global"),
                    defaults={
                        "tenant": Tenant.objects.get(name=tenant_name),
                        "status": Status.objects.get(name="Active"),
                        "type": PrefixTypeChoices.TYPE_NETWORK,
                    },
                )

                prefix.locations.add(self.device_site)
                prefix.vrfs.add(
                    VRF.objects.get(
                        name="oob", tenant=Tenant.objects.get(name=tenant_name)
                    )
                )
                if created:
                    self.logger.info(
                        f"Prefix {prefix.prefix} created for Tenant {tenant_name}."
                    )
                dns_name = self.util.dns_lookup(
                    controller["oob_ip"].split("/")[0])
                desired_dns_name = dns_name or ""
                device = Device.objects.get(
                    name=self.util.nautobot_hostname(controller["name"])
                )
                iface, created = Interface.objects.get_or_create(
                    device=device,
                    name="mgmt0",
                    defaults={
                        "type": InterfaceTypeChoices.TYPE_1GE_FIXED,
                        "status": Status.objects.get(name="Active"),
                        "mgmt_only": True,
                    },
                )
                if created:
                    self.logger.info(
                        f"Interface {iface.name} created for Device {device.name}."
                    )
                new_ipaddress, created = IPAddress.objects.update_or_create(
                    address=controller["oob_ip"],
                    namespace=prefix.namespace,
                    defaults={
                        "tenant": prefix.tenant,
                        "status": Status.objects.get(name="Active"),
                        "type": IPAddressTypeChoices.TYPE_HOST,
                        "dns_name": desired_dns_name,
                    },
                )
                if device.primary_ip4 != new_ipaddress:
                    device.primary_ip4 = new_ipaddress
                    device.save()
                if new_ipaddress.dns_name != desired_dns_name:
                    new_ipaddress.dns_name = desired_dns_name
                    new_ipaddress.save()
                if new_ipaddress not in iface.ip_addresses.all():
                    iface.add_ip_addresses(ip_addresses=[new_ipaddress])
                if created:
                    self.logger.info(
                        f"IPAddress {new_ipaddress.address} created for Tenant {new_ipaddress.tenant}."
                    )

        # Bridge domain subnets
        bd_dict = self.conn.get_bds(tenant="all")
        if self.debug:
            self.logger.debug(f'{{"bridge_domains": {bd_dict}}}')
        for bd_key, bd_value in bd_dict.items():
            if bd_value.get("subnets"):
                tenant_name = bd_value.get("tenant")

                if (
                    bd_value.get("tenant") == "mgmt"
                    or bd_value.get("tenant") not in BUBBLE_TENANTS
                ):
                    _namespace = "Global"
                else:
                    _namespace = BUBBLE_NAMESPACE
                for subnet, _ in bd_value["subnets"]:
                    if all(
                        tenant not in IGNORE_TENANTS
                        for tenant in [
                            bd_value.get("tenant"),
                            bd_value.get("vrf_tenant"),
                        ]
                    ):
                        cidr_subnet = ip_network(
                            subnet, strict=False).with_prefixlen
                        tenant_name = self.tenant_name(
                            bd_value["vrf_tenant"] or bd_value.get("tenant")
                        )
                        prefix, created = Prefix.objects.get_or_create(
                            prefix=cidr_subnet,
                            namespace=Namespace.objects.get(name=_namespace),
                            defaults={
                                "description": f"ACI Bridge Domain: {bd_key}",
                                "tenant": Tenant.objects.get(name=tenant_name),
                                "status": Status.objects.get(name="Active"),
                                "type": PrefixTypeChoices.TYPE_NETWORK,
                            },
                        )
                        prefix.locations.add(self.device_site)
                        vrf, created = VRF.objects.get_or_create(
                            name=bd_value["vrf"],
                            tenant=Tenant.objects.get(name=tenant_name),
                            namespace=prefix.namespace,
                        )
                        if created:
                            self.logger.info(
                                f"VRF {vrf.name} created for Tenant {tenant_name} in namespace {prefix.namespace}."
                            )
                        prefix.vrfs.add(vrf)
                        if created:
                            self.logger.info(
                                f"Prefix {prefix.prefix} created for Tenant {tenant_name}."
                            )
                        dns_name = self.util.dns_lookup(subnet.split("/")[0])
                        try:
                            new_ipaddress, created = IPAddress.objects.get_or_create(
                                # Work around for bug #7024
                                host=subnet.split("/")[0],
                                # Work around for bug #7024
                                mask_length=subnet.split("/")[1],
                                namespace=prefix.namespace,
                                defaults={
                                    "tenant": prefix.tenant,
                                    "status": Status.objects.get(name="Active"),
                                    "type": IPAddressTypeChoices.TYPE_HOST,
                                    "dns_name": dns_name or "",
                                },
                            )
                            if dns_name and new_ipaddress.dns_name != dns_name:
                                new_ipaddress.dns_name = dns_name
                                new_ipaddress.save()
                            if created:
                                self.logger.info(
                                    f"IPAddress {new_ipaddress.address} created for Tenant {new_ipaddress.tenant}."
                                )
                        except Exception as e:
                            self.logger.error(
                                f"Error creating IPAddress {subnet}: {e}")

    def mate_vlan_with_interface(self, vlan_object, nb_vlan, iface):
        if iface.mode != InterfaceModeChoices.MODE_TAGGED:
            iface.mode = InterfaceModeChoices.MODE_TAGGED
            iface.save()
            self.logger.info(
                f"Interface {iface.name} ({iface.device.name}) mode set to tagged."
            )

        if vlan_object.mode == "untagged":
            if nb_vlan in iface.tagged_vlans.all():
                iface.tagged_vlans.remove(nb_vlan)
                self.logger.info(
                    f"VLAN {nb_vlan.name} ({nb_vlan.vid}) removed from Device {iface.device.name} Interface {iface.name} as tagged VLAN and set as untagged VLAN."
                )
            if iface.untagged_vlan != nb_vlan:
                iface.untagged_vlan = nb_vlan
                iface.save()
        elif nb_vlan not in iface.tagged_vlans.all():
            iface.tagged_vlans.add(nb_vlan)
            self.logger.info(
                f"VLAN {nb_vlan.name} ({nb_vlan.vid}) added to Device {iface.device.name} Interface {iface.name}."
            )

    def load_epgs(self):
        paths = self.conn.get_static_path()
        if self.debug:
            self.logger.debug(f'{{"static_paths": {[str(x) for x in paths]}}}')
        for path in paths:
            if path.node_id == 0 and not path.members:
                self.log_concern(
                    f"Interface Policy Group {path.name} has no port members. You should consider removing it from the fabric.")
                continue
            if path.type == "non-PC":
                try:
                    device = self.get_device_by_node_id(path.node_id)
                    iface = Interface.objects.get(
                        device=device, name=path.name)

                except ObjectDoesNotExist:
                    self.logger.warning(
                        f"Device with node_id {path.node_id} and Interface {path.name} not found."
                    )
                    continue
            else:
                ifaces = []
                lags = []
                for member in path.members:
                    device = Device.objects.get(
                        name=self.util.nautobot_hostname(member.hostname)
                    )
                    iface_lag, created = Interface.objects.get_or_create(
                        device=device,
                        name=path.name,
                        defaults={
                            "type": InterfaceTypeChoices.TYPE_LAG,
                            "status": Status.objects.get(name="Active"),
                            "mode": InterfaceModeChoices.MODE_TAGGED,
                        },
                    )
                    lags.append(iface_lag)

                    if created:
                        self.logger.info(
                            f"Interface {iface_lag.name} created for Device {member.hostname}."
                        )

                    for intf in member.interfaces:
                        iface, created = Interface.objects.get_or_create(
                            device=device,
                            name=intf,
                            defaults={
                                "type": InterfaceTypeChoices.TYPE_OTHER,
                                "status": Status.objects.get(name="Active"),
                                "mode": InterfaceModeChoices.MODE_TAGGED,
                            },
                        )

                        if created:
                            self.logger.info(
                                f"Interface {iface.name} created for Device {member.hostname}."
                            )
                        if iface.lag != iface_lag:
                            iface.lag = iface_lag
                            iface.save()

                        ifaces.append(iface)
                if ifaces:
                    grouped = [
                        x for x in ifaces if x.device.device_redundancy_group]

                    if len(grouped) <= 1:
                        device_rg, created = (
                            DeviceRedundancyGroup.objects.get_or_create(
                                name=f"{ifaces[0].device.name}-{ifaces[1].device.name}",
                                defaults={
                                    "description": "VPC Pair Group",
                                    "status": Status.objects.get(name="Active"),
                                },
                            )
                        )
                        if created:
                            self.logger.info(
                                f"Device Redundancy Group {device_rg.name} created for VPC Pair tracking."
                            )
                        for iface in ifaces:
                            if iface.device not in device_rg.devices.all():
                                device_rg.devices.add(iface.device)
                                self.logger.info(
                                    f"Device {iface.device.name} added to Device Redundancy Group {device_rg.name}."
                                )

            for vlan in path.vlans:
                nb_tenant = Tenant.objects.get(
                    name=self.tenant_name(vlan.tenant))
                vlg_name = self.make_vlan_group_name(vlan.tenant)
                vlg, created = VLANGroup.objects.get_or_create(name=vlg_name)
                if created:
                    self.logger.info(f"VLAN Group {vlg_name} created.")
                try:
                    if re.search('[0-9]+', vlan.bd):
                        # We have a possible vlan number in the name
                        if not re.search(str(vlan.vlan), vlan.bd):
                            # if the vlan number is not in the name, we likely have a problem
                            raise ValidationError(
                                f"VLAN {vlan.vlan} does not seem to match {vlan.bd}.  VLAN encap setting may be incorrect."
                            )
                    nb_vlan, created = VLAN.objects.get_or_create(
                        vlan_group=vlg,
                        name=vlan.bd,
                        defaults={
                            "vid": vlan.vlan,
                            "status": Status.objects.get(name="Active"),
                            "tenant": nb_tenant,
                        },
                    )
                    # if nb_vlan.name != vlan.bd:
                    #     nb_vlan.name = vlan.bd
                    #     nb_vlan.save()
                    #     self.logger.info(
                    #         f"VLAN {vlan.bd} ({vlan.vlan}) name updated to {nb_vlan.name}."
                    #     )
                    # if nb_vlan.tenant != nb_tenant:
                    #     nb_vlan.tenant = nb_tenant
                    #     nb_vlan.save()
                    #     self.logger.info(
                    #         f"VLAN {vlan.bd} ({vlan.vlan}) tenant updated to {nb_tenant.name}."
                    #     )
                    if created:
                        self.logger.info(
                            f"VLAN {vlan.bd} ({vlan.vlan}) created for VLAN Group {vlg_name}."
                        )
                    if (
                        self.apic.location.parent
                        and self.apic.location.parent not in nb_vlan.locations.all()
                    ):
                        nb_vlan.locations.add(self.apic.location.parent)
                    if self.apic.location not in nb_vlan.locations.all():
                        nb_vlan.locations.add(self.apic.location)

                    self.set_cf_value(self.cf_ap, nb_vlan, vlan.ap)
                    self.set_cf_value(self.cf_epg, nb_vlan, vlan.epg)
                    self.set_cf_value(self.cf_bd, nb_vlan, vlan.bd)
                    self.set_cf_value(self.cf_tenant, nb_vlan, vlan.tenant)

                    if path.type == "non-PC":
                        self.mate_vlan_with_interface(vlan, nb_vlan, iface)
                    else:
                        for iface_lag in lags:
                            self.mate_vlan_with_interface(
                                vlan, nb_vlan, iface_lag)
                        for iface in ifaces:
                            self.mate_vlan_with_interface(vlan, nb_vlan, iface)

                except Exception as e:
                    if self.debug:
                        self.logger.error(
                            f"Error creating VLAN {vlan.vlan} for VLAN Group {vlg_name}: {e}"
                        )
                    self.log_concern(
                        f"Detected VLAN {vlan.vlan} tagged on {'Interface Policy Group: ' + path.name if path.type != 'non-PC' else 'Node: ' + str(path.node_id) + ' Interface: ' + path.name} does not match ACI Bridge Domain {vlan.bd}.  Likely incorrect VLAN encap setting, please investigate.")
                    if created:
                        try:
                            nb_vlan.delete()
                        except Exception as e:
                            self.logger.error(
                                f"Error deleting VLAN {nb_vlan.vid}: {e}")
                    continue

    def log_concern(self, msg):
        """Log a concern."""
        self.concerns.append(msg)
        self.logger.warning(msg)

    def make_vlan_group_name(self, tenant_name) -> str:
        """Return VLAN Group name."""
        if "stretch" in tenant_name.lower():
            return tenant_name
        return f"{self.apic.name}:{tenant_name}"
        # else:
        #     if self.apic.location.parent:
        #         vlg_name = self.apic.location.parent.name
        #     else:
        #         vlg_name = self.apic.location.name
        # return vlg_name

    def load_prefixes(self):
        """Load Bridge domain subnets from ACI."""
        bd_dict = self.conn.get_bds(tenant="all")
        if self.debug:
            self.logger.debug(f'{{"bridge_domains": {bd_dict}}}')
        # pylint: disable-next=too-many-nested-blocks
        for bd_key, bd_value in bd_dict.items():
            if bd_value.get("subnets"):
                nb_tenant = Tenant.objects.get(
                    name=self.tenant_name(bd_value.get("tenant"))
                )

                if (
                    bd_value.get("tenant") == "mgmt"
                    or bd_value.get("tenant") not in BUBBLE_TENANTS
                ):
                    _namespace = "Global"
                else:
                    _namespace = BUBBLE_NAMESPACE

                if bd_value.get("tenant") not in IGNORE_TENANTS:
                    vlg_name = self.make_vlan_group_name(
                        bd_value.get("tenant"))

                    vlan_group = self.util.get_vlan_group(
                        vlg_name, self.device_site)

                    try:
                        vlan = VLAN.objects.get(
                            name=bd_value["name"], vlan_group=vlan_group
                        )

                    except ObjectDoesNotExist:
                        self.log_concern(
                            f"ACI Bridge Domain {bd_value['name']} under tenant {bd_value.get('tenant')} appears to have no associated bindings.  Please check the ACI configuration and consider removing it from the fabric.")
                        vlan = None

                    for subnet, _ in bd_value["subnets"]:
                        new_prefix = self.util.get_prefix(
                            prefix=str(ip_network(subnet, strict=False)),
                            namespace=self.util.get_namespace(_namespace),
                            tenant=nb_tenant,
                            description=f"ACI Bridge Domain: {bd_key}",
                        )

                        if bd_value.get("vrf", None) != "":
                            for vrf in [
                                self.util.get_vrf(
                                    name=bd_value["vrf"],
                                    namespace=self.util.get_namespace(
                                        _namespace),
                                    tenant=nb_tenant,
                                )
                            ]:
                                new_prefix.vrfs.add(vrf)

                        prefix_changed = False
                        if vlan:
                            if new_prefix.vlan != vlan:
                                new_prefix.vlan = vlan
                                prefix_changed = True
                        new_prefix.locations.add(self.device_site)
                        if prefix_changed:
                            new_prefix.validated_save()

    def load_interfaces(self):
        """Load interfaces from ACI."""

        interfaces = self.conn.get_interfaces(
            nodes=self.nodes,
        )
        if self.debug:
            self.logger.debug(f'{{"interfaces": {interfaces}}}')

        for device in self.devices:
            for interface_name, interface in interfaces[
                str(device.custom_field_data[self.cf_node_id.key])
            ].items():
                new_interface = self.util.get_interface(
                    device=device, name=interface_name.replace(
                        "eth", "Ethernet")
                )

                if interface["gbic_model"]:
                    if "cisco" in interface["gbic_vendor"].lower():
                        interface["gbic_vendor"] = "Cisco"

                    sfp_mfg, created = Manufacturer.objects.get_or_create(
                        name=interface["gbic_vendor"].capitalize()
                    )
                    if created:
                        self.logger.info(
                            f"Manufacturer {sfp_mfg.name} created.")
                    sfp, created = InventoryItem.objects.update_or_create(
                        device=device,
                        name=new_interface.name,
                        defaults={
                            "serial": interface["gbic_sn"],
                            "part_id": interface["gbic_model"],
                            "manufacturer": sfp_mfg,
                            "discovered": True,
                        },
                    )
                    if created:
                        self.logger.info(
                            f"Inventory Item SFP {sfp.part_id} in interface {sfp.name} created for Device {device.name}."
                        )

                iface_changed = False
                new_description = interface["descr"]
                new_mtu = int(interface["mtu"])
                new_enabled = interface["admin"] == "up"
                if new_interface.description != new_description:
                    new_interface.description = new_description
                    iface_changed = True
                if new_interface.mtu != new_mtu:
                    new_interface.mtu = new_mtu
                    iface_changed = True
                if new_interface.enabled != new_enabled:
                    new_interface.enabled = new_enabled
                    iface_changed = True
                if interface["usage"] != "fabric":
                    if interface["mode"] == "trunk":
                        if new_interface.mode != InterfaceModeChoices.MODE_TAGGED:
                            new_interface.mode = InterfaceModeChoices.MODE_TAGGED
                            iface_changed = True
                if iface_changed:
                    new_interface.save()

                if interface["state"] == "up" and self.discover_neighbors:
                    pod_id = device.custom_field_data[self.cf_pod_id.key]
                    node_id = device.custom_field_data[self.cf_node_id.key]
                    lldp_nbrs = self.conn.get_lldp_neighbors(
                        pod=pod_id, node_id=node_id, interface=new_interface.name
                    )
                    cdp_nbrs = self.conn.get_cdp_neighbors(
                        pod=pod_id, node_id=node_id, interface=new_interface.name
                    )

                    nbr_dicts = []
                    nbr_dicts.extend(lldp_nbrs)
                    nbr_dicts.extend(cdp_nbrs)
                    for nbr_dict in nbr_dicts:
                        try:
                            remote_device = Device.objects.get(
                                name__iexact=self.util.nautobot_hostname(
                                    nbr_dict["remote_device"]
                                )
                            )

                            remote_interface, created = Interface.objects.get_or_create(
                                device=remote_device,
                                name=self.util.real_interface_name(
                                    nbr_dict["remote_interface"]
                                ),
                                defaults={
                                    "type": InterfaceTypeChoices.TYPE_OTHER,
                                    "status": Status.objects.get(name="Active"),
                                },
                            )
                            if created:
                                self.logger.info(
                                    f"Interface {remote_interface.name} created for Device {remote_device.name}."
                                )

                            if (
                                not new_interface.connected_endpoint
                                and not remote_interface.connected_endpoint
                            ):
                                _, created = Cable.objects.get_or_create(
                                    termination_a_id=new_interface.id,
                                    termination_a_type=ContentType.objects.get_for_model(
                                        new_interface
                                    ),
                                    termination_b_id=remote_interface.id,
                                    termination_b_type=ContentType.objects.get_for_model(
                                        remote_interface
                                    ),
                                    defaults={
                                        "status": self.util.status_connected},
                                )
                                if created:
                                    self.logger.info(
                                        f"Cable created between {new_interface.device.name} {new_interface.name} and {remote_interface.device.name} {remote_interface.name}."
                                    )
                        except ObjectDoesNotExist:
                            self.log_concern(
                                f"CDP/LLDP Discovered Remote Device {nbr_dict['remote_device']} ({nbr_dict['remote_interface']}) connected to {device.name} ({new_interface.name}) but Device/Interface not in Nautobot."
                            )
                        except Exception as e:
                            self.logger.warning(
                                f"Attempted to create a Cable between {new_interface.device.name} ({new_interface.name}) and {remote_interface.device.name} ({remote_interface.name}), but an existing Cable was found."
                            )
                            continue

    def set_cf_value(self, custom_field, object, value):
        """Set Custom Field value."""

        if not object.custom_field_data.get(custom_field.key, None) or object.custom_field_data[custom_field.key] != value:
            object.custom_field_data[custom_field.key] = value
            object.validated_save()

    def ensure_cf(
        self,
        label,
        type: CustomFieldTypeChoices,
        models: list,
        description="",
        grouping="Cisco ACI",
    ):
        """Ensure Custom Field for ACI Node ID exists."""
        cf, created = CustomField.objects.get_or_create(
            label=label,
            type=type,
            defaults={
                "grouping": grouping,
                "description": description,
            },
        )
        if created:
            for model in models:
                cf.content_types.add(ContentType.objects.get_for_model(model))

            self.logger.info(f"Custom Field '{label}' created.")
        return cf

    def get_device_by_node_id(self, node_id):
        """Return device by ACI Node ID."""
        try:
            params = {
                f"_custom_field_data__{self.cf_node_id.key}": node_id,
                "controller_managed_device_group__name": self.apic.name,
            }
            device = Device.objects.get(**params)
            return device
        except ObjectDoesNotExist:
            return None
        except Exception as e:
            self.logger.error(
                f"Error retrieving Device with Node ID {node_id}: {e}")

    def load_devices(self):
        """Load devices from ACI device data."""
        self.nodes = self.conn.get_nodes()
        self.controllers = self.conn.get_controllers()
        self.nodes.update(self.controllers)
        self.devices = []
        if self.debug:
            self.logger.debug(f'{{"nodes": {self.nodes}}}')

        for key, value in self.nodes.items():
            device_type = self.util.get_device_type(model=value["model"])
            role, created = Role.objects.get_or_create(name=value["role"])
            content_types = ContentType.objects.get_for_model(Device)
            if content_types not in role.content_types.all():
                role.content_types.add(content_types)
            if created:
                self.logger.info(
                    f"Role {value['role']} created for Device content type."
                )

            platform, created = Platform.objects.get_or_create(
                name="cisco_aci")
            if created:
                self.logger.info("Platform cisco_aci created.")
            new_device = self.util.get_device(
                name=self.util.nautobot_hostname(value["name"]),
                device_type=device_type,
                role=role,
                location=self.device_site,
                platform=platform,
                serial=value["serial"],
            )
            self.set_cf_value(self.cf_node_id, new_device, int(key))
            self.set_cf_value(self.cf_pod_id, new_device, int(value["pod_id"]))

            self.devices.append(new_device)

        device_rg, created = DeviceRedundancyGroup.objects.get_or_create(
            name=self.apic.name,
            defaults={
                "description": f"Device Redundancy Group for {self.apic.name}",
                "status": Status.objects.get(name="Active"),
            },
        )
        if created:
            self.logger.info(
                f"Device Redundancy Group {device_rg.name} created.")
        for controller in self.controllers.values():
            device = Device.objects.get(
                name=self.util.nautobot_hostname(controller["name"])
            )
            if device.device_redundancy_group != device_rg:
                device.device_redundancy_group = device_rg
                device.save()
        if self.apic.controller_device_redundancy_group != device_rg:
            self.apic.controller_device_redundancy_group = device_rg
            self.apic.save()
        device_group, created = ControllerManagedDeviceGroup.objects.get_or_create(
            controller=self.apic, name=self.apic.name
        )
        if created:
            self.logger.info(
                f"Controller Managed Device Group {device_group.name} created."
            )
        for node in self.nodes.values():
            device = Device.objects.get(
                name=self.util.nautobot_hostname(node["name"])
            )
            if device.controller_managed_device_group != device_group:
                device.controller_managed_device_group = device_group
                device.save()


register_jobs(CiscoACI)
