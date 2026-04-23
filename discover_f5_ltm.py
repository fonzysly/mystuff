"""
F5 LTM Discovery Job for Nautobot 2.4

This job discovers and synchronizes F5 LTM (Local Traffic Manager) configuration
into Nautobot Load Balancer models.
"""
import socket
import requests
from typing import Dict, List, Optional, Tuple
from urllib3.exceptions import InsecureRequestWarning
from django.contrib.contenttypes.models import ContentType
from django.db.models.deletion import ProtectedError
from django.utils import timezone
import ipaddress
from datetime import datetime, timezone as dt_timezone

# Nautobot imports
from nautobot.apps.jobs import Job, ObjectVar, BooleanVar, register_jobs
from nautobot.virtualization.models import VirtualMachine
from nautobot.extras.models import SecretsGroup, CustomField, Relationship, Status, RelationshipAssociation, RelationshipModel
from nautobot.ipam.models import IPAddress, Prefix, Namespace

from nautobot.extras.choices import (
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
    CustomFieldTypeChoices,
    RelationshipTypeChoices,
    RelationshipSideChoices,
    RelationshipRequiredSideChoices
)

# Load Balancer Models
from nautobot.load_balancers.models import (
    VirtualServer,
    LoadBalancerPool,
    LoadBalancerPoolMember,
    HealthCheckMonitor,
    CertificateProfile,
)
from nautobot.load_balancers.choices import HealthCheckTypeChoices, LoadBalancingAlgorithmChoices, LoadBalancerTypeChoices, ProtocolChoices, SourceNATTypeChoices, LoadBalancerPoolMemberStatusChoices, CertificateTypeChoices

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

name = "Discovery"


class DiscoverF5LTM(Job):
    """
    Job to discover F5 LTM (Local Traffic Manager) configuration and populate
    Nautobot Load Balancer models.
    """

    class Meta:
        name = "Discover F5 LTM"
        description = "Discover F5 LTM configuration and populate Nautobot Load Balancer models"
        field_order = ['f5_device', 'secrets_group', 'purge_orphans']
        has_sensitive_variables = False

    f5_device = ObjectVar(
        model=VirtualMachine,
        required=False,
        label="F5 Device",
        description="The F5 LTM virtual machine to query",
        query_params={"platform": ["bigip_f5"], "has_primary_ip": True}
    )

    secrets_group = ObjectVar(
        model=SecretsGroup,
        required=True,
        label="Secrets Group",
        description="Secrets group containing F5 credentials",
    )

    purge_orphans = BooleanVar(
        required=False,
        default=False,
        label="Purge Orphans",
        description="Delete Nautobot load balancer objects linked to this F5 device if they are no longer present on the F5"
    )

    def __init__(self):
        super().__init__()
        self.session = None
        self.f5_host = None
        self.token = None
        self.base_url = None
        self.partitions = []
        self.relationships = {}
        self.certificate_expirations = {}
        self.purge_orphans = False

    def ensure_custom_fields(self):
        """
        Ensure the custom fields exist for all Load Balancer models.
        """
        self.logger.info("Ensuring custom fields are present")

        models = [
            VirtualServer,
            LoadBalancerPool,
            LoadBalancerPoolMember,
            HealthCheckMonitor,
            CertificateProfile
        ]

        try:
            cf, created = CustomField.objects.get_or_create(
                label="Partition",
                type=CustomFieldTypeChoices.TYPE_TEXT,
                defaults={
                    "description": "F5 LTM Partition",
                    "required": False,
                    "filter_logic": "loose",
                }
            )
            if created:
                self.logger.info("Created custom field 'Partition'")
            self.cf_partition = cf
        except Exception as e:
            self.logger.error(
                f"Failed to create custom field 'Partition': {str(e)}")
        for model in models:
            cf.content_types.add(ContentType.objects.get_for_model(model))

    def ensure_custom_relationships(self):
        """
        Ensure custom relationships exist between Load Balancer models and VirtualMachine.
        """
        self.logger.info("Ensuring custom relationships are present")

        vm_content_type = VirtualMachine._meta.label

        models = [
            VirtualServer,
            LoadBalancerPool,
            LoadBalancerPoolMember,
            HealthCheckMonitor,
            CertificateProfile
        ]

        for model in models:
            model_name = model.__name__
            content_type = model._meta.label

            relationship_name = f"{model_name}_VirtualMachine"
            try:
                relationship, created = Relationship.objects.get_or_create(
                    label=relationship_name,
                    type=RelationshipTypeChoices.TYPE_MANY_TO_MANY,
                    required_on=RelationshipRequiredSideChoices.NEITHER_SIDE_REQUIRED,
                    defaults={
                        "source_type": ContentType.objects.get_for_model(VirtualMachine),
                        "destination_type": ContentType.objects.get_for_model(model),
                        "source_label": model_name,
                        "destination_label": "F5 LTM Device",
                        "source_filter": {"platform": ["bigip_f5"]},
                        "source_hidden": False
                    }
                )
                self.relationships[model_name] = relationship
                if created:
                    self.logger.info(
                        f"Created relationship between {content_type} and {vm_content_type}")
                else:
                    self.logger.debug(
                        f"Relationship between {content_type} and {vm_content_type} already exists")
            except Exception as e:
                self.logger.error(
                    f"Failed to create relationship for {content_type}: {str(e)}")

    def get_auth_credentials(self) -> Tuple[str, str]:
        """
        Extract username and password from the SecretsGroup.

        Returns:
            Tuple[str, str]: Username and password for F5 authentication
        """
        try:
            # Get username and password from secrets group

            username = self.secrets_group.get_secret_value(
                access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME,
            )
            password = self.secrets_group.get_secret_value(
                access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
            )

            if not username or not password:
                self.logger.error(
                    "Username or password not found in secrets group")
                return None, None

            return username, password

        except Exception as e:
            self.logger.error(
                f"Failed to get authentication credentials: {str(e)}")
            return None, None

    def authenticate(self) -> bool:
        """
        Authenticate to the F5 LTM API and get token.

        Returns:
            bool: True if authentication successful, False otherwise
        """
        username, password = self.get_auth_credentials()
        self.session.auth = (username, password)

        return True

    def get_partitions(self) -> List[str]:
        """
        Get list of partitions from F5 LTM.

        Returns:
            List[str]: List of partition names
        """
        url = f"{self.base_url}/mgmt/tm/auth/partition"

        try:
            response = self.session.get(url, verify=False)
            response.raise_for_status()

            partitions_data = response.json()

            if 'items' in partitions_data:
                partitions = [item['name']
                              for item in partitions_data['items']]
                self.logger.info(
                    f"Found {len(partitions)} partitions: {', '.join(partitions)}")
                return partitions

            self.logger.warning("No partitions found in response")
            return ['Common']  # Default to Common partition

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get partitions: {str(e)}")
            if hasattr(e, 'response') and e.response:
                self.logger.debug(f"Response status: {e.response.status_code}")
                self.logger.debug(f"Response body: {e.response.text}")
            return ['Common']  # Default to Common partition

    def get_virtual_addresses(self):
        self.virtual_addresses = []
        url = f"{self.base_url}/mgmt/tm/ltm/virtual-address"
        params = {
            "expandSubcollections": "true"
        }
        try:
            response = self.session.get(url, params=params, verify=False)
            response.raise_for_status()

            virtual_addresses = response.json().get("items", [])
            self.logger.info(
                f"Found {len(virtual_addresses)} virtual addresses")
            self.virtual_addresses = virtual_addresses

        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Failed to get virtual addresses: {str(e)}")
            if hasattr(e, 'response') and e.response:
                self.logger.debug(f"Response status: {e.response.status_code}")
                self.logger.debug(f"Response body: {e.response.text}")
            self.virtual_addresses = []

    def get_nodes(self):
        url = f"{self.base_url}/mgmt/tm/ltm/node"
        params = {
            "expandSubcollections": "true"
        }
        self.nodes = {}
        try:
            response = self.session.get(url, params=params, verify=False)
            response.raise_for_status()

            items = response.json().get("items", [])
            for item in items:
                self.nodes[item['name']] = item
            self.logger.info(
                f"Found {len(self.nodes)} nodes")

        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Failed to get nodes: {str(e)}")
            if hasattr(e, 'response') and e.response:
                self.logger.debug(f"Response status: {e.response.status_code}")
                self.logger.debug(f"Response body: {e.response.text}")

    def get_virtual_servers(self) -> List[Dict]:
        """
        Get virtual servers


        Returns:
            List[Dict]: List of virtual server dictionaries
        """
        url = f"{self.base_url}/mgmt/tm/ltm/virtual"
        params = {
            "expandSubcollections": "true"
        }

        try:
            response = self.session.get(url, params=params, verify=False)
            response.raise_for_status()

            vs_data = response.json()

            if 'items' in vs_data:
                self.logger.info(
                    f"Found {len(vs_data['items'])} virtual servers")
                return vs_data['items']

            self.logger.warning(
                f"No virtual servers found")
            return []

        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Failed to get virtual server: {str(e)}")
            if hasattr(e, 'response') and e.response:
                self.logger.debug(f"Response status: {e.response.status_code}")
                self.logger.debug(f"Response body: {e.response.text}")
            return []

    def get_pools(self) -> List[Dict]:
        """
        Get pools


        Returns:
            List[Dict]: List of pool dictionaries
        """
        url = f"{self.base_url}/mgmt/tm/ltm/pool"
        params = {
            "expandSubcollections": "true"
        }

        try:
            response = self.session.get(url, params=params, verify=False)
            response.raise_for_status()

            pools_data = response.json()

            if 'items' in pools_data:
                self.logger.info(
                    f"Found {len(pools_data['items'])} pools")
                return pools_data['items']

            self.logger.warning(f"No pools found")
            return []

        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Failed to get pools: {str(e)}")
            if hasattr(e, 'response') and e.response:
                self.logger.debug(f"Response status: {e.response.status_code}")
                self.logger.debug(f"Response body: {e.response.text}")
            return []

    def get_monitors(self, ) -> List[Dict]:
        """
        Get health monitors.


        Returns:
            List[Dict]: List of health monitor dictionaries
        """
        # F5 has different monitor types with different endpoints
        monitor_types = [
            "http", "https", "tcp", "udp", "icmp", "gateway-icmp",
            "tcp-half-open", "ftp", "dns"
        ]

        all_monitors = []

        for monitor_type in monitor_types:
            url = f"{self.base_url}/mgmt/tm/ltm/monitor/{monitor_type}"

            try:
                response = self.session.get(url,  verify=False)
                response.raise_for_status()

                monitor_data = response.json()

                if 'items' in monitor_data:
                    self.logger.debug(
                        f"Found {len(monitor_data['items'])} {monitor_type} monitors")

                    # Add monitor type to each item for reference
                    for item in monitor_data['items']:
                        item['monitor_type'] = monitor_type

                    all_monitors.extend(monitor_data['items'])

            except requests.exceptions.RequestException as e:
                # Just log and continue - some monitor types might not exist
                self.logger.debug(
                    f"Failed to get {monitor_type} monitors: {str(e)}")

        self.logger.info(
            f"Found {len(all_monitors)} total monitors")
        return all_monitors

    def get_certificate_profiles(self) -> List[Dict]:
        """
        Get SSL profiles (certificate profiles).

        Returns:
            List[Dict]: List of SSL profile dictionaries
        """
        # For client SSL profiles
        client_ssl_url = f"{self.base_url}/mgmt/tm/ltm/profile/client-ssl"
        # For server SSL profiles
        server_ssl_url = f"{self.base_url}/mgmt/tm/ltm/profile/server-ssl"

        profiles = []

        # Get client SSL profiles
        try:
            response = self.session.get(
                client_ssl_url, verify=False)
            response.raise_for_status()

            ssl_data = response.json()

            if 'items' in ssl_data:
                # Add profile type to each item
                for item in ssl_data['items']:
                    item['profile_type'] = 'client'
                profiles.extend(ssl_data['items'])
                self.logger.debug(
                    f"Found {len(ssl_data['items'])} client SSL profiles")

        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Failed to get client SSL profiles: {str(e)}")

        # Get server SSL profiles
        try:
            response = self.session.get(
                server_ssl_url,  verify=False)
            response.raise_for_status()

            ssl_data = response.json()

            if 'items' in ssl_data:
                # Add profile type to each item
                for item in ssl_data['items']:
                    item['profile_type'] = 'server'
                profiles.extend(ssl_data['items'])
                self.logger.debug(
                    f"Found {len(ssl_data['items'])} server SSL profiles")

        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Failed to get server SSL profiles: {str(e)}")

        self.logger.info(
            f"Found {len(profiles)} total SSL profiles")
        return profiles

    def extract_ip_port(self, destination: str) -> Tuple[str, Optional[int]]:
        """
        Extract IP and port from F5 destination string format.

        Args:
            destination (str): F5 destination string (e.g., "/Common/192.168.1.1:80" or "/Common/192.168.1.1.80")

        Returns:
            Tuple[str, Optional[int]]: IP address and port (if present)
        """
        # Extract IP address and port from destination
        # Format can be either /partition/ip:port or /partition/ip.port
        if not destination:
            return None, None

        # Remove partition prefix
        if '/' in destination:
            _, dest = destination.rsplit('/', 1)
        else:
            dest = destination

        # Extract IP and port
        if ':' in dest:
            # Format: IP:port
            ip, port_str = dest.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = None
        elif '.' in dest:
            # Format: IP.port
            parts = dest.split('.')
            if len(parts) >= 5:  # At least 4 octets for IP plus port
                port_str = parts[-1]
                ip = '.'.join(parts[:-1])
                try:
                    port = int(port_str)
                except ValueError:
                    port = None
            else:
                ip = dest
                port = None
        else:
            ip = dest
            port = None

        return ip, port

    def extract_pool_name(self, pool_path: str) -> str:
        """
        Extract pool name from F5 pool path.

        Args:
            pool_path (str): F5 pool path (e.g., "/Common/my_pool")

        Returns:
            str: Pool name
        """
        if not pool_path:
            return None

        # Remove partition prefix
        if '/' in pool_path:
            _, pool_name = pool_path.rsplit('/', 1)
            return pool_name

        return pool_path

    def extract_monitor_info(self, monitor_data: Dict) -> Dict:
        """
        Extract health check monitor information from F5 monitor data.

        Args:
            monitor_data (Dict): F5 monitor data

        Returns:
            Dict: Monitor information
        """
        monitor_info = {
            'name': monitor_data.get('name'),
            'interval': int(monitor_data.get('interval', 5)),
            'timeout': int(monitor_data.get('timeout', 16)),
            'health_check_type': monitor_data.get('kind', 'tm:ltm:monitor:tcp:tcpstate').split(':')[3].upper(),
        }
        match monitor_info['health_check_type']:
            case 'ICMP':
                monitor_info['health_check_type'] = HealthCheckTypeChoices.PING
            case 'DNS':
                monitor_info['health_check_type'] = HealthCheckTypeChoices.DNS
            case 'HTTPS':
                monitor_info['health_check_type'] = HealthCheckTypeChoices.HTTPS
            case 'HTTP':
                monitor_info['health_check_type'] = HealthCheckTypeChoices.HTTP
            case 'TCP':
                monitor_info['health_check_type'] = HealthCheckTypeChoices.TCP
            case _:
                monitor_info['health_check_type'] = HealthCheckTypeChoices.CUSTOM

        # Handle retry count (F5 uses "up/down interval" or "time until up")
        if 'upInterval' in monitor_data:
            monitor_info['retry'] = int(monitor_data.get('upInterval', 3))
        elif 'timeUntilUp' in monitor_data:
            monitor_info['retry'] = max(
                1, int(int(monitor_data.get('timeUntilUp', 0)) / int(monitor_info['interval'])))
        else:
            monitor_info['retry'] = 3  # Default value

        # Extract port if present
        if 'destination' in monitor_data:
            _, port = self.extract_ip_port(monitor_data['destination'])
            if port:
                monitor_info['port'] = port

        return monitor_info

    def normalize_f5_profile_value(self, value: Optional[str]) -> Optional[str]:
        """Normalize F5 profile values, treating blank and 'none' as unset."""
        if value is None:
            return None

        normalized = str(value).strip()
        if not normalized or normalized.lower() == 'none':
            return None

        return normalized

    def get_cert_key_chain_entries(self, ssl_profile: Dict) -> List[Dict]:
        """Return normalized certKeyChain entries from an SSL profile payload."""
        cert_key_chain = ssl_profile.get('certKeyChain') or []
        if isinstance(cert_key_chain, dict):
            cert_key_chain = [cert_key_chain]

        return [entry for entry in cert_key_chain if isinstance(entry, dict)]

    def get_preferred_cert_key_chain_entry(self, ssl_profile: Dict) -> Optional[Dict]:
        """Select the most relevant certKeyChain entry for this profile."""
        entries = self.get_cert_key_chain_entries(ssl_profile)
        if not entries:
            return None

        preferred_usages = {
            'client': ('SERVER', 'CLIENT', 'CA'),
            'server': ('CLIENT', 'SERVER', 'CA'),
        }
        usage_order = preferred_usages.get(
            ssl_profile.get('profile_type'),
            ('SERVER', 'CLIENT', 'CA'),
        )

        for usage in usage_order:
            for entry in entries:
                if str(entry.get('usage', '')).upper() == usage:
                    return entry

        return entries[0]

    def extract_certificate_file_paths(self, ssl_profile: Dict) -> Dict[str, str]:
        """Extract certificate, chain, and key paths from documented F5 SSL profile fields."""
        file_paths = {}
        preferred_entry = self.get_preferred_cert_key_chain_entry(ssl_profile)

        certificate_file_path = None
        chain_file_path = None
        key_file_path = None

        if preferred_entry:
            certificate_file_path = self.normalize_f5_profile_value(
                preferred_entry.get('cert') or preferred_entry.get('certFile')
            )
            chain_file_path = self.normalize_f5_profile_value(
                preferred_entry.get(
                    'chain') or preferred_entry.get('chainFile')
            )
            key_file_path = self.normalize_f5_profile_value(
                preferred_entry.get('key') or preferred_entry.get('keyFile')
            )

        if not certificate_file_path:
            certificate_file_path = self.normalize_f5_profile_value(
                ssl_profile.get('cert') or ssl_profile.get('certFile')
            )
        if not chain_file_path:
            chain_file_path = self.normalize_f5_profile_value(
                ssl_profile.get('chain') or ssl_profile.get('chainFile')
            )
        if not key_file_path:
            key_file_path = self.normalize_f5_profile_value(
                ssl_profile.get('key') or ssl_profile.get('keyFile')
            )

        if certificate_file_path:
            file_paths['certificate_file_path'] = certificate_file_path
        if chain_file_path:
            file_paths['chain_file_path'] = chain_file_path
        if key_file_path:
            file_paths['key_file_path'] = key_file_path

        return file_paths

    def extract_certificate_info(self, ssl_profile: Dict) -> Dict:
        """
        Extract certificate profile information from F5 SSL profile data.

        Args:
            ssl_profile (Dict): F5 SSL profile data

        Returns:
            Dict: Certificate profile information
        """
        cert_info = {
            'name': ssl_profile.get('name'),
            'certificate_type': ssl_profile.get('profile_type', CertificateTypeChoices.TYPE_SERVER),
        }
        if cert_info['certificate_type'] == 'client':
            cert_info['certificate_type'] = CertificateTypeChoices.TYPE_CLIENT
        elif cert_info['certificate_type'] == 'server':
            cert_info['certificate_type'] = CertificateTypeChoices.TYPE_SERVER

        cert_info.update(self.extract_certificate_file_paths(ssl_profile))

        # Extract cipher string
        if 'ciphers' in ssl_profile:
            cert_info['cipher'] = ssl_profile['ciphers']

        # Extract expiration date if available
        expiration_date = self.resolve_certificate_expiration(
            cert_info.get('certificate_file_path'))
        if expiration_date:
            cert_info['expiration_date'] = expiration_date

        return cert_info

    def parse_expiration_date(self, value) -> Optional[datetime]:
        """Parse F5 certificate expiration date formats into a timezone-aware datetime."""
        if value in (None, ""):
            return None

        if isinstance(value, datetime):
            if timezone.is_naive(value):
                return timezone.make_aware(value, dt_timezone.utc)
            return value.astimezone(dt_timezone.utc)

        if isinstance(value, (int, float)):
            # F5 may provide epoch in seconds or milliseconds.
            epoch = float(value)
            if epoch > 9999999999:
                epoch = epoch / 1000
            try:
                return datetime.fromtimestamp(epoch, tz=dt_timezone.utc)
            except Exception:
                return None

        text = str(value).strip()
        if not text:
            return None

        if text.isdigit():
            return self.parse_expiration_date(int(text))

        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if timezone.is_naive(parsed):
                return timezone.make_aware(parsed, dt_timezone.utc)
            return parsed.astimezone(dt_timezone.utc)
        except ValueError:
            pass

        for fmt in (
            "%b %d %H:%M:%S %Y %Z",
            "%a %b %d %H:%M:%S %Z %Y",
            "%Y-%m-%d",
            "%m/%d/%Y",
        ):
            try:
                parsed = datetime.strptime(text, fmt)
                if '%H' not in fmt:
                    parsed = parsed.replace(hour=0, minute=0, second=0)
                return timezone.make_aware(parsed, dt_timezone.utc)
            except ValueError:
                continue

        return None

    def get_certificate_expirations(self):
        """Get certificate expiration dates from F5 SSL cert files endpoint."""
        self.certificate_expirations = {}
        url = f"{self.base_url}/mgmt/tm/sys/file/ssl-cert"
        params = {
            "expandSubcollections": "true"
        }

        try:
            response = self.session.get(url, params=params, verify=False)
            response.raise_for_status()
            cert_data = response.json()
            cert_items = cert_data.get('items', [])

            for cert_item in cert_items:
                expiration_date = None
                for field in ('expirationDate', 'expirationString', 'expiration'):
                    expiration_date = self.parse_expiration_date(
                        cert_item.get(field))
                    if expiration_date:
                        break

                if not expiration_date:
                    continue

                aliases = [
                    cert_item.get('fullPath'),
                    cert_item.get('name'),
                    cert_item.get('apiAnonymous'),
                ]

                for alias in aliases:
                    if not alias:
                        continue

                    alias_text = str(alias)
                    self.certificate_expirations[alias_text] = expiration_date

                    basename = alias_text.rsplit('/', 1)[-1]
                    self.certificate_expirations[basename] = expiration_date

                    if basename.endswith('.crt'):
                        self.certificate_expirations[basename[:-4]
                                                     ] = expiration_date
                    else:
                        self.certificate_expirations[f"{basename}.crt"] = expiration_date

            self.logger.info(
                f"Collected expiration metadata for {len(self.certificate_expirations)} certificate aliases")

        except requests.exceptions.RequestException as e:
            self.logger.warning(
                f"Failed to retrieve SSL certificate file metadata for expiration dates: {str(e)}")

    def resolve_certificate_expiration(self, cert_file_path: Optional[str]):
        """Resolve expiration date for a profile's cert file path from cached cert metadata."""
        if not cert_file_path:
            return None

        candidates = [str(cert_file_path)]
        basename = str(cert_file_path).rsplit('/', 1)[-1]
        candidates.append(basename)

        if basename.endswith('.crt'):
            candidates.append(basename[:-4])
        else:
            candidates.append(f"{basename}.crt")

        for candidate in candidates:
            if candidate in self.certificate_expirations:
                return self.certificate_expirations[candidate]

        self.logger.debug(
            f"No expiration metadata found for certificate profile file: {cert_file_path}")
        return None

    def ssl_profile_key(self, partition: str, profile_name: str, profile_type: Optional[str] = None) -> str:
        """Build a stable key for SSL profile lookups by partition/name/type."""
        if profile_type:
            return f"/{partition}/{profile_name}:{profile_type}"
        return f"/{partition}/{profile_name}"

    def register_ssl_profile_keys(self, profiles_map: Dict[str, CertificateProfile], ssl_profile: Dict, profile_obj: CertificateProfile):
        """Register multiple lookup keys for a certificate profile."""
        partition = ssl_profile.get('partition', 'Common')
        profile_name = ssl_profile.get('name')
        profile_type = ssl_profile.get('profile_type')
        full_path = ssl_profile.get('fullPath')

        if not profile_name:
            return

        keys = [
            self.ssl_profile_key(partition, profile_name, profile_type),
            self.ssl_profile_key(partition, profile_name, None),
            full_path,
            f"/{partition}/{profile_name}",
        ]

        for key in keys:
            if key:
                profiles_map[key] = profile_obj

    def link_relationship(self, relationship, source, destination):
        association, created = RelationshipAssociation.objects.update_or_create(
            relationship=relationship,
            source_type=relationship.source_type,
            destination_type=relationship.destination_type,
            source_id=source.id,
            destination_id=destination.id
        )
        if created:
            self.logger.info(
                f"Created relationship: from {source} to {destination}")

    def is_linked(self, relationship, source, destination):
        return RelationshipAssociation.objects.filter(
            relationship=relationship,
            source_id=source.id,
            destination_id=destination.id
        ).exists()

    def get_linked_destination_ids(self, relationship, source=None):
        """Return destination IDs linked through a relationship, optionally scoped to one source."""
        filters = {"relationship": relationship}
        if source is not None:
            filters["source_id"] = source.id

        return set(
            RelationshipAssociation.objects.filter(**filters).values_list(
                'destination_id', flat=True
            )
        )

    def unlink_stale_relationships_for_model(self, relationship_key: str, discovered_ids: set, object_label: str) -> set:
        """Remove this F5 device's stale relationships for objects that were not rediscovered."""
        if not self.purge_orphans:
            return set()

        relationship = self.relationships.get(relationship_key)
        if not relationship:
            self.logger.debug(
                f"No relationship configured for {relationship_key}; skipping stale relationship cleanup")
            return set()

        linked_ids = self.get_linked_destination_ids(
            relationship, source=self.f5_device)
        if not linked_ids:
            return set()

        stale_ids = linked_ids - set(discovered_ids)
        if not stale_ids:
            return set()

        deleted_count, _ = RelationshipAssociation.objects.filter(
            relationship=relationship,
            source_id=self.f5_device.id,
            destination_id__in=stale_ids,
        ).delete()
        self.logger.info(
            f"Removed {deleted_count} stale {object_label} relationship(s) from F5 device {self.f5_device.name}")
        return stale_ids

    def purge_orphans_for_model(self, model, relationship_key: str, candidate_ids: set, object_label: str):
        """Purge objects only after they have lost all F5 provenance relationships."""
        if not self.purge_orphans:
            return

        relationship = self.relationships.get(relationship_key)
        if not relationship:
            self.logger.debug(
                f"No relationship configured for {relationship_key}; skipping orphan purge")
            return

        if not candidate_ids:
            return

        remaining_linked_ids = self.get_linked_destination_ids(relationship)
        orphan_ids = set(candidate_ids) - remaining_linked_ids
        if not orphan_ids:
            return

        orphans = model.objects.filter(id__in=orphan_ids)
        if not orphans.exists():
            return

        purge_count = 0
        skipped_count = 0
        for orphan in orphans:
            try:
                self.logger.info(
                    f"Purging orphaned {object_label}: {orphan}")
                orphan.delete()
                purge_count += 1
            except ProtectedError as exc:
                self.logger.warning(
                    f"Skipping orphaned {object_label} {orphan}; protected dependency still exists: {exc}")
                skipped_count += 1
            except Exception as exc:
                self.logger.warning(
                    f"Skipping orphaned {object_label} {orphan}; delete failed: {exc}")
                skipped_count += 1

        self.logger.info(
            f"Purged {purge_count} orphaned {object_label}(s) for F5 device {self.f5_device.name}; skipped {skipped_count}")

    def sync_health_monitors(self, monitors_data: List[Dict]) -> Dict[str, HealthCheckMonitor]:
        """
        Synchronize health monitors from F5 to Nautobot.

        Args:
            monitors_data (List[Dict]): F5 health monitor data


        Returns:
            Dict[str, HealthCheckMonitor]: Dictionary mapping monitor names to Nautobot objects
        """

        monitors_map = {}

        for monitor_data in monitors_data:
            monitor_name = monitor_data.get('name')
            partition = monitor_data.get('partition')
            if not monitor_name:
                self.logger.warning("Skipping monitor with no name")
                continue

            # Extract monitor info
            monitor_info = self.extract_monitor_info(monitor_data)

            # Look for existing monitor
            existing_monitor = HealthCheckMonitor.objects.filter(
                name=monitor_name
            ).first()

            if existing_monitor:
                # Check for changes
                changed = False
                for key, value in monitor_info.items():
                    if hasattr(existing_monitor, key) and getattr(existing_monitor, key) != value:
                        setattr(existing_monitor, key, value)
                        changed = True

                if changed:
                    existing_monitor.save()
                    self.logger.info(f"Updated health monitor: {monitor_name}")

                # Set custom field and relationship
                self.set_partition(existing_monitor, partition)
                # Add relationship to F5 device
                if "HealthCheckMonitor" in self.relationships:
                    self.link_relationship(
                        relationship=self.relationships["HealthCheckMonitor"],
                        source=self.f5_device,
                        destination=existing_monitor
                    )

                monitors_map[monitor_name] = existing_monitor
            else:
                # Create new monitor
                try:
                    new_monitor = HealthCheckMonitor.objects.create(
                        **monitor_info
                    )

                    # Set custom field and relationship
                    self.set_partition(new_monitor, partition)
                    # Add relationship to F5 device
                    if "HealthCheckMonitor" in self.relationships:
                        self.link_relationship(
                            relationship=self.relationships["HealthCheckMonitor"],
                            source=self.f5_device,
                            destination=new_monitor
                        )
                    self.logger.info(f"Created health monitor: {monitor_name}")
                    monitors_map[monitor_name] = new_monitor
                except Exception as e:
                    self.logger.error(
                        f"Failed to create health monitor {monitor_name}: {str(e)}")

        return monitors_map

    def sync_certificate_profiles(self, ssl_profiles: List[Dict]) -> Dict[str, CertificateProfile]:
        """
        Synchronize certificate profiles from F5 to Nautobot.

        Args:
            ssl_profiles (List[Dict]): F5 SSL profile data


        Returns:
            Dict[str, CertificateProfile]: Dictionary mapping profile names to Nautobot objects
        """

        profiles_map = {}

        for ssl_profile in ssl_profiles:
            profile_name = ssl_profile.get('name')
            partition = ssl_profile.get('partition', 'Common')
            if not profile_name:
                self.logger.warning(
                    "Skipping certificate profile with no name")
                continue

            # Extract certificate info
            cert_info = self.extract_certificate_info(ssl_profile)

            # Look for existing profile
            existing_profile = CertificateProfile.objects.filter(
                name=profile_name
            ).first()

            if existing_profile:
                # Check for changes
                changed = False
                for key, value in cert_info.items():
                    if hasattr(existing_profile, key) and getattr(existing_profile, key) != value:
                        setattr(existing_profile, key, value)
                        changed = True

                if changed:
                    existing_profile.save()
                    self.logger.info(
                        f"Updated certificate profile: {profile_name}")

                # Set custom field and relationship
                self.set_partition(existing_profile, partition)
                # Add relationship to F5 device
                if "CertificateProfile" in self.relationships:
                    self.link_relationship(
                        relationship=self.relationships["CertificateProfile"],
                        source=self.f5_device,
                        destination=existing_profile
                    )

                self.register_ssl_profile_keys(
                    profiles_map, ssl_profile, existing_profile)
            else:
                # Create new profile
                try:
                    new_profile = CertificateProfile.objects.create(
                        **cert_info
                    )

                    # Set custom field and relationship
                    self.set_partition(new_profile, partition)
                    # Add relationship to F5 device
                    if "CertificateProfile" in self.relationships:
                        self.link_relationship(
                            relationship=self.relationships["CertificateProfile"],
                            source=self.f5_device,
                            destination=new_profile
                        )
                    self.logger.info(
                        f"Created certificate profile: {profile_name}")
                    self.register_ssl_profile_keys(
                        profiles_map, ssl_profile, new_profile)
                except Exception as e:
                    self.logger.error(
                        f"Failed to create certificate profile {profile_name}: {str(e)}")

        return profiles_map

    def sync_pools_and_members(self, pools_data: List[Dict],
                               monitors_map: Dict[str, HealthCheckMonitor]) -> Tuple[Dict[str, LoadBalancerPool], set, set]:
        """
        Synchronize pools and pool members from F5 to Nautobot.

        Args:
            pools_data (List[Dict]): F5 pool data
            monitors_map (Dict[str, HealthCheckMonitor]): Dictionary mapping monitor names to objects

        Returns:
            Dict[str, LoadBalancerPool]: Dictionary mapping pool names to Nautobot objects
        """

        pools_map = {}
        processed_pools = set()
        processed_members = set()

        for pool_data in pools_data:
            pool_name = pool_data.get('name')
            partition = pool_data.get('partition', 'Common')
            if not pool_name:
                self.logger.warning("Skipping pool with no name")
                continue

            # Extract load balancing algorithm
            lb_method = pool_data.get('loadBalancingMode', 'round-robin')
            lb_algorithm = self.map_lb_algorithm(lb_method)

            # Extract monitor reference
            monitor_name = None
            monitor_obj = None
            if 'monitor' in pool_data and pool_data['monitor'] != 'none':
                monitor_refs = pool_data['monitor'].split(' and ')
                # Use the first monitor for now
                if monitor_refs:
                    monitor_full_path = monitor_refs[0]
                    if '/' in monitor_full_path:
                        _, monitor_name = monitor_full_path.rsplit('/', 1)
                    else:
                        monitor_name = monitor_full_path

                    if monitor_name in monitors_map:
                        monitor_obj = monitors_map[monitor_name]

            # Look for existing pool
            existing_pool = LoadBalancerPool.objects.filter(
                name=pool_name
            ).first()

            if existing_pool:
                # Check for changes
                changed = False
                if existing_pool.load_balancing_algorithm != lb_algorithm:
                    existing_pool.load_balancing_algorithm = lb_algorithm
                    changed = True

                if existing_pool.health_check_monitor != monitor_obj:
                    existing_pool.health_check_monitor = monitor_obj
                    changed = True

                if changed:
                    existing_pool.save()
                    self.logger.info(f"Updated pool: {pool_name}")

                # Set custom field and relationship
                self.set_partition(existing_pool, partition)
                # Add relationship to F5 device
                if "LoadBalancerPool" in self.relationships:
                    self.link_relationship(
                        relationship=self.relationships["LoadBalancerPool"],
                        source=self.f5_device,
                        destination=existing_pool
                    )

                pools_map[pool_name] = existing_pool
                processed_pools.add(existing_pool.id)
            else:
                # Create new pool
                try:
                    new_pool = LoadBalancerPool(
                        name=pool_name,
                        load_balancing_algorithm=lb_algorithm,
                        health_check_monitor=monitor_obj

                    )
                    new_pool.save()

                    # Set custom field and relationship
                    self.set_partition(new_pool, partition)
                    # Add relationship to F5 device
                    if "LoadBalancerPool" in self.relationships:
                        self.link_relationship(
                            relationship=self.relationships["LoadBalancerPool"],
                            source=self.f5_device,
                            destination=new_pool
                        )

                    self.logger.info(f"Created pool: {pool_name}")
                    pools_map[pool_name] = new_pool
                    processed_pools.add(new_pool.id)
                except Exception as e:
                    self.logger.error(
                        f"Failed to create pool {pool_name}: {str(e)}")
                    continue

            # Now process pool members
            processed_members.update(
                self.sync_pool_members(
                    pool_data, pools_map[pool_name], monitors_map)
            )

        return pools_map, processed_pools, processed_members

    def sync_pool_members(self, pool_data: Dict, pool_obj: LoadBalancerPool,
                          monitors_map: Dict[str, HealthCheckMonitor]):
        """
        Synchronize pool members for a specific pool.

        Args:
            pool_data (Dict): F5 pool data
            pool_obj (LoadBalancerPool): Nautobot pool object
            monitors_map (Dict[str, HealthCheckMonitor]): Dictionary mapping monitor names to objects
        """
        # Skip if no members data available
        if 'membersReference' not in pool_data or 'items' not in pool_data['membersReference']:
            self.logger.debug(f"No members found for pool: {pool_obj.name}")
            return set()

        members_data = pool_data['membersReference']['items']
        self.logger.info(
            f"Synchronizing {len(members_data)} members for pool: {pool_obj.name}")

        # Track processed members to handle deletions
        processed_members = set()

        for member_data in members_data:
            # Extract member address and port
            member_name = member_data.get('name', '')
            partition = member_data.get('partition', 'Common')
            if not member_name or ':' not in member_name:
                self.logger.warning(
                    f"Invalid member name format: {member_name}")
                continue

            # Format is typically "ip:port"
            ip_str, port_str = member_name.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                self.logger.warning(
                    f"Invalid port in member name: {member_name}")
                continue

            # Get IP from member_name node entity
            ip_str = self.nodes.get(ip_str, {}).get('address', None)
            ip_address = None
            # Get IP address object from IPAM
            if not ip_str or 'any' in ip_str:
                self.logger.warning(
                    f"Missing or invalid IP for member: {member_name}")
                continue

            if ip_str:
                try:
                    ip_cidr = self.find_best_cidr(ip_str)
                    ip_subnet = ipaddress.ip_network(
                        f"{ip_str}/{ip_cidr}", strict=False)
                    prefix = Prefix.objects.get(
                        prefix=ip_subnet.with_prefixlen, namespace__name="Global")
                    ip_address = IPAddress.objects.get(
                        host=ip_str, parent=prefix)
                except IPAddress.DoesNotExist:
                    self.logger.warning(
                        f"IP address {ip_str} not found in IPAM, creating it")
                    try:
                        ip_address = IPAddress.objects.create(
                            address=f"{ip_str}/{ip_cidr}", parent=prefix, status=self.status_active)

                    except Exception as e:
                        self.logger.error(
                            f"Failed to create IP address {ip_str}/{ip_cidr}: {str(e)}")
                        continue
                except Prefix.DoesNotExist:
                    self.logger.warning(
                        f"Prefix for IP address {ip_str} not found in IPAM, skipping member {member_name}")
                    continue

            # Get status based on member state
            status = Status.objects.get(name='Active')
            if 'session' in member_data:
                session_state = member_data['session']
                if session_state == "user-disabled" or session_state == "user-down":
                    status = Status.objects.get(name='Maintenance')
                elif session_state == "monitor-down":
                    status = Status.objects.get(name='Failed')

            # Extract member-specific monitor if any
            member_monitor = None
            if 'monitor' in member_data and member_data['monitor'] != 'default':
                monitor_full_path = member_data['monitor']
                if '/' in monitor_full_path:
                    _, monitor_name = monitor_full_path.rsplit('/', 1)
                else:
                    monitor_name = monitor_full_path

                if monitor_name in monitors_map:
                    member_monitor = monitors_map[monitor_name]

            # Look for existing member
            existing_member = LoadBalancerPoolMember.objects.filter(
                ip_address=ip_address,
                port=port,
                load_balancer_pool=pool_obj
            ).first()

            if existing_member:
                # Check for changes
                changed = False

                if existing_member.status != status:
                    existing_member.status = status
                    changed = True

                if existing_member.health_check_monitor != member_monitor:
                    existing_member.health_check_monitor = member_monitor
                    changed = True

                if not existing_member.label and member_name:
                    existing_member.label = member_name
                    changed = True

                if changed:
                    existing_member.save()
                    self.logger.info(f"Updated pool member: {member_name}")

                # Set custom field and relationship
                self.set_partition(existing_member, partition)

                # Add relationship to F5 device
                if "LoadBalancerPoolMember" in self.relationships and not self.is_linked(self.relationships["LoadBalancerPoolMember"], self.f5_device, existing_member):
                    self.link_relationship(
                        relationship=self.relationships["LoadBalancerPoolMember"],
                        source=self.f5_device,
                        destination=existing_member
                    )

                processed_members.add(existing_member.id)
            else:
                # Create new member
                try:
                    new_member = LoadBalancerPoolMember(
                        ip_address=ip_address,
                        port=port,
                        load_balancer_pool=pool_obj,
                        status=status,
                        label=member_name,
                        health_check_monitor=member_monitor
                    )
                    new_member.save()

                    # Set custom field and relationship
                    self.set_partition(new_member, partition)
                    # Add relationship to F5 device
                    if "LoadBalancerPoolMember" in self.relationships:
                        self.link_relationship(
                            relationship=self.relationships["LoadBalancerPoolMember"],
                            source=self.f5_device,
                            destination=new_member
                        )

                    self.logger.info(f"Created pool member: {member_name}")
                    processed_members.add(new_member.id)
                except Exception as e:
                    self.logger.error(
                        f"Failed to create pool member {member_name}: {str(e)}")

        return processed_members

    def set_partition(self, object, value):
        """Set Partition value."""
        if object.custom_field_data is None:
            object.cf = {}
        if object.custom_field_data.get(self.cf_partition.key, None) != value:
            object.custom_field_data[self.cf_partition.key] = value
            object.validated_save()

    def find_best_cidr(self, address: str) -> int:

        for cidr in range(32, 1, -1):
            ipnetwork = ipaddress.ip_interface(
                f"{address}/{cidr}")
            prefix = Prefix.objects.filter(
                prefix=str(ipnetwork.network))

            if prefix:
                return prefix[0].prefix_length
        return 32

    def sync_virtual_servers(self, vs_data: List[Dict],
                             pools_map: Dict[str, LoadBalancerPool],
                             cert_profiles_map: Dict[str, CertificateProfile],
                             monitors_map: Dict[str, HealthCheckMonitor]):
        """
        Synchronize virtual servers from F5 to Nautobot.

        Args:
            vs_data (List[Dict]): F5 virtual server data
            pools_map (Dict[str, LoadBalancerPool]): Dictionary mapping pool names to objects
            cert_profiles_map (Dict[str, CertificateProfile]): Dictionary mapping certificate profile names to objects
            monitors_map (Dict[str, HealthCheckMonitor]): Dictionary mapping monitor names to objects
        """

        # Track processed virtual servers to handle deletions
        processed_vs = set()

        for vs in vs_data:
            vs_name = vs.get('name')
            partition = vs.get('partition', 'Common')
            if not vs_name:
                self.logger.warning("Skipping virtual server with no name")
                continue

            ip_address = None

            # Extract IP and port
            ip_str, port = self.extract_ip_port(vs.get('destination', ''))
            if ip_str == "any":
                self.logger.warning(
                    f"Skipping virtual server {vs_name} with 'any' as destination IP")
                continue
            if not ip_str:
                self.logger.warning(
                    f"Could not extract IP from destination for VS: {vs_name}")
                continue
            # Check if ip is hostname or ip
            try:
                ipaddress.ip_address(ip_str)
                is_ip = True
            except ValueError:
                is_ip = False

            try:
                for address in self.virtual_addresses:
                    if address['partition'] == partition and address['name'] == ip_str:
                        ip_str = address['address']
                        ip_mask = address['mask']
                        is_ip = True
                        break
            except socket.error:
                self.logger.warning(
                    f"Could not resolve virtual-address {ip_str} to IP")
                continue
            # Get or create IP address
            if not is_ip:
                self.logger.warning(
                    f"Virtual server {vs_name} destination did not resolve to an IP: {ip_str}")
                continue
            if is_ip:
                try:
                    ip_address = IPAddress.objects.get(host=ip_str)
                except IPAddress.DoesNotExist:
                    self.logger.warning(
                        f"IP address {ip_str} not found in IPAM, creating it")
                    try:
                        ip_cidr = self.find_best_cidr(ip_str)
                        if ip_cidr == 32:
                            ip_cidr = ipaddress.IPv4Network(
                                f'0.0.0.0/{ip_mask}', strict=False).prefixlen
                        subnet = ipaddress.ip_network(
                            f"{ip_str}/{ip_cidr}", strict=False)

                        prefix, created = Prefix.objects.get_or_create(
                            prefix=subnet.with_prefixlen, namespace=self.global_namespace, status=self.status_active)
                        if created:
                            self.logger.info(f"Created new prefix: {prefix}")

                        ip_address = IPAddress.objects.create(
                            address=f"{ip_str}/{ip_cidr}", status=self.status_active, parent=prefix)
                    except Exception as e:
                        self.logger.error(
                            f"Failed to create IP address {ip_str}: {str(e)}")
                        continue

            # Extract pool if present
            pool_obj = None
            if 'pool' in vs:
                pool_name = self.extract_pool_name(vs['pool'])
                if pool_name and pool_name in pools_map:
                    pool_obj = pools_map[pool_name]

            # Determine protocol
            protocol = self.determine_protocol(vs)

            # Determine load balancer type
            lb_type = self.determine_lb_type(vs)

            # Check if SSL is enabled
            ssl_enabled = self.check_ssl_enabled(vs)

            # Get status
            enabled = vs.get('enabled', True)

            # Get certificate profiles if SSL enabled
            cert_profiles = []
            if ssl_enabled:
                cert_profiles = self.get_vs_certificate_profiles(
                    vs, cert_profiles_map)

            # Extract monitor if any
            monitor_obj = None
            if 'monitor' in vs:
                monitor_ref = vs['monitor']
                if '/' in monitor_ref:
                    _, monitor_name = monitor_ref.rsplit('/', 1)
                else:
                    monitor_name = monitor_ref

                if monitor_name in monitors_map:
                    monitor_obj = monitors_map[monitor_name]

            # Extract source NAT configuration
            source_nat_type, source_nat_pool = self.extract_source_nat(vs)

            # Look for existing virtual server
            existing_vs = VirtualServer.objects.filter(
                name=vs_name,
                vip=ip_address
            ).first()

            if existing_vs:
                # Check for changes
                changed = False

                # Update fields that may have changed
                if port is not None and existing_vs.port != port:
                    existing_vs.port = port
                    changed = True

                if existing_vs.protocol != protocol:
                    existing_vs.protocol = protocol
                    changed = True

                if existing_vs.load_balancer_type != lb_type:
                    existing_vs.load_balancer_type = lb_type
                    changed = True

                if existing_vs.enabled != enabled:
                    existing_vs.enabled = enabled
                    changed = True

                if existing_vs.ssl_offload != ssl_enabled:
                    existing_vs.ssl_offload = ssl_enabled
                    changed = True

                if existing_vs.load_balancer_pool != pool_obj:
                    existing_vs.load_balancer_pool = pool_obj
                    changed = True

                if existing_vs.health_check_monitor != monitor_obj:
                    existing_vs.health_check_monitor = monitor_obj
                    changed = True

                if source_nat_type and existing_vs.source_nat_type != source_nat_type:
                    existing_vs.source_nat_type = source_nat_type
                    changed = True

                    if source_nat_pool and existing_vs.source_nat_pool != source_nat_pool:
                        existing_vs.source_nat_pool = source_nat_pool
                        changed = True

                if changed:
                    existing_vs.save()
                    self.logger.info(f"Updated virtual server: {vs_name}")

                # Set custom field and relationship
                self.set_partition(existing_vs, partition)
                # Add relationship to F5 device
                if "VirtualServer" in self.relationships:
                    self.link_relationship(
                        relationship=self.relationships["VirtualServer"],
                        source=self.f5_device,
                        destination=existing_vs
                    )

                # Reconcile certificate profiles (client and server)
                existing_vs.certificate_profiles.set(cert_profiles)

                processed_vs.add(existing_vs.id)
            else:
                # Create new virtual server
                try:
                    if source_nat_type:
                        new_vs = VirtualServer.objects.create(
                            name=vs_name,
                            vip=ip_address,
                            port=port,
                            protocol=protocol,
                            load_balancer_type=lb_type,
                            enabled=enabled,
                            ssl_offload=ssl_enabled,
                            load_balancer_pool=pool_obj,
                            health_check_monitor=monitor_obj,
                            source_nat_type=source_nat_type,
                            source_nat_pool=source_nat_pool,
                            device=None  # Using virtual_machine instead
                        )
                    else:
                        new_vs = VirtualServer.objects.create(
                            name=vs_name,
                            vip=ip_address,
                            port=port,
                            protocol=protocol,
                            load_balancer_type=lb_type,
                            enabled=enabled,
                            ssl_offload=ssl_enabled,
                            load_balancer_pool=pool_obj,
                            health_check_monitor=monitor_obj,
                            device=None  # Using virtual_machine instead
                        )

                    # Set custom field and relationship
                    self.set_partition(new_vs, partition)
                    # Add relationship to F5 device
                    if "VirtualServer" in self.relationships:
                        self.link_relationship(
                            relationship=self.relationships["VirtualServer"],
                            source=self.f5_device,
                            destination=new_vs
                        )

                    # Add certificate profiles if SSL enabled
                    if ssl_enabled and cert_profiles:
                        new_vs.certificate_profiles.set(cert_profiles)

                    self.logger.info(f"Created virtual server: {vs_name}")
                    processed_vs.add(new_vs.id)
                except Exception as e:
                    self.logger.error(
                        f"Failed to create virtual server {vs_name}: {str(e)}")

        return processed_vs

    def map_lb_algorithm(self, f5_method: str) -> str:
        """
        Map F5 load balancing method to Nautobot choices.

        Args:
            f5_method (str): F5 load balancing method

        Returns:
            str: Nautobot load balancing algorithm
        """
        # Map F5 load balancing methods to Nautobot choices
        mapping = {
            'round-robin': LoadBalancingAlgorithmChoices.ROUND_ROBIN,
            'ratio-member': LoadBalancingAlgorithmChoices.CUSTOM_LOAD,
            'least-connections-member': LoadBalancingAlgorithmChoices.LEAST_CONNECTIONS,
            'fastest-app-response': LoadBalancingAlgorithmChoices.LEAST_RESPONSE_TIME,
            'least-sessions': LoadBalancingAlgorithmChoices.LEAST_PACKETS,
            'dynamic-ratio-member': LoadBalancingAlgorithmChoices.CUSTOM_LOAD,
            'observed-member': LoadBalancingAlgorithmChoices.LEAST_CONNECTIONS,
            'predictive-member': LoadBalancingAlgorithmChoices.LEAST_REQUEST,
            'ratio-node': LoadBalancingAlgorithmChoices.LEAST_CONNECTIONS,
            'ratio-session': LoadBalancingAlgorithmChoices.LEAST_PACKETS,
            'weighted-least-connections-member': LoadBalancingAlgorithmChoices.LEAST_CONNECTIONS
        }

        return mapping.get(f5_method.lower(), LoadBalancingAlgorithmChoices.ROUND_ROBIN)

    def determine_protocol(self, vs_data: Dict) -> ProtocolChoices:
        """
        Determine protocol for a virtual server.

        Args:
            vs_data (Dict): F5 virtual server data

        Returns:
            str: Protocol (TCP, UDP, HTTP, etc.)
        """
        # Check if protocol is explicitly set
        ip_protocol = vs_data.get('ipProtocol', '').upper()
        if ip_protocol == 'TCP':
            return ProtocolChoices.PROTOCOL_TCP
        elif ip_protocol == 'UDP':
            return ProtocolChoices.PROTOCOL_UDP

        # Check profiles for HTTP/HTTPS
        if 'profilesReference' in vs_data and 'items' in vs_data['profilesReference']:
            for profile in vs_data['profilesReference']['items']:
                if profile.get('name') == 'http' or 'http' in profile.get('name', ''):
                    return ProtocolChoices.PROTOCOL_HTTP2
                elif profile.get('name') == 'https' or 'https' in profile.get('name', ''):
                    return ProtocolChoices.PROTOCOL_HTTPS

        # Default to TCP if nothing else matches
        return ProtocolChoices.PROTOCOL_TCP

    def determine_lb_type(self, vs_data: Dict) -> LoadBalancerTypeChoices:
        """
        Determine load balancer type for a virtual server.

        Args:
            vs_data (Dict): F5 virtual server data

        Returns:
            str: Load balancer type (L4, L7, etc.)
        """
        # Check if this is a DNS virtual server
        if 'profilesReference' in vs_data and 'items' in vs_data['profilesReference']:
            for profile in vs_data['profilesReference']['items']:
                if profile.get('name') == 'dns' or 'dns' in profile.get('name', ''):
                    return LoadBalancerTypeChoices.TYPE_DNS

        # Check if this is an L7 (HTTP/HTTPS) virtual server
        protocol = self.determine_protocol(vs_data)
        if protocol in ('HTTP', 'HTTPS'):
            return LoadBalancerTypeChoices.TYPE_LAYER7

        # Default to L4 for TCP/UDP
        return LoadBalancerTypeChoices.TYPE_LAYER4

    def check_ssl_enabled(self, vs_data: Dict) -> bool:
        """
        Check if SSL offload is enabled for a virtual server.

        Args:
            vs_data (Dict): F5 virtual server data

        Returns:
            bool: True if SSL offload is enabled
        """
        # Check for SSL profiles
        if 'profilesReference' in vs_data and 'items' in vs_data['profilesReference']:
            for profile in vs_data['profilesReference']['items']:
                if ('ssl' in profile.get('name', '').lower() or
                    'clientssl' in profile.get('name', '').lower() or
                        'serverssl' in profile.get('name', '').lower()):
                    return True

        # Check protocol
        protocol = self.determine_protocol(vs_data)
        if protocol == 'HTTPS':
            return True

        return False

    def get_vs_certificate_profiles(self, vs_data: Dict, cert_profiles_map: Dict[str, CertificateProfile]) -> List[CertificateProfile]:
        """
        Get certificate profiles for a virtual server.

        Args:
            vs_data (Dict): F5 virtual server data
            cert_profiles_map (Dict[str, CertificateProfile]): Dictionary mapping profile names to objects

        Returns:
            List[CertificateProfile]: List of certificate profile objects
        """
        profiles = []
        profile_partition = vs_data.get('partition', 'Common')

        # Check for SSL profiles
        if 'profilesReference' in vs_data and 'items' in vs_data['profilesReference']:
            for profile_ref in vs_data['profilesReference']['items']:
                profile_name = profile_ref.get('name')
                profile_full_path = profile_ref.get('fullPath')
                profile_context = (
                    profile_ref.get('context')
                    or profile_ref.get('profileContext')
                    or ""
                ).lower()

                is_ssl_profile = (
                    'ssl' in (profile_name or '').lower()
                    or 'ssl' in (profile_full_path or '').lower()
                    or 'client' in profile_context
                    or 'server' in profile_context
                )
                if not is_ssl_profile or not profile_name:
                    continue

                profile_type = None
                if 'client' in profile_context:
                    profile_type = 'client'
                elif 'server' in profile_context:
                    profile_type = 'server'

                partition = profile_ref.get('partition', profile_partition)
                candidate_keys = [
                    profile_full_path,
                    self.ssl_profile_key(
                        partition, profile_name, profile_type),
                    self.ssl_profile_key(partition, profile_name),
                    f"/{partition}/{profile_name}",
                ]

                profile_obj = None
                for key in candidate_keys:
                    if key and key in cert_profiles_map:
                        profile_obj = cert_profiles_map[key]
                        break

                if profile_obj and profile_obj not in profiles:
                    profiles.append(profile_obj)

        return profiles

    def extract_source_nat(self, vs_data: Dict) -> Tuple[str, Optional[Prefix]]:
        """
        Extract source NAT configuration from virtual server.

        Args:
            vs_data (Dict): F5 virtual server data

        Returns:
            Tuple[str, Optional[Prefix]]: NAT type and NAT pool prefix
        """
        # Default values
        nat_type = None
        nat_pool = None
        # Check for source address translation settings
        if 'sourceAddressTranslation' in vs_data:
            sat_data = vs_data['sourceAddressTranslation']
            sat_type = sat_data.get('type', '')

            if sat_type == 'automap':
                nat_type = SourceNATTypeChoices.TYPE_AUTO
            elif sat_type == 'snat':
                nat_type = SourceNATTypeChoices.TYPE_POOL

                # Get SNAT pool
                if 'pool' in sat_data:
                    pool_path = sat_data['pool']
                    if '/' in pool_path:
                        _, pool_name = pool_path.rsplit('/', 1)
                    else:
                        pool_name = pool_path

                    # Try to find a matching prefix in IPAM
                    # This is a best-effort approach as we don't have direct mapping between
                    # F5 SNAT pools and Nautobot prefixes
                    try:
                        nat_pool = Prefix.objects.filter(
                            description__icontains=pool_name).first()
                    except Exception:
                        pass
        return nat_type, nat_pool

    def check_connectivity(self):
        """
        Check connectivity to the F5 device.
        """
        try:
            response = self.session.get(f"{self.base_url}/mgmt/tm")
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            self.log_failure(f"Connectivity check failed: {e}")
            return False

    def run(self, *args, **kwargs):
        """
        Execute the F5 LTM discovery job.
        """
        self.global_namespace = Namespace.objects.get(name="Global")
        self.status_active = Status.objects.get(name="Active")

        # Initialize variables
        self.secrets_group = kwargs['secrets_group']
        self.purge_orphans = kwargs.get('purge_orphans', False)

        if not kwargs['f5_device']:
            for device in VirtualMachine.objects.filter(platform__name='bigip_f5', primary_ip4__isnull=False):
                self.process_f5_device(device)

        else:
            self.process_f5_device(kwargs['f5_device'])

    def process_f5_device(self, f5_device: VirtualMachine):
        """
        Process the discovered F5 device.
        """
        self.logger.info(f"Processing F5 device: {f5_device.name}")
        self.f5_device = f5_device
        if not self.f5_device:
            return self.log_failure("No F5 device found")

        # Process the F5 device (e.g., create/update Nautobot objects)
        if not self.f5_device.primary_ip4:
            return self.log_failure("F5 device has no primary IP address configured")

        self.f5_host = str(self.f5_device.primary_ip4.host)
        self.base_url = f"https://{self.f5_host}"

        # Initialize HTTP session
        self.session = requests.Session()
        self.session.verify = False

        # Authenticate to F5
        if not self.authenticate():
            return self.log_failure("Failed to authenticate to F5 LTM")

        if not self.check_connectivity():
            self.logger.error(
                f"Failed to connect to {self.f5_device.name} LTM")
            return

        # Ensure custom fields and relationships exist
        self.ensure_custom_fields()
        self.ensure_custom_relationships()

        # Get partitions
        self.partitions = self.get_partitions()
        if not self.partitions:
            return self.log_failure("No partitions found on F5 LTM")

        # Get monitors
        monitors_data = self.get_monitors()
        monitors_map = self.sync_health_monitors(monitors_data)

        # Get certificate profiles
        cert_profiles_data = self.get_certificate_profiles()
        self.get_certificate_expirations()
        cert_profiles_map = self.sync_certificate_profiles(
            cert_profiles_data)

        # Get pools and members
        self.get_nodes()
        pools_data = self.get_pools()
        pools_map, processed_pool_ids, processed_member_ids = self.sync_pools_and_members(
            pools_data, monitors_map)

        # Get virtual servers
        self.get_virtual_addresses()
        vs_data = self.get_virtual_servers()
        processed_vs_ids = self.sync_virtual_servers(
            vs_data, pools_map, cert_profiles_map, monitors_map)

        processed_monitor_ids = {
            monitor.id for monitor in monitors_map.values()}
        processed_cert_profile_ids = {
            profile.id for profile in cert_profiles_map.values()}

        # Remove stale relationships for this F5 before purging global orphans.
        stale_vs_ids = self.unlink_stale_relationships_for_model(
            "VirtualServer",
            processed_vs_ids,
            "virtual server",
        )
        stale_member_ids = self.unlink_stale_relationships_for_model(
            "LoadBalancerPoolMember",
            processed_member_ids,
            "pool member",
        )
        stale_pool_ids = self.unlink_stale_relationships_for_model(
            "LoadBalancerPool",
            processed_pool_ids,
            "pool",
        )
        stale_monitor_ids = self.unlink_stale_relationships_for_model(
            "HealthCheckMonitor",
            processed_monitor_ids,
            "health monitor",
        )
        stale_cert_profile_ids = self.unlink_stale_relationships_for_model(
            "CertificateProfile",
            processed_cert_profile_ids,
            "certificate profile",
        )

        # Optional orphan purge deletes only objects with no remaining F5 relationships.
        self.purge_orphans_for_model(
            VirtualServer,
            "VirtualServer",
            stale_vs_ids,
            "virtual server",
        )
        self.purge_orphans_for_model(
            LoadBalancerPoolMember,
            "LoadBalancerPoolMember",
            stale_member_ids,
            "pool member",
        )
        self.purge_orphans_for_model(
            LoadBalancerPool,
            "LoadBalancerPool",
            stale_pool_ids,
            "pool",
        )
        self.purge_orphans_for_model(
            HealthCheckMonitor,
            "HealthCheckMonitor",
            stale_monitor_ids,
            "health monitor",
        )
        self.purge_orphans_for_model(
            CertificateProfile,
            "CertificateProfile",
            stale_cert_profile_ids,
            "certificate profile",
        )

        # Close session
        self.session.close()

        self.log_success(
            f"Successfully discovered {self.f5_device.name} LTM configuration")

    def log_failure(self, message: str) -> Dict:
        """
        Log a failure message and return a MessageDict for job result.

        Args:
            message (str): Failure message

        Returns:
            Dict: Job result dictionary
        """
        self.logger.error(message)
        return {"status": "failed", "message": message}

    def log_success(self, message: str) -> Dict:
        """
        Log a success message and return a MessageDict for job result.

        Args:
            message (str): Success message

        Returns:
            Dict: Job result dictionary
        """
        self.logger.info(message)
        return {"status": "success", "message": message}


# Register the job

register_jobs(DiscoverF5LTM)
