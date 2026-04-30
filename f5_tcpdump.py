import ipaddress
import logging
import os
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse

from filters.f5_capture_filters import resolve_virtual_machine_vip_ips
from nautobot.extras.choices import (
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)
from nautobot.extras.models import ExternalIntegration
from scripts.lib.f5_capture_client import F5CaptureClient, build_capture_file_name
from scripts.lib.scp_client import SCPDropboxClient, parse_scp_destination


logger = logging.getLogger(__name__)

F5_SECRET_RELATIONSHIP_SLUG = "virtual_machine_secret_group"
SCP_DROPBOX_INTEGRATION_NAME = "SCP Dropbox"


def _get_model(app_label, model_name):
    try:
        from django.apps import apps
    except ImportError:
        return None

    try:
        return apps.get_model(app_label, model_name)
    except Exception:
        return None


def _candidate_identity_key(candidate):
    if candidate is None:
        return None
    candidate_id = getattr(candidate, "id", getattr(candidate, "pk", None))
    if candidate_id is not None:
        return candidate_id
    if isinstance(candidate, dict):
        return candidate.get("id") or candidate.get("pk")
    return id(candidate)


def _is_same_object(left, right):
    if left is right:
        return True

    left_key = _candidate_identity_key(left)
    right_key = _candidate_identity_key(right)
    if left_key is not None and right_key is not None:
        return left_key == right_key
    return False


def _looks_like_virtual_machine(candidate):
    if candidate is None:
        return False

    object_type = str(getattr(candidate, "object_type", "")).lower()
    if object_type == "virtualization.virtualmachine":
        return True

    model_name = str(
        getattr(getattr(candidate, "_meta", None), "model_name", "")).lower()
    if model_name == "virtualmachine":
        return True

    class_name = candidate.__class__.__name__.lower()
    return class_name == "virtualmachine"


def _looks_like_secrets_group(candidate):
    if candidate is None:
        return False
    if hasattr(candidate, "get_secret_value"):
        return True

    object_type = str(getattr(candidate, "object_type", "")).lower()
    if object_type == "extras.secretsgroup":
        return True

    model_name = str(
        getattr(getattr(candidate, "_meta", None), "model_name", "")).lower()
    if model_name == "secretsgroup":
        return True

    class_name = candidate.__class__.__name__.lower()
    return class_name == "secretsgroup"


def _resolve_selected_virtual_machine(selected_virtual_machine):
    if selected_virtual_machine is None:
        raise ValueError("An F5 virtual machine selection is required.")

    if _looks_like_virtual_machine(selected_virtual_machine):
        return selected_virtual_machine

    virtual_machine_model = _get_model("virtualization", "VirtualMachine")
    manager = getattr(virtual_machine_model, "objects", None)
    if manager is None or not hasattr(manager, "get"):
        raise ValueError("Unable to resolve Nautobot VirtualMachine model.")

    lookup_value = None
    if isinstance(selected_virtual_machine, dict):
        lookup_value = selected_virtual_machine.get(
            "id") or selected_virtual_machine.get("pk")
    else:
        lookup_value = str(selected_virtual_machine).strip() or None

    if lookup_value is None:
        raise ValueError(
            "The selected F5 virtual machine is missing an identifier.")

    try:
        return manager.get(pk=lookup_value)
    except TypeError:
        return manager.get(id=lookup_value)
    except Exception as exc:
        raise ValueError(
            f"Unable to resolve the selected F5 virtual machine '{lookup_value}': {exc}"
        ) from exc


def _collect_related_candidates(candidate, *, selected_virtual_machine=None):
    if candidate is None:
        return []

    if _is_same_object(candidate, selected_virtual_machine):
        return []

    if isinstance(candidate, dict):
        collected = []
        if any(key in candidate for key in ("id", "pk", "object_type", "display", "name")):
            collected.append(candidate)
        for value in candidate.values():
            collected.extend(_collect_related_candidates(
                value, selected_virtual_machine=selected_virtual_machine))
        return collected

    if hasattr(candidate, "all"):
        try:
            return _collect_related_candidates(
                list(candidate.all()), selected_virtual_machine=selected_virtual_machine)
        except Exception:
            return []

    if isinstance(candidate, (list, tuple, set)):
        collected = []
        for item in candidate:
            collected.extend(_collect_related_candidates(
                item, selected_virtual_machine=selected_virtual_machine))
        return collected

    return [candidate]


def _extract_related_candidates_from_relationship_association(selected_virtual_machine, association):
    matches = []
    for attribute_name in (
        "source",
        "destination",
        "peer",
        "source_object",
        "destination_object",
        "related_object",
        "peer_object",
    ):
        matches.extend(_collect_related_candidates(
            getattr(association, attribute_name, None),
            selected_virtual_machine=selected_virtual_machine,
        ))
    return matches


def resolve_f5_secrets_group(virtual_machine, *, relationship_slug=F5_SECRET_RELATIONSHIP_SLUG):
    direct_secrets_group = getattr(virtual_machine, "secrets_group", None)
    if direct_secrets_group is not None:
        return direct_secrets_group

    getter = getattr(virtual_machine, "get_secrets_group", None)
    if callable(getter):
        resolved = getter()
        if resolved is not None:
            return resolved

    candidates = []

    for attribute_name in (
        relationship_slug,
        "virtual_machine_secret_group",
    ):
        candidates.extend(_collect_related_candidates(
            getattr(virtual_machine, attribute_name, None),
            selected_virtual_machine=virtual_machine,
        ))

    relationship_method = getattr(
        virtual_machine, "get_relationships_with_related_objects", None)
    if callable(relationship_method):
        try:
            candidates.extend(_collect_related_candidates(
                relationship_method(),
                selected_virtual_machine=virtual_machine,
            ))
        except Exception:
            logger.exception(
                "Unable to inspect related objects for virtual machine %s during secrets-group resolution.",
                getattr(virtual_machine, "id", None),
            )

    if not candidates:
        relationship_association_model = _get_model(
            "extras", "RelationshipAssociation")
        manager = getattr(relationship_association_model, "objects", None)
        if manager is not None:
            if hasattr(manager, "filter"):
                associations = manager.filter(
                    relationship__slug=relationship_slug)
            elif hasattr(manager, "all"):
                associations = manager.all()
            else:
                associations = []
            for association in associations:
                candidates.extend(
                    _extract_related_candidates_from_relationship_association(
                        virtual_machine, association
                    )
                )

    secrets_groups = []
    seen = set()
    for candidate in candidates:
        if not _looks_like_secrets_group(candidate):
            continue
        dedupe_key = _candidate_identity_key(candidate)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        secrets_groups.append(candidate)

    if not secrets_groups:
        raise ValueError(
            f"No secrets group could be resolved for F5 virtual machine {getattr(virtual_machine, 'name', 'unknown')}."
        )

    if len(secrets_groups) > 1:
        raise ValueError(
            f"Multiple secrets groups were resolved for F5 virtual machine {getattr(virtual_machine, 'name', 'unknown')}."
        )

    return secrets_groups[0]


def _get_secret_value(secrets_group, related_object, access_type, secret_type):
    try:
        return secrets_group.get_secret_value(
            access_type=access_type,
            secret_type=secret_type,
            obj=related_object,
        )
    except TypeError:
        return secrets_group.get_secret_value(
            access_type=access_type,
            secret_type=secret_type,
        )


def resolve_f5_credentials(virtual_machine):
    secrets_group = resolve_f5_secrets_group(virtual_machine)
    access_type_candidates = [
        getattr(SecretsGroupAccessTypeChoices, "TYPE_GENERIC", None),
        getattr(SecretsGroupAccessTypeChoices, "TYPE_HTTP_S", None),
        getattr(SecretsGroupAccessTypeChoices, "TYPE_HTTP", None),
    ]
    access_type_candidates = [
        candidate for candidate in access_type_candidates if candidate]
    if not access_type_candidates:
        access_type_candidates = ["generic"]

    username_type = getattr(SecretsGroupSecretTypeChoices,
                            "TYPE_USERNAME", "username")
    password_type = getattr(SecretsGroupSecretTypeChoices,
                            "TYPE_PASSWORD", "password")

    username = None
    password = None
    errors = []

    for access_type in access_type_candidates:
        if username is None:
            try:
                username = _get_secret_value(
                    secrets_group, virtual_machine, access_type, username_type)
            except Exception as exc:
                errors.append(str(exc))

        if password is None:
            try:
                password = _get_secret_value(
                    secrets_group, virtual_machine, access_type, password_type)
            except Exception as exc:
                errors.append(str(exc))

        if username and password:
            return username, password

    error_suffix = f" Details: {'; '.join(errors)}" if errors else ""
    raise ValueError(
        f"Unable to resolve username/password from the attached secrets group for F5 virtual machine {getattr(virtual_machine, 'name', 'unknown')}.{error_suffix}"
    )


def _normalize_source_ip(source_ip):
    normalized = str(source_ip or "").strip()
    if not normalized:
        raise ValueError("A source IP address is required.")
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError as exc:
        raise ValueError(f"Invalid source IP address '{source_ip}'.") from exc


def _get_custom_field_mapping(virtual_machine):
    for attribute_name in ("custom_field_data", "cf"):
        value = getattr(virtual_machine, attribute_name, None)
        if isinstance(value, dict):
            return value
    return {}


def _strip_cidr(value):
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    if "://" in normalized:
        return normalized
    return normalized.split("/", 1)[0]


def _extract_host_from_endpoint(value):
    normalized = str(value or "").strip()
    if not normalized:
        return None
    if "://" in normalized:
        return urlparse(normalized).hostname
    normalized = _strip_cidr(normalized)
    return normalized or None


def _extract_primary_ip_host(primary_ip):
    if primary_ip is None:
        return None

    if hasattr(primary_ip, "host") and getattr(primary_ip, "host"):
        return _extract_host_from_endpoint(primary_ip.host)

    if hasattr(primary_ip, "address") and getattr(primary_ip, "address"):
        return _extract_host_from_endpoint(primary_ip.address)

    return _extract_host_from_endpoint(primary_ip)


def resolve_f5_ssh_endpoint(virtual_machine):
    for attribute_name in ("primary_ip4", "primary_ip", "primary_ip6"):
        host = _extract_primary_ip_host(
            getattr(virtual_machine, attribute_name, None))
        if host:
            return host

    custom_fields = _get_custom_field_mapping(virtual_machine)
    for key in (
        "ssh_endpoint",
        "ssh_host",
        "management_ip",
        "management_address",
        "mgmt_ip",
        "f5_management_ip",
        "primary_ip",
    ):
        host = _extract_host_from_endpoint(custom_fields.get(key))
        if host:
            return host

    if getattr(virtual_machine, "name", None):
        return str(virtual_machine.name).strip()

    raise ValueError(
        "Unable to determine an SSH endpoint for the selected F5 virtual machine."
    )


def _normalize_capture_duration(duration_value):
    try:
        duration = int(duration_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Capture duration must be an integer number of seconds.") from exc
    if duration <= 0:
        raise ValueError("Capture duration must be greater than zero.")
    if duration > 120:
        raise ValueError("Capture duration must be 120 seconds or less.")
    return duration


def _normalize_bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _resolve_scp_dropbox_credentials(integration):
    secrets_group = getattr(integration, "secrets_group", None)
    if secrets_group is None:
        raise ValueError(
            "SCP Dropbox external integration has no attached secrets group.")

    access_type = getattr(SecretsGroupAccessTypeChoices,
                          "TYPE_GENERIC", "generic")
    username_type = getattr(SecretsGroupSecretTypeChoices,
                            "TYPE_USERNAME", "username")
    password_type = getattr(SecretsGroupSecretTypeChoices,
                            "TYPE_PASSWORD", "password")

    username = secrets_group.get_secret_value(
        access_type=access_type, secret_type=username_type)
    password = secrets_group.get_secret_value(
        access_type=access_type, secret_type=password_type)
    if not username or not password:
        raise ValueError(
            "SCP Dropbox external integration returned an empty username or password.")
    return username, password


def resolve_scp_dropbox_destination(integration_name=SCP_DROPBOX_INTEGRATION_NAME):
    integration = ExternalIntegration.objects.get(name=integration_name)
    username, password = _resolve_scp_dropbox_credentials(integration)
    destination = parse_scp_destination(
        getattr(integration, "remote_url", ""),
        username=username,
    )
    return integration, destination, username, password


def _build_windows_scp_command(username, host, remote_path):
    return f"pscp.exe {username}@{host}:{remote_path} ."


def _send_notification_email(subject, body, to_email):
    normalized_emails = [
        email.strip()
        for email in str(to_email or "").split(";")
        if email.strip()
    ]
    if not normalized_emails:
        return

    from scripts.lib.utils import send_email

    for email in normalized_emails:
        send_email(subject, body, email)
        print(f"Notification email sent to: {email}")


def _build_notification_subject(incident_number, workflow_status):
    return f"{incident_number}: F5 TCPDump Capture {workflow_status}"


def _build_notification_body(incident_number, workflow_status, *, result=None, error_message=None):
    lines = [
        "Your F5 TCPDump Capture workflow has completed.",
        "",
        f"Workflow action status: {workflow_status}",
    ]

    if result:
        lines.append(
            f"Business result: {result.get('status', workflow_status)}")

    if error_message:
        lines.append(f"Failure reason: {error_message}")

    lines.extend(
        [
            "",
            "Details:",
            f"- Incident Number: {incident_number}",
        ]
    )

    if result:
        lines.extend(
            [
                f"- F5 Load Balancer: {result.get('f5_name', '')}",
                f"- Destination VIP: {result.get('vip_ip', '')}",
                f"- Source IP Address: {result.get('source_ip', '')}",
                f"- Capture duration (seconds): {result.get('capture_duration_seconds', '')}",
                f"- Capture file name: {result.get('capture_file_name', '')}",
                f"- SCP host: {result.get('scp_host', '')}",
                f"- SCP remote path: {result.get('scp_remote_path', '')}",
                "",
                "Windows download command:",
                result.get('download_command_windows', ''),
            ]
        )

        if result.get("capture_tls_keys"):
            lines.extend(
                [
                    "",
                    "TLS guidance:",
                    "- This capture was generated with F5 TLS session-secret data enabled.",
                    "- In Wireshark, enable the F5 TLS dissector before reviewing the capture.",
                    "- If needed, derive a pre-master secret log from the capture and load it under Edit > Preferences > Protocols > TLS.",
                    "- Handle this capture as sensitive data because it may contain material that can decrypt the session.",
                ]
            )

    return "\n".join(lines)


def run(params: dict):
    incident_number = str(params.get("incident_number") or "").strip()
    if not incident_number:
        raise ValueError("An incident number is required.")

    submitter_email = str(params.get("submitter_email") or "").strip()
    workflow_result = None
    workflow_error = None

    try:
        virtual_machine = _resolve_selected_virtual_machine(
            params.get("f5_virtual_machine") or params.get("virtual_machine")
        )
        print(f"Validating capture request for F5 {virtual_machine.name}.")

        vip_ip = str(params.get("vip_ip") or "").strip()
        if not vip_ip:
            raise ValueError("A destination VIP IP is required.")

        resolved_vips = resolve_virtual_machine_vip_ips(virtual_machine)
        if vip_ip not in resolved_vips:
            raise ValueError(
                f"Selected VIP {vip_ip} is not hosted on F5 {virtual_machine.name}."
            )
        print(
            f"Validated destination VIP {vip_ip} on F5 {virtual_machine.name}.")

        source_ip = _normalize_source_ip(params.get("source_ip"))
        capture_duration_seconds = _normalize_capture_duration(
            params.get("capture_duration_seconds")
        )
        capture_tls_keys = _normalize_bool(params.get("capture_tls_keys"))

        username, password = resolve_f5_credentials(virtual_machine)
        print("Resolved SSH credentials for the selected F5.")

        ssh_endpoint = resolve_f5_ssh_endpoint(virtual_machine)
        print("Resolved SSH endpoint for the selected F5.")

        _integration, scp_destination, scp_username, scp_password = resolve_scp_dropbox_destination()
        print(f"Resolved SCP Dropbox destination {scp_destination.host}.")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        capture_file_name = build_capture_file_name(
            incident_number, vip_ip, timestamp=timestamp)
        remote_capture_path = f"/var/tmp/{capture_file_name}"

        local_file_handle = tempfile.NamedTemporaryFile(
            prefix="f5-tcpdump-", suffix=".pcap", delete=False)
        local_file_path = local_file_handle.name
        local_file_handle.close()

        capture_client = None
        dropbox_client = None
        tls_enabled = False
        remote_file_retrieved = False

        try:
            capture_client = F5CaptureClient(
                ssh_endpoint, username, password)
            capture_client.connect()
            capture_client.enter_bash()
            print(f"Connected to F5 {virtual_machine.name} and entered bash.")

            interface_name = capture_client.determine_capture_interface(vip_ip)
            print(
                f"Using capture target {interface_name}:nnnp for VIP {vip_ip}.")

            if capture_tls_keys:
                capture_client.enable_tls_key_capture()
                tls_enabled = True
                print("Enabled TLS session-secret capture on the F5.")

            capture_client.run_capture(
                interface_name,
                vip_ip,
                source_ip,
                remote_capture_path,
                capture_duration_seconds,
                capture_tls_keys=capture_tls_keys,
            )
            print(f"Stopped tcpdump after {capture_duration_seconds} seconds.")

            capture_client.retrieve_file(remote_capture_path, local_file_path)
            remote_file_retrieved = True
            print(f"Retrieved capture file {capture_file_name} from the F5.")

            dropbox_client = SCPDropboxClient(
                scp_destination.host,
                scp_username,
                scp_password,
                port=scp_destination.port,
            )
            scp_remote_path = dropbox_client.upload_file(
                local_file_path,
                remote_directory=scp_destination.remote_directory,
                remote_file_name=capture_file_name,
            )
            print(f"Uploaded capture to {scp_remote_path}.")
        finally:
            if tls_enabled and capture_client is not None:
                try:
                    capture_client.disable_tls_key_capture()
                    print("Disabled TLS session-secret capture on the F5.")
                except Exception:
                    logger.exception(
                        "Failed to disable TLS session-secret capture on F5 %s.",
                        getattr(virtual_machine, "name", "unknown"),
                    )

            if remote_file_retrieved and capture_client is not None:
                try:
                    capture_client.remove_remote_file(remote_capture_path)
                except Exception:
                    logger.exception(
                        "Failed to remove remote capture file %s from F5 %s.",
                        remote_capture_path,
                        getattr(virtual_machine, "name", "unknown"),
                    )

            if capture_client is not None:
                capture_client.close()
            if dropbox_client is not None:
                dropbox_client.close()
            if os.path.exists(local_file_path):
                os.remove(local_file_path)

        workflow_result = {
            "status": "success",
            "incident_number": incident_number,
            "f5_name": virtual_machine.name,
            "vip_ip": vip_ip,
            "source_ip": source_ip,
            "capture_duration_seconds": capture_duration_seconds,
            "capture_file_name": capture_file_name,
            "scp_host": scp_destination.host,
            "scp_port": scp_destination.port,
            "scp_remote_path": scp_remote_path,
            "scp_username": scp_username,
            "capture_tls_keys": capture_tls_keys,
            "wireshark_guidance_required": capture_tls_keys,
            "download_command_windows": _build_windows_scp_command(
                scp_username,
                scp_destination.host,
                scp_remote_path,
            ),
        }
        print("Prepared notification payload for submitter email.")
        return workflow_result
    except Exception as exc:
        workflow_error = exc
        raise
    finally:
        if submitter_email:
            try:
                if workflow_result is not None:
                    _send_notification_email(
                        _build_notification_subject(
                            incident_number, "success"),
                        _build_notification_body(
                            incident_number,
                            "success",
                            result=workflow_result,
                        ),
                        submitter_email,
                    )
                elif workflow_error is not None:
                    _send_notification_email(
                        _build_notification_subject(incident_number, "failed"),
                        _build_notification_body(
                            incident_number,
                            "failed",
                            error_message=str(workflow_error),
                        ),
                        submitter_email,
                    )
            except Exception:
                logger.exception(
                    "Failed to send submitter notification for incident %s.",
                    incident_number,
                )
