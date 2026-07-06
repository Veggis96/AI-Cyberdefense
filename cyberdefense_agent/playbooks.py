from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    attack_type: str
    actions: list[str]


PLAYBOOKS = {
    "brute_force": Playbook(
        attack_type="brute_force",
        actions=[
            "Temporarily lock targeted account if failures continue.",
            "Require MFA re-verification for the affected user.",
            "Block or rate-limit the source IP at the identity edge after analyst approval.",
            "Review successful logins from the same source in the next 24 hours.",
        ],
    ),
    "port_scan": Playbook(
        attack_type="port_scan",
        actions=[
            "Confirm whether the source belongs to an approved scanner.",
            "Throttle or block the source IP at the perimeter after analyst approval.",
            "Check exposed services on the targeted asset.",
            "Increase logging for the target host for the next hour.",
        ],
    ),
    "malware_indicator": Playbook(
        attack_type="malware_indicator",
        actions=[
            "Isolate the affected endpoint from non-essential network access.",
            "Collect process, file hash, and parent process evidence.",
            "Run endpoint protection scan and preserve quarantine details.",
            "Search for the same indicator across other assets.",
        ],
    ),
    "data_exfiltration": Playbook(
        attack_type="data_exfiltration",
        actions=[
            "Validate whether the transfer matches expected business activity.",
            "Restrict outbound traffic from the asset after analyst approval.",
            "Identify destination, protocol, account, and data classification.",
            "Preserve network flow evidence for incident handling.",
        ],
    ),
    "web_attack": Playbook(
        attack_type="web_attack",
        actions=[
            "Confirm whether the request was blocked by the WAF or application layer.",
            "Rate-limit the source and inspect nearby requests in the same session.",
            "Review application logs for errors, stack traces, or unexpected database activity.",
            "Create a detection ticket with payload and endpoint evidence.",
        ],
    ),
    "rare_port_access": Playbook(
        attack_type="rare_port_access",
        actions=[
            "Validate whether the port is expected for the affected asset.",
            "Review recent service changes and firewall policy for the host.",
            "Increase network logging for the asset while the activity is investigated.",
        ],
    ),
    "unusual_login_time": Playbook(
        attack_type="unusual_login_time",
        actions=[
            "Confirm whether the login matches the user's expected working pattern.",
            "Review MFA, source IP, and recent account changes for the user.",
            "Force credential review after analyst approval if other signals are present.",
        ],
    ),
    "data_transfer_anomaly": Playbook(
        attack_type="data_transfer_anomaly",
        actions=[
            "Validate the transfer against business activity for the asset.",
            "Review destination, protocol, and user context for the transfer.",
            "Restrict outbound traffic from the asset after analyst approval if unexplained.",
        ],
    ),
    "threat_intel_match": Playbook(
        attack_type="threat_intel_match",
        actions=[
            "Validate the indicator source and confirm the observable in raw logs.",
            "Search for the same indicator across recent events and stored memory.",
            "Block or quarantine related traffic after analyst approval if confirmed.",
            "Create an investigation ticket with indicator, source, and evidence.",
        ],
    ),
    "windows_service_install": Playbook(
        attack_type="windows_service_install",
        actions=[
            "Validate the service name, binary path, and installing account.",
            "Compare the service against approved software deployment records.",
            "Disable the service after analyst approval if it is unauthorized.",
            "Search for the same service binary across Windows hosts.",
        ],
    ),
    "windows_audit_log_cleared": Playbook(
        attack_type="windows_audit_log_cleared",
        actions=[
            "Confirm whether log clearing was part of approved maintenance.",
            "Collect available forwarded logs and endpoint telemetry for the host.",
            "Review privileged account activity immediately before the event.",
            "Isolate the host after analyst approval if log clearing is unexplained.",
        ],
    ),
    "windows_user_created": Playbook(
        attack_type="windows_user_created",
        actions=[
            "Validate the new account against identity management change records.",
            "Review group membership and recent privileged activity for the account.",
            "Disable the account after analyst approval if it is unauthorized.",
            "Search for related account changes on domain controllers and hosts.",
        ],
    ),
    "windows_privileged_logon": Playbook(
        attack_type="windows_privileged_logon",
        actions=[
            "Validate the privileged logon source and account owner.",
            "Review nearby authentication, process creation, and account-change events.",
            "Require credential review after analyst approval if the logon is unusual.",
        ],
    ),
    "windows_suspicious_process": Playbook(
        attack_type="windows_suspicious_process",
        actions=[
            "Collect process command line, parent process, user, and file hash evidence.",
            "Search for the same command line and hash across other endpoints.",
            "Isolate the endpoint after analyst approval if execution is confirmed malicious.",
            "Preserve endpoint telemetry for incident handling.",
        ],
    ),
    "cloud_root_login": Playbook(
        attack_type="cloud_root_login",
        actions=[
            "Confirm whether root console login was tied to an approved emergency change.",
            "Review newly created sessions, access keys, roles, policies, and billing changes.",
            "Rotate root credentials and require MFA re-verification after analyst approval if unexplained.",
            "Create an identity investigation ticket with source, account, and control-plane evidence.",
        ],
    ),
    "cloud_access_key_created": Playbook(
        attack_type="cloud_access_key_created",
        actions=[
            "Validate the access key creation against an approved administrator change.",
            "Review policy attachments and API activity for the creating principal.",
            "Disable the access key after analyst approval if it is unauthorized.",
            "Search recent cloud audit events for the same principal and source IP.",
        ],
    ),
    "cloud_failed_login_spike": Playbook(
        attack_type="cloud_failed_login_spike",
        actions=[
            "Check for successful logins from the same source after the failures.",
            "Review MFA status, account privilege, and recent password resets for the user.",
            "Rate-limit or block the source IP at the identity edge after analyst approval.",
        ],
    ),
    "saas_mfa_method_added": Playbook(
        attack_type="saas_mfa_method_added",
        actions=[
            "Confirm the MFA factor addition with the account owner or helpdesk ticket.",
            "Review recent login failures and source IP changes for the user.",
            "Remove the MFA factor after analyst approval if it is unauthorized.",
        ],
    ),
    "saas_admin_role_assignment": Playbook(
        attack_type="saas_admin_role_assignment",
        actions=[
            "Validate the admin role assignment against an approved access request.",
            "Review the assigning principal and follow-up administrative actions.",
            "Remove the admin role after analyst approval if it is unauthorized.",
        ],
    ),
    "saas_oauth_consent": Playbook(
        attack_type="saas_oauth_consent",
        actions=[
            "Review application publisher, permissions, and consenting user context.",
            "Check whether the application has been seen or approved before.",
            "Revoke OAuth consent after analyst approval if the application is suspicious.",
        ],
    ),
}


def playbook_for(attack_type: str) -> Playbook:
    return PLAYBOOKS.get(
        attack_type,
        Playbook(
            attack_type=attack_type,
            actions=["Escalate to an analyst with the attached evidence."],
        ),
    )
