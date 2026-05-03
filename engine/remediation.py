"""
Generates a remediation plan per RiskFinding.
Output is a RemediationAction dataclass:
  - finding_ref (control_id + resource_id)
  - priority: 1 (highest) -> N
  - action_title
  - action_steps: list[str]   # human-readable ordered steps
  - iac_hint: str             # Bicep or Terraform snippet (commented, for reference only)
  - effort_estimate: "Low" | "Medium" | "High"
  - owner_suggestion: str
"""

import logging
from dataclasses import dataclass, field

from engine.risk_scorer import RiskFinding

logger = logging.getLogger(__name__)

EFFORT_BY_SEVERITY = {
    "critical": "Medium",
    "high": "Medium",
    "medium": "Low",
    "low": "Low",
}

OWNER_BY_SECTION = {
    "Identity and Access Management": "IAM / Security Team",
    "Storage": "Cloud Infrastructure Team",
    "Networking": "Network / Security Team",
    "Key Vault": "Security Team",
    "SQL": "Database Administration Team",
    "Virtual Machines": "Cloud Infrastructure Team",
    "Logging and Monitoring": "Security Operations Team",
}

STEPS_BY_CONTROL: dict[str, list[str]] = {
    "CIS-2.1": [
        "Navigate to the Storage Account in the Azure Portal.",
        "Select 'Configuration' under Settings.",
        "Set 'Secure transfer required' to 'Enabled'.",
        "Click Save and verify no applications use plain HTTP.",
    ],
    "CIS-2.2": [
        "Navigate to the Storage Account in the Azure Portal.",
        "Select 'Networking' under Security + Networking.",
        "Set 'Public network access' to 'Disabled'.",
        "Configure private endpoints or service endpoints as required.",
        "Update application connection strings to use private endpoint FQDN.",
    ],
    "CIS-2.3": [
        "Navigate to the Storage Account in the Azure Portal.",
        "Select 'Configuration' under Settings.",
        "Set 'Allow Blob public access' to 'Disabled'.",
        "Audit existing blob containers and remove any public ACLs.",
    ],
    "CIS-2.4": [
        "Navigate to the Storage Account in the Azure Portal.",
        "Select 'Data protection' under Data management.",
        "Enable 'Enable soft delete for blobs' with a retention of at least 7 days.",
        "Optionally enable soft delete for containers and file shares.",
    ],
    "CIS-3.1": [
        "Open the NSG in the Azure Portal.",
        "Review all Inbound security rules.",
        "Delete or restrict any rule allowing port 22 from source 0.0.0.0/0 or *.",
        "Deploy Azure Bastion in the VNet for SSH access.",
        "Update runbooks and documentation to use Bastion.",
    ],
    "CIS-3.2": [
        "Open the NSG in the Azure Portal.",
        "Review all Inbound security rules.",
        "Delete or restrict any rule allowing port 3389 from source 0.0.0.0/0 or *.",
        "Deploy Azure Bastion for RDP access.",
        "Update runbooks and documentation to use Bastion.",
    ],
    "CIS-3.3": [
        "Navigate to the NSG in the Azure Portal.",
        "Select 'NSG flow logs' under Monitoring.",
        "Enable flow logs and select a storage account for log retention.",
        "Optionally configure Traffic Analytics for insights.",
    ],
    "CIS-4.1": [
        "Navigate to the Key Vault in the Azure Portal.",
        "Select 'Properties' under Settings.",
        "Ensure 'Soft-delete' shows as Enabled (cannot be disabled once enabled).",
        "If not enabled, update via CLI: az keyvault update --name <name> --enable-soft-delete true",
    ],
    "CIS-4.2": [
        "Navigate to the Key Vault in the Azure Portal.",
        "Select 'Properties' under Settings.",
        "Set 'Purge protection' to 'Enabled'.",
        "Note: once enabled, purge protection cannot be disabled.",
    ],
    "CIS-4.3": [
        "Navigate to the Key Vault in the Azure Portal.",
        "Select 'Networking' under Settings.",
        "Set 'Public network access' to 'Disabled'.",
        "Add a private endpoint in the VNet used by applications.",
        "Update application configurations to use private endpoint FQDN.",
    ],
    "CIS-5.1": [
        "Navigate to the SQL Server in the Azure Portal.",
        "Select 'Auditing' under Security.",
        "Toggle 'Enable Azure SQL Auditing' to On.",
        "Configure audit log destination (Log Analytics recommended).",
        "Set retention to at least 90 days.",
    ],
    "CIS-5.2": [
        "Navigate to the SQL Server in the Azure Portal.",
        "Select 'Networking' under Security.",
        "Set 'Public endpoint' to 'Disabled'.",
        "Add a private endpoint in the application VNet.",
        "Update connection strings to use private endpoint.",
    ],
    "CIS-5.3": [
        "Navigate to the SQL Server in the Azure Portal.",
        "Select 'Microsoft Defender for Cloud' under Security.",
        "Enable 'Microsoft Defender for SQL'.",
        "Configure alert notifications to the security team email.",
    ],
    "CIS-6.1": [
        "Identify the OS and data disks attached to the VM.",
        "Navigate to the VM in the Azure Portal.",
        "Select 'Disks' and enable encryption at host or Azure Disk Encryption.",
        "Create or use an existing Key Vault for disk encryption keys.",
        "Restart the VM to apply encryption (schedule a maintenance window).",
    ],
    "CIS-6.2": [
        "Navigate to the VM in the Azure Portal.",
        "Select 'Boot diagnostics' under Help.",
        "Enable boot diagnostics with a managed storage account.",
        "Verify diagnostic data is captured on next boot.",
    ],
    "CIS-7.1": [
        "Navigate to the Key Vault in the Azure Portal.",
        "Select 'Diagnostic settings' under Monitoring.",
        "Add a diagnostic setting targeting Log Analytics workspace.",
        "Enable AuditEvent log category.",
        "Set retention to at least 90 days.",
    ],
    "CIS-7.2": [
        "Navigate to the App Service in the Azure Portal.",
        "Select 'Configuration' under Settings.",
        "Set 'HTTPS Only' to On.",
        "Update any hardcoded HTTP URLs in the application.",
    ],
    "CIS-7.3": [
        "Navigate to the App Service in the Azure Portal.",
        "Select 'Configuration' under Settings, then 'General settings'.",
        "Set 'Remote debugging' to Off.",
        "Verify no IDE configurations reference this endpoint.",
    ],
    "CIS-8.1": [
        "Navigate to the SQL Server in the Azure Portal.",
        "Select 'Azure Active Directory' under Settings.",
        "Click 'Set admin' and assign an AAD user or group.",
        "Remove or rotate the SQL administrator password once AAD auth is confirmed.",
    ],
}

IAC_HINTS: dict[str, str] = {
    "CIS-2.1": """# REFERENCE ONLY — review before applying
# Bicep
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  properties: {
    supportsHttpsTrafficOnly: true
  }
}""",
    "CIS-2.2": """# REFERENCE ONLY — review before applying
# Bicep
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  properties: {
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
    }
  }
}""",
    "CIS-3.1": """# REFERENCE ONLY — review before applying
# Bicep: Remove rule allowing SSH from internet
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-06-01' = {
  properties: {
    securityRules: [
      // Remove any rule with destinationPortRange '22' and sourceAddressPrefix '*'
    ]
  }
}""",
    "CIS-5.1": """# REFERENCE ONLY — review before applying
# Terraform
resource "azurerm_mssql_server_extended_auditing_policy" "example" {
  server_id              = azurerm_mssql_server.example.id
  storage_endpoint       = azurerm_storage_account.example.primary_blob_endpoint
  retention_in_days      = 90
}""",
    "CIS-6.1": """# REFERENCE ONLY — review before applying
# Terraform
resource "azurerm_virtual_machine_extension" "disk_encryption" {
  name                 = "AzureDiskEncryption"
  virtual_machine_id   = azurerm_linux_virtual_machine.example.id
  publisher            = "Microsoft.Azure.Security"
  type                 = "AzureDiskEncryptionForLinux"
  type_handler_version = "1.1"
}""",
}


@dataclass
class RemediationAction:
    finding_ref: str
    control_id: str
    resource_name: str
    priority: int
    action_title: str
    action_steps: list[str] = field(default_factory=list)
    iac_hint: str = ""
    effort_estimate: str = "Medium"
    owner_suggestion: str = "Cloud Infrastructure Team"


def generate_remediation(findings: list[RiskFinding]) -> list[RemediationAction]:
    """Generate a prioritised remediation plan for all risk findings."""
    actions: list[RemediationAction] = []

    for priority, finding in enumerate(findings, start=1):
        control_id = finding.control_id
        steps = STEPS_BY_CONTROL.get(control_id, [
            f"Review the {finding.control_title} control against resource {finding.resource_name}.",
            "Apply the recommended configuration change per the CIS Azure Benchmark guidance.",
            "Verify the change is in effect and re-run this assessment.",
        ])

        iac_hint = IAC_HINTS.get(
            control_id,
            f"# REFERENCE ONLY — review before applying\n# See remediation guidance: {finding.remediation_template}",
        )

        effort = EFFORT_BY_SEVERITY.get(finding.severity, "Medium")
        if finding.resource_criticality in ("critical", "high"):
            effort = "Medium" if effort == "Low" else effort

        owner = OWNER_BY_SECTION.get(finding.section, "Cloud Infrastructure Team")

        action = RemediationAction(
            finding_ref=f"{control_id}::{finding.resource_id}",
            control_id=control_id,
            resource_name=finding.resource_name,
            priority=priority,
            action_title=f"[{finding.risk_band}] {finding.control_title} — {finding.resource_name}",
            action_steps=steps,
            iac_hint=iac_hint,
            effort_estimate=effort,
            owner_suggestion=owner,
        )
        actions.append(action)

    logger.info("Generated %d remediation actions", len(actions))
    return actions
