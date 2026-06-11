#Requires -Version 5.1
<#
  KQL from Defender for Identity / M365 Defender advanced hunting examples.
  These are the same logical queries; run with Invoke-M365DefenderAdvancedHunt (not Graph).
#>

function ConvertTo-SafeKqlString {
  <#
    Escape an operator-supplied value before interpolating it into a KQL
    double-quoted string literal, so a crafted value (e.g. a UPN containing a
    double-quote) cannot break out of the literal (KQL injection). Reject
    embedded newlines; escape backslash then double-quote per Kusto
    string-literal rules. The mcp-sentinel scanner flags this very pattern.
  #>
  param([Parameter(Mandatory)][AllowEmptyString()][string] $Value)
  if ($Value -match '[\r\n]') {
    throw "Refusing to interpolate a value containing a newline into KQL: '$Value'"
  }
  return ($Value -replace '\\', '\\') -replace '"', '\"'
}

function Get-IdentityKql_Example1_NtlmVsKerberos {
  return @'
IdentityLogonEvents
| where Application == "Active Directory"
| where Protocol in ("Ntlm", "Kerberos")
| where ActionType == "LogonSuccess"
| summarize count() by Protocol
'@
}

function Get-IdentityKql_Example2_SingleServiceAccountByDevice {
  param([string] $ServiceAccountUpn = 'your_svcaccount@domain.local')
  $safeUpn = ConvertTo-SafeKqlString $ServiceAccountUpn
  return @"
IdentityLogonEvents
| where Application == "Active Directory"
| where AccountUpn == "$safeUpn"
| where ActionType == "LogonSuccess"
| summarize count() by DeviceName
"@
}

function Get-IdentityKql_Example3_AllServiceAccounts {
  return @'
IdentityInfo
| where SourceProvider == "ActiveDirectory"
| where Type == "ServiceAccount"
| summarize arg_max(Timestamp, *) by AccountName
| sort by Timestamp desc
'@
}

function Get-IdentityKql_Example4_MultipleServiceAccounts {
  param(
    [string[]] $ServiceUpns = @('svc1@contoso.local', 'svc2@contoso.local', 'svc3@contoso.local')
  )
  $parts = $ServiceUpns | ForEach-Object { '"' + (ConvertTo-SafeKqlString $_) + '"' }
  $listInner = $parts -join ','
  $dynamic = "dynamic([$listInner])"
  return @"
let srvcList = $dynamic;
IdentityLogonEvents
| where AccountUpn in~ (srvcList)
| summarize count() by AccountName, DeviceName, Protocol
"@
}

function Get-IdentityKql_Example5_DcSmbFileWrite {
  return @'
IdentityDirectoryEvents
| where ActionType == "SMB file copy"
| extend ParsedFields=parse_json(AdditionalFields)
| extend FileName=tostring(ParsedFields.FileName), FilePath=tostring(ParsedFields.FilePath), Method=tostring(ParsedFields.Method)
| where Method == "Write"
| project Timestamp, ActionType, DeviceName, IPAddress, AccountDisplayName, DestinationDeviceName, DestinationPort, FileName, FilePath, Method
'@
}

function Get-IdentityKql_Example6_SamrLdapEnumeration {
  return @'
IdentityQueryEvents
| where Application == "Active Directory"
| where ActionType in ("SAMR", "LDAP")
| project Timestamp, ActionType, DeviceName, DestinationDeviceName, AccountDisplayName, QueryType, QueryTarget
'@
}
