#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Event Log Collector Module
.DESCRIPTION
    Collects security-relevant Windows Event Log entries from domain controllers.
    Filters for authentication events, privilege use, account management, and
    other high-value security event IDs.
    All operations are read-only.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0

    Key Event IDs collected:
    4624 - Successful logon
    4625 - Failed logon
    4648 - Logon using explicit credentials
    4662 - An operation was performed on an object
    4663 - An attempt was made to access an object
    4672 - Special privileges assigned to new logon
    4720 - A user account was created
    4722 - A user account was enabled
    4723 - An attempt was made to change an account's password
    4724 - An attempt was made to reset an account's password
    4728 - A member was added to a security-enabled global group
    4732 - A member was added to a security-enabled local group
    4756 - A member was added to a security-enabled universal group
    4768 - A Kerberos authentication ticket (TGT) was requested
    4769 - A Kerberos service ticket was requested
    4771 - Kerberos pre-authentication failed
    4776 - The computer attempted to validate the credentials for an account
    4794 - An attempt was made to set the DSRM password
    5136 - A directory service object was modified
    7045 - A new service was installed in the system
#>

Set-StrictMode -Version Latest

#region Helper

function Get-EventsFromLog {
    <#
    .SYNOPSIS
        Retrieves events from a specified log on a local or remote machine.
    #>
    param(
        [string]$ComputerName = 'localhost',
        [string]$LogName      = 'Security',
        [int[]]$EventIds,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$MaxEvents = 1000
    )

    try {
        $filterHash = @{
            LogName   = $LogName
            StartTime = $StartTime
            EndTime   = $EndTime
        }
        if ($EventIds -and $EventIds.Count -gt 0) {
            $filterHash.Id = $EventIds
        }

        $params = @{
            FilterHashtable = $filterHash
            MaxEvents       = $MaxEvents
            ErrorAction     = 'Stop'
        }

        if ($ComputerName -ne 'localhost' -and $ComputerName -ne $env:COMPUTERNAME) {
            $params.ComputerName = $ComputerName
            if ($null -ne $Credential) { $params.Credential = $Credential }
        }

        return Get-WinEvent @params
    }
    catch [System.Exception] {
        if ($_.Exception.Message -like '*No events*') {
            Write-Verbose "No events found on ${ComputerName} for log '$LogName'."
            return @()
        }
        Write-Warning "Failed to retrieve events from ${ComputerName} ($LogName): $_"
        return @()
    }
}

function Convert-EventToObject {
    <#
    .SYNOPSIS
        Extracts key fields from a WinEvent record into a PSCustomObject.
    #>
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    try {
        $xml     = [xml]$Event.ToXml()
        $ns      = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

        $eventData = @{}
        $xml.SelectNodes('//e:EventData/e:Data', $ns) | ForEach-Object {
            if ($_.Name) { $eventData[$_.Name] = $_.'#text' }
        }

        return [PSCustomObject]@{
            EventId          = $Event.Id
            TimeCreated      = $Event.TimeCreated
            MachineName      = $Event.MachineName
            ProviderName     = $Event.ProviderName
            Level            = $Event.LevelDisplayName
            Message          = $Event.Message
            EventData        = $eventData
            SubjectUserSid   = $eventData['SubjectUserSid']
            SubjectUserName  = $eventData['SubjectUserName']
            SubjectDomainName = $eventData['SubjectDomainName']
            TargetUserSid    = $eventData['TargetUserSid']
            TargetUserName   = $eventData['TargetUserName']
            TargetDomainName = $eventData['TargetDomainName']
            LogonType        = $eventData['LogonType']
            IpAddress        = $eventData['IpAddress']
            IpPort           = $eventData['IpPort']
            ProcessName      = $eventData['ProcessName']
            WorkstationName  = $eventData['WorkstationName']
        }
    }
    catch {
        Write-Verbose "Could not parse event XML: $_"
        return [PSCustomObject]@{
            EventId     = $Event.Id
            TimeCreated = $Event.TimeCreated
            MachineName = $Event.MachineName
            Message     = $Event.Message
            EventData   = @{}
        }
    }
}

#endregion

#region Exported Functions

function Get-SecurityEventLogs {
    <#
    .SYNOPSIS
        Retrieves a broad set of security events from specified computers.
    .DESCRIPTION
        Collects all security-relevant event IDs for a configurable time window.
    .PARAMETER ComputerName
        Target computers (typically DCs).
    .PARAMETER DaysBack
        Number of days back to collect events. Default: 7.
    .PARAMETER MaxEvents
        Maximum number of events per event ID per host. Default: 500.
    .PARAMETER Credential
        Optional credential for remote access.
    .EXAMPLE
        Get-SecurityEventLogs -ComputerName dc01.corp.local -DaysBack 3
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [int]$DaysBack   = 7,
        [int]$MaxEvents  = 500,
        [System.Management.Automation.PSCredential]$Credential
    )

    $securityEventIds = @(
        4624, 4625, 4648, 4662, 4663, 4672, 4720, 4722, 4723, 4724,
        4726, 4728, 4732, 4738, 4740, 4756, 4768, 4769, 4771, 4776,
        4794, 4798, 4799, 5136, 5141, 7045
    )

    $startTime = (Get-Date).AddDays(-$DaysBack)
    $endTime   = Get-Date

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Collecting security events from: $computer (last $DaysBack days)"

            $events = Get-EventsFromLog -ComputerName $computer -LogName 'Security' `
                -EventIds $securityEventIds -StartTime $startTime -EndTime $endTime `
                -Credential $Credential -MaxEvents $MaxEvents

            $events | ForEach-Object { Convert-EventToObject $_ }
        }
    }
}

function Get-DomainControllerLogs {
    <#
    .SYNOPSIS
        Collects Directory Service and System event logs from domain controllers.
    .PARAMETER ComputerName
        Domain controller hostnames.
    .PARAMETER DaysBack
        Number of days back. Default: 3.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-DomainControllerLogs -ComputerName dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [int]$DaysBack   = 3,
        [int]$MaxEvents  = 200,
        [System.Management.Automation.PSCredential]$Credential
    )

    $dsEventIds = @(
        1102,   # Audit log cleared
        1644,   # LDAP search statistics
        2887,   # Number of unsigned LDAP binds
        2888,   # Number of SASL LDAP binds using weak encryption
        2889,   # Clients making unsigned LDAP binds
        4928,   # AD replica source naming context established
        4929,   # AD replica source naming context removed
        4932,   # AD naming context synchronization began
        4933,   # AD naming context synchronization ended
        4934,   # Attributes of an AD object were replicated
        4935,   # Replication failure begins
        4936    # Replication failure ends
    )

    $startTime = (Get-Date).AddDays(-$DaysBack)
    $endTime   = Get-Date

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Collecting Directory Service logs from: $computer"

            # Directory Service log
            $dsEvents = Get-EventsFromLog -ComputerName $computer `
                -LogName 'Directory Service' -EventIds $dsEventIds `
                -StartTime $startTime -EndTime $endTime `
                -Credential $Credential -MaxEvents $MaxEvents

            # Security log - audit cleared
            $auditCleared = Get-EventsFromLog -ComputerName $computer `
                -LogName 'Security' -EventIds @(1102, 4719) `
                -StartTime $startTime -EndTime $endTime `
                -Credential $Credential -MaxEvents 50

            ($dsEvents + $auditCleared) | ForEach-Object { Convert-EventToObject $_ }
        }
    }
}

function Get-AuthenticationEvents {
    <#
    .SYNOPSIS
        Collects authentication-related events (logons, Kerberos, NTLM).
    .DESCRIPTION
        Focuses on logon success/failure events, Kerberos ticket requests, and
        NTLM credential validation. Useful for identifying brute force, pass-the-hash,
        pass-the-ticket, and Kerberoasting activity.
    .PARAMETER ComputerName
        Target hosts.
    .PARAMETER DaysBack
        Number of days back.
    .PARAMETER MaxEvents
        Max events to collect. Default: 1000.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-AuthenticationEvents -ComputerName dc01.corp.local -DaysBack 1 -MaxEvents 500
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [int]$DaysBack   = 7,
        [int]$MaxEvents  = 1000,
        [System.Management.Automation.PSCredential]$Credential
    )

    $authEventIds = @(
        4624,  # Successful logon
        4625,  # Failed logon
        4648,  # Logon with explicit credentials
        4768,  # Kerberos TGT request
        4769,  # Kerberos service ticket request
        4770,  # Kerberos service ticket renewed
        4771,  # Kerberos pre-authentication failed
        4772,  # Kerberos authentication ticket request failed
        4776,  # NTLM credential validation
        4777   # Domain controller failed to validate credentials
    )

    $startTime = (Get-Date).AddDays(-$DaysBack)
    $endTime   = Get-Date

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Collecting authentication events from: $computer"

            $events = Get-EventsFromLog -ComputerName $computer -LogName 'Security' `
                -EventIds $authEventIds -StartTime $startTime -EndTime $endTime `
                -Credential $Credential -MaxEvents $MaxEvents

            $results = $events | ForEach-Object {
                $obj = Convert-EventToObject $_

                # Enrich with logon type description
                $obj | Add-Member -NotePropertyName 'LogonTypeDescription' -NotePropertyValue (
                    switch ($obj.LogonType) {
                        '2'  { 'Interactive' }
                        '3'  { 'Network' }
                        '4'  { 'Batch' }
                        '5'  { 'Service' }
                        '7'  { 'Unlock' }
                        '8'  { 'NetworkCleartext' }
                        '9'  { 'NewCredentials' }
                        '10' { 'RemoteInteractive (RDP)' }
                        '11' { 'CachedInteractive' }
                        default { "Unknown ($($obj.LogonType))" }
                    }
                ) -Force

                # Flag Kerberoasting indicators (4769 with DES/RC4 encryption)
                if ($obj.EventId -eq 4769) {
                    $encType = $obj.EventData['TicketEncryptionType']
                    $obj | Add-Member -NotePropertyName 'PossibleKerberoasting' -NotePropertyValue `
                        ($encType -in @('0x17','0x18','23','24')) -Force
                }

                $obj
            }

            $results
        }
    }
}

function Get-PrivilegedAccountEvents {
    <#
    .SYNOPSIS
        Collects events related to privileged account activity.
    .DESCRIPTION
        Gathers events covering: privilege use, account creation/modification,
        group membership changes, DSRM password changes, AdminSDHolder changes,
        and directory replication (potential DCSync indicators).
    .PARAMETER ComputerName
        Target hosts.
    .PARAMETER DaysBack
        Number of days back.
    .PARAMETER MaxEvents
        Max events to collect.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-PrivilegedAccountEvents -ComputerName dc01.corp.local -DaysBack 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [int]$DaysBack   = 30,
        [int]$MaxEvents  = 500,
        [System.Management.Automation.PSCredential]$Credential
    )

    $privEventIds = @(
        4670,  # Permissions on an object were changed
        4672,  # Special privileges assigned to new logon
        4673,  # A privileged service was called
        4674,  # An operation was attempted on a privileged object
        4720,  # User account created
        4722,  # User account enabled
        4723,  # Password change attempt
        4724,  # Password reset attempt
        4725,  # User account disabled
        4726,  # User account deleted
        4728,  # Member added to global security group
        4729,  # Member removed from global security group
        4732,  # Member added to local security group
        4733,  # Member removed from local security group
        4738,  # User account was changed
        4740,  # User account was locked out
        4756,  # Member added to universal security group
        4757,  # Member removed from universal security group
        4794,  # DSRM password set attempt
        4798,  # User's local group membership enumerated
        4799,  # Security-enabled local group membership enumerated
        5136,  # Directory service object modified
        5137,  # Directory service object created
        5138,  # Directory service object undeleted
        5139,  # Directory service object moved
        5141   # Directory service object deleted
    )

    $startTime = (Get-Date).AddDays(-$DaysBack)
    $endTime   = Get-Date

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Collecting privileged account events from: $computer"

            $events = Get-EventsFromLog -ComputerName $computer -LogName 'Security' `
                -EventIds $privEventIds -StartTime $startTime -EndTime $endTime `
                -Credential $Credential -MaxEvents $MaxEvents

            $events | ForEach-Object {
                $obj = Convert-EventToObject $_

                # Flag AdminSDHolder-related 5136 events
                if ($obj.EventId -eq 5136) {
                    $dn = $obj.EventData['ObjectDN']
                    $obj | Add-Member -NotePropertyName 'IsAdminSDHolderChange' -NotePropertyValue `
                        ($null -ne $dn -and $dn -like '*AdminSDHolder*') -Force
                }

                # Flag potential DCSync: 4662 with Replicating Directory Changes right
                if ($obj.EventId -eq 4662) {
                    $accessMask = $obj.EventData['AccessMask']
                    $properties = $obj.EventData['Properties']
                    $obj | Add-Member -NotePropertyName 'PotentialDCSync' -NotePropertyValue `
                        ($null -ne $properties -and ($properties -like '*1131f6aa*' -or $properties -like '*1131f6ad*')) -Force
                }

                $obj
            }
        }
    }
}

#endregion

Export-ModuleMember -Function Get-SecurityEventLogs, Get-DomainControllerLogs,
                               Get-AuthenticationEvents, Get-PrivilegedAccountEvents
