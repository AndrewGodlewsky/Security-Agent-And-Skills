#requires -Version 5.1
<#
Read-only inventory; writes only the requested JSON artifact.
Never invokes installed products, uninstall commands, or Win32_Product.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutFile,
    [ValidateSet('OS','MachineApps','UserApps','StoreApps','Hotfixes')]
    [string[]]$Collectors = @('OS','MachineApps','UserApps'),
    [ValidateRange(1,120)][int]$HotfixTimeoutSeconds = 30
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$items = [System.Collections.Generic.List[object]]::new()
$checks = [System.Collections.Generic.List[object]]::new()
$patches = @()
$observed = [DateTime]::UtcNow.ToString('o')
function Add-Coverage([string]$Scope, [string]$Collector, [string]$Status, [string]$Detail) {
    $checks.Add([ordered]@{scope=$Scope;collector=$Collector;status=$Status;detail=$Detail})
}
function Add-Component([string]$Name,[string]$Version,[string]$Source,[string]$Kind) {
    $items.Add([ordered]@{ecosystem='Windows';name=$Name;version=$Version;source=$Source;
        location=$Source;evidence_kind=$Kind;scope='windows-host'})
}
function Read-Uninstall([Microsoft.Win32.RegistryHive]$Hive,[Microsoft.Win32.RegistryView]$View) {
    $label = "$Hive/$View/Software/Microsoft/Windows/CurrentVersion/Uninstall"
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive,$View)
        $key = $base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall',$false)
        if ($null -eq $key) {
            Add-Coverage $label 'registry' 'complete' 'Uninstall key absent in this registry view'
            return
        }
        foreach ($name in $key.GetSubKeyNames()) {
            $sub = $null
            try {
                $sub = $key.OpenSubKey($name,$false)
                if ($null -eq $sub) { throw 'Subkey disappeared or is inaccessible' }
                $display = [string]$sub.GetValue('DisplayName','')
                if ($display) {
                    Add-Component $display ([string]$sub.GetValue('DisplayVersion','')) "$label/$name" 'installed'
                }
            } catch {
                Add-Coverage "$label/$name" 'registry' 'error' $_.Exception.Message
            } finally { if ($null -ne $sub) { $sub.Dispose() } }
        }
        Add-Coverage $label 'registry' 'complete' 'Read display names and versions only'
    } catch {
        Add-Coverage $label 'registry' 'error' $_.Exception.Message
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        if ($null -ne $base) { $base.Dispose() }
    }
}
if ($env:OS -ne 'Windows_NT') { throw 'This collector requires Windows' }
foreach ($collector in @('OS','MachineApps','UserApps','StoreApps','Hotfixes')) {
    if ($collector -notin $Collectors) {
        Add-Coverage 'windows-host' $collector 'not_selected' 'Not requested for this collection'
        continue
    }
    switch ($collector) {
        'OS' {
            $base=$null; $key=$null
            try {
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
                $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion',$false)
                if ($null -eq $key) { throw 'Windows version key unavailable' }
                $build=[string]$key.GetValue('CurrentBuildNumber','')
                $ubr=$key.GetValue('UBR',$null)
                if (-not $build -or $null -eq $ubr) { throw 'Build number or update revision unavailable' }
                $major=$key.GetValue('CurrentMajorVersionNumber',$null)
                $minor=$key.GetValue('CurrentMinorVersionNumber',$null)
                if ($null -eq $major -or $null -eq $minor) { throw 'OS version metadata unavailable' }
                Add-Component 'Microsoft Windows' "$major.$minor.$build.$ubr" 'HKLM/WindowsNT/CurrentVersion' 'os'
                $context=[ordered]@{product_name=[string]$key.GetValue('ProductName','');
                    edition=[string]$key.GetValue('EditionID','');
                    display_version=[string]$key.GetValue('DisplayVersion','');
                    build=$build;ubr=$ubr;architecture=$env:PROCESSOR_ARCHITECTURE}
                Add-Coverage 'windows-host' 'OS' 'complete' 'Build and revision collected; advisory edition/build-branch prerequisites need separate assessment'
            } catch { Add-Coverage 'windows-host' 'OS' 'error' $_.Exception.Message }
            finally {
                if ($null -ne $key) {$key.Dispose()}
                if ($null -ne $base) {$base.Dispose()}
            }
        }
        'MachineApps' {
            foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
                Read-Uninstall ([Microsoft.Win32.RegistryHive]::LocalMachine) $view
            }
        }
        'UserApps' {
            foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
                Read-Uninstall ([Microsoft.Win32.RegistryHive]::CurrentUser) $view
            }
            Add-Coverage 'other-windows-users' 'registry' 'unsupported' 'Only the current user hive is inspected'
        }
        'StoreApps' {
            try {
                if (-not(Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {throw 'Get-AppxPackage unavailable in this PowerShell host'}
                foreach($app in @(Get-AppxPackage -ErrorAction Stop)) {
                    Add-Component ([string]$app.Name) ([string]$app.Version) ("Appx/"+$app.PackageFullName) 'installed'
                }
                Add-Coverage 'windows-host' 'StoreApps' 'complete' 'Current-user Store registration only; running package versions not checked'
            } catch { Add-Coverage 'windows-host' 'StoreApps' 'error' $_.Exception.Message }
        }
        'Hotfixes' {
            $job=$null
            try {
                $job=Start-Job -ScriptBlock { Get-HotFix -ErrorAction Stop | Select-Object -ExpandProperty HotFixID }
                if (-not(Wait-Job -Job $job -Timeout $HotfixTimeoutSeconds)) {throw 'Hotfix query timed out'}
                $patches=@(Receive-Job -Job $job -ErrorAction Stop)
                if ($job.State -ne 'Completed') {throw 'Hotfix query failed'}
                Add-Coverage 'windows-host' 'Hotfixes' 'partial' 'Get-HotFix is not exhaustive Windows Update history; absence of a KB is not proof it is missing or unsuperseded'
            } catch { Add-Coverage 'windows-host' 'Hotfixes' 'error' $_.Exception.Message }
            finally {
                if ($null -ne $job) {
                    Stop-Job -Job $job -ErrorAction SilentlyContinue
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}
Add-Coverage 'windows-host' 'runtime' 'unsupported' 'Portable applications, other users, running-process versions, WSL, containers and service reachability require targeted inspection'
if (-not(Get-Variable context -ErrorAction SilentlyContinue)) { $context=$null }
$artifact=[ordered]@{schema_version=1;collected_at=$observed;scopes=@('windows-host');
    components=@($items.ToArray());coverage=@($checks.ToArray());hotfixes=@($patches);context=$context}
$destination=[IO.Path]::GetFullPath($OutFile)
$parent=[IO.Path]::GetDirectoryName($destination)
[IO.Directory]::CreateDirectory($parent) | Out-Null
[IO.File]::WriteAllText($destination,($artifact | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
Write-Output $destination

