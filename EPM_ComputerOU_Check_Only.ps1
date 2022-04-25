<#
.SYNOPSIS
    An example of a an EPM Advanced Policy condition checking script for validating the AD OU of the target host computer account.

.DESCRIPTION
    Validates that the distinguished name of the target computer matches the OU specified in the $requiredOU variable.

.EXAMPLE
    There are currently no parameters for this class. It is intended to be used as an advanced
    policy script in CyberArk EPM.  For more information and instructions on using a policy targeting script:
    https://docs.cyberark.com/Product-Doc/OnlineHelp/EPM/Latest/en/Content/EPM/Server%20User%20Guide/AdvancedPolicyTargetingConditions.htm
    PS C:\> EPM_ComputerOU_Check_Only.ps1

.NOTES
    Filename: EPM_ComputerOU_Check_Only.ps1
    Author: adam.markert@cyberark.com
    Modified date: 2022-04-21
    Version 1.0 - Initial release
#>

### Variables for Computer OU Check ###
$performOUCheck = $true
$requiredOU = "OU=EPM Workstations,OU=CyberArk,DC=CYBR,DC=COM"

function Get-OUStatus(){
$machineDN = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\DataStore\Machine\0" -Name "DNName"

if([string]::IsNullOrWhiteSpace($machineDN)){
    Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1001 -EntryType Information -Message "EPM Condition Check - EPM OU targeting condition not met, could not retrieve machine DN from registry" -Category 1 -RawData 10,20
    return $false;
    
}elseif([string]::IsNullOrWhiteSpace($requiredOU)){
    Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1001 -EntryType Information -Message "EPM Condition Check - EPM OU targeting condition not met, no target OU specified" -Category 1 -RawData 10,20
    return $false;
    
}elseif($machineDN -notmatch $requiredOU){
    Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1001 -EntryType Information -Message "EPM Condition Check - EPM OU targeting condition not met, $machineDN is not in $requiredOU" -Category 1 -RawData 10,20
    return $false;
    
}else{
    Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1001 -EntryType Information -Message "EPM Condition Check - EPM OU targeting condition is met, $machineDN is in $requiredOU" -Category 1 -RawData 10,20
    return $true;
}
}

if($performOUCheck){
    if(!(Get-OUStatus)){
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 2020 -EntryType Information -Message "EPM Policy Checks Complete - OU check failed - Exiting 1" -Category 1 -RawData 10,20
        exit 1;
    }else{
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1020 -EntryType Information -Message "EPM Policy Checks Complete - OU check succeeded - Exiting 0" -Category 1 -RawData 10,20
        exit 0;
    }
}
