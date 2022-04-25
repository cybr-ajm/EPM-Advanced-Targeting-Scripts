<#
.SYNOPSIS
    An example of a multiple condition checking script, intended to allow for advanced
    targeting of CyberArk EPM Policies.

.DESCRIPTION
    This script checks for a series of conditions in order to determine if the current
    machine and user context should result in the application of certain CyberArk EPM Policies.
    These conditions are the Organizational Unit of the computer
    account, and a specific value in a property of a WMI class.  If all of the conditions evaluate
    to TRUE, the script will return and exit code of 0 (policy applies).  If any are FALSE, or fail to look up
    properly, it will return an exit code of 1 (policy does not apply).

.EXAMPLE
    There are currently no parameters for this class. It is intended to be used as an advanced
    policy script in CyberArk EPM.  For more information and instructions on using a policy targeting script:
    https://docs.cyberark.com/Product-Doc/OnlineHelp/EPM/Latest/en/Content/EPM/Server%20User%20Guide/AdvancedPolicyTargetingConditions.htm
    PS C:\> EPM_WMI_and_ComputerOU_Check.ps1

.NOTES
    Filename: EPM_WMI_and_ComputerOU_Check.ps1
    Author: adam.markert@cyberark.com
    Modified date: 2022-04-01
    Version 1.0 - Initial release
#>


### Variables for WMI Check, use $performWMICheck to toggle this condition check ###
$performWMICheck = $true
$WMIClassName = "Win32_ComputerSystem"
$WMIPropertyName = "Name"
$requiredWMIPropertyValue = "EPMWKS01"

### Variables for Computer OU Check ###
$performOUCheck = $true
$requiredOU = "OU=EPM Workstations,OU=CyberArk,DC=CYBR,DC=COM"

function Get-OUStatus(){
$machineDN = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\DataStore\Machine\0" -Name "DNName"

if([string]::IsNullOrWhiteSpace($machineDN)){
    Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 2001 -EntryType Information -Message "EPM Condition Check - EPM OU targeting condition not met, could not retrieve machine DN from registry" -Category 1 -RawData 10,20
    return $false;
    
}elseif([string]::IsNullOrWhiteSpace($requiredOU)){
    Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 2002 -EntryType Information -Message "EPM Condition Check - EPM OU targeting condition not met, no target OU specified" -Category 1 -RawData 10,20
    return $false;
    
}elseif($machineDN -notmatch $requiredOU){
    Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 2003 -EntryType Information -Message "EPM Condition Check - EPM OU targeting condition not met, $machineDN is not in $requiredOU" -Category 1 -RawData 10,20
    return $false;
    
}else{
    Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1001 -EntryType Information -Message "EPM Condition Check - EPM OU targeting condition is met, $machineDN is in $requiredOU" -Category 1 -RawData 10,20
    return $true;
}
}

function Get-WMIStatus(){
    $WMIPropertyValue

    try{
        $WMIPropertyValue = (Get-CimInstance -ClassName $WMIClassName -ErrorAction Stop).$WMIPropertyName
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1001 -EntryType Information -Message "EPM Condition Check - $WMIClassName.$WMIPropertyName is $WMIPropertyValue." -Category 1 -RawData 10,20
    }
    catch{
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 2001 -EntryType Information -Message "EPM Condition Check - Error checking WMI Property. Class may not exist." -Category 1 -RawData 10,20
        return $false
    }

    if($WMIPropertyValue -eq $requiredWMIPropertyValue){
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1002 -EntryType Information -Message "EPM Condition Check - WMI Property Value of $WMIPropertyValue matches required value of $requiredWMIPropertyValue." -Category 1 -RawData 10,20
        return $true
    }else{
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 2002 -EntryType Information -Message "EPM Condition Check - WMI Property Value of $WMIPropertyValue does not match required value of $requiredWMIPropertyValue." -Category 1 -RawData 10,20
        return $false
    }
}

if($performWMICheck){
    if(!(Get-WMIStatus)){
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1020 -EntryType Information -Message "EPM Policy Checks Complete - WMI check Failed - Exiting 1" -Category 1 -RawData 10,20
        exit 1;
    }
}

if($performOUCheck){
    if(!(Get-OUStatus)){
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 2020 -EntryType Information -Message "EPM Policy Checks Complete - OU check Failed - Exiting 1" -Category 1 -RawData 10,20
    exit 1;
    }else{
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 1020 -EntryType Information -Message "EPM Policy Checks Complete - All checks passed - Exiting 0" -Category 1 -RawData 10,20
        exit 0;
    }
}