<#
.SYNOPSIS
    An example of a an EPM Advanced Policy condition checking script for validating a WMI property on the target host.

.DESCRIPTION
    Checks for the presence of a specific WMI Class/Property, and validates the value before Exiting 0 to activate the script. Absence of 
    the property or correct value results in an exit code of 1 (disables EPM policy).  The class name, property, and required property value
    are specified in variables at the top of the script.

.EXAMPLE
    There are currently no parameters for this class. It is intended to be used as an advanced
    policy script in CyberArk EPM.  For more information and instructions on using a policy targeting script:
    https://docs.cyberark.com/Product-Doc/OnlineHelp/EPM/Latest/en/Content/EPM/Server%20User%20Guide/AdvancedPolicyTargetingConditions.htm
    PS C:\> EPM_WMI_Check_Only.ps1

.NOTES
    Filename: EPM_WMI_Check_Only.ps1
    Author: adam.markert@cyberark.com
    Modified date: 2022-04-21
    Version 1.0 - Initial release
#>


### Variables for WMI Check, use $performWMICheck to toggle this condition check ###
$performWMICheck = $true
$WMIClassName = "Win32_ComputerSystem"
$WMIPropertyName = "Name"
$requiredWMIPropertyValue = "EPMWKS01"

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
        Write-EventLog -LogName "Application" -Source "CyberArk EPM" -EventID 2020 -EntryType Information -Message "EPM Policy Checks Complete - WMI check Failed - Exiting 1" -Category 1 -RawData 10,20
        exit 1;
    }
}
