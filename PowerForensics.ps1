
#Title Bar Function
Function Get-TitleBar ($Title, $BorderChar="-", $ForeColor = "Yellow", $BackColor = "Black") {
    $ColorSplat = @{ForegroundColor = $ForeColor; BackgroundColor = $BackColor}
    $border = $BorderChar * ($title.length +4)
    $gap = " " * (($host.UI.RawUI.windowsize.width/2)-($title.length/2)-2)
    $gap2 = " " * ((($host.UI.RawUI.windowsize.width/2)-($title.length/2)-2)-1)
    Write-Host
    Write-Host "$gap$border$gap2" @ColorSplat
    Write-Host "$gap| $title |$gap2" @ColorSplat
    Write-Host "$gap$border$gap2" @ColorSplat
    Write-Host
}

Get-TitleBar "Win7PowerShellForensics" 

If (-NOT ([bool]((whoami /all) -match "S-1-16-12288"))){
  Write-Warning "$($Env:Username) is not an Administrator! Attempting to elevate the Script"
  start-sleep (3); 
  write-host ("`a"*4)
   $arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
} 
#Clipboard_Last_Item

function Get-ClipboardText{
	Add-Type -AssemblyName 'PresentationCore'
	Write-Output ([System.Windows.Clipboard]::GetText())
}
echo --------------------- Last Item on the clipboard-----------------
Get-ClipboardText | Out-String

#Manufacturer_Info
echo -------------Bios Information-------------
gwmi win32_bios



#MRU_Domain_Users_Last_Login
echo -------------Domain_User_Logins-------------
if (Get-Module -ListAvailable -Name ActiveDirectory) {
   foreach ($User in Get-ADUser -Filter * -Properties *)
{   
    $TimeSpan = "{0:dd\:hh\:mm\:ss}" -f ([timespan]::fromticks($User.'msDS-LastSuccessfulInteractiveLogonTime' - $User.'msDS-LastFailedInteractiveLogonTime'))
    $LastFailedLogon= [datetime]::FromFileTime($User.'msDS-LastFailedInteractiveLogonTime')
    $LastSuccessfulLogon= [datetime]::FromFileTime($User.'msDS-LastSuccessfulInteractiveLogonTime')   
    @{"User" = $User.Name; "Last failed logon" = $LastFailedLogon; "Last successfull logon" = $LastSuccessfulLogon; "Time span" = $TimeSpan }.GetEnumerator() | Sort -Descending -Property Name | Format-Table
}

} else {
    Write-Host "Active Directory Not Available"
}

#Installed_Applications
echo -------------Installed_Applications-------------

Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall |Out-String

#Running_Unique_Processes
echo -------------Running_Unique_Processes-------------
Get-Process | Get-Unique | Out-String

#Services_Sorted_by _Status
echo -------------Services-------------
Get-Service | Sort-Object Status | Out-String

#Basic_Windows_Info
echo -------------Basic Windows Info-------------
  Write-Host -NoNewLine "OS Version: "

  Get-CimInstance Win32_OperatingSystem | Select-Object  Caption | ForEach{ $_.Caption }

  Write-Host ""

Write-Host -NoNewLine "Install Date: "

  Get-CimInstance Win32_OperatingSystem | Select-Object  InstallDate | ForEach{ $_.InstallDate }

  Write-Host ""

Write-Host -NoNewLine "Service Pack Version: "

  Get-CimInstance Win32_OperatingSystem | Select-Object  ServicePackMajorVersion | ForEach{ $_.ServicePackMajorVersion }

  Write-Host ""

Write-Host -NoNewLine "OS Architecture: "

  Get-CimInstance Win32_OperatingSystem | Select-Object  OSArchitecture | ForEach{ $_.OSArchitecture }

  Write-Host ""

Write-Host -NoNewLine "Boot Device: "

  Get-CimInstance Win32_OperatingSystem | Select-Object  BootDevice | ForEach{ $_.BootDevice }

  Write-Host ""

Write-Host -NoNewLine "Build Number: "

  Get-CimInstance Win32_OperatingSystem | Select-Object  BuildNumber | ForEach{ $_.BuildNumber }

  Write-Host ""

Write-Host -NoNewLine "Host Name: "

  Get-CimInstance Win32_OperatingSystem | Select-Object  CSName | ForEach{ $_.CSName }

  Write-Host ""

#Get_Fresh_Event_Logs
echo -------------Get_Fresh_Event_Logs-------------
Get-EventLog application -Newest 30 | Out-String

#Storage and USB
echo -------------STORAGE_DEVICES-------------
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR" |Select-Object Name | Out-String
echo -------------USB_DEVICES-------------
Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\usbflags" |Select-Object Name | Out-String
#Startup
echo -------------STARTUP-------------
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" | Out-String
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" | Out-String
#IE
echo -------------IE_Typed_URLs-------------
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs" | Out-String
#Network
echo -------------Network_Connections-------------
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet\*" |Select-Object PSChildName | Out-String
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*"|Select-Object ProfileName, Description | Out-String
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\UnManaged\*" |Select-Object Description, FirstNetwork, DnsSuffix | Out-String
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\*" |Select-Object Description, FirstNetwork, DnsSuffix | Out-String
#MRU
echo -------------Most_Recently_Used-------------
echo -------------Most_Recently_Ran_Commands-------------
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" | Out-String
echo -------------Most_Recently_Typed_Paths-------------
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" | Out-String

#MRU_Office
echo -------------Most_Recently_Opened_Files_with_Microsoft_Office_Products-------------
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\*.0\*\File MRU" | Out-String
echo -------------Most_Recent_Save_Locations_used_with_Microsoft_Office_Products-------------
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\*.0\*\Place MRU" | Out-String
#WMI_Backdoor_Check
echo -----------------WMI_Backdoor_Check----------------------------------
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding

#Dump Dns History
echo ------------------------Internet_Browser_History---------------------------
ipconfig /displaydns | select-string 'Record Name' | foreach-object { $_.ToString().Split(' ')[-1]   } | Sort | Out-String

Write-Host "Press any key to continue ..."

$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host
Write-Host "1"
Write-Host "2"
Write-Host "3"
Write-Host "Bye Bye"
