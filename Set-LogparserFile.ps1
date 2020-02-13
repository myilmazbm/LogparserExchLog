

[CmdletBinding(DefaultParameterSetName = "ALL")]
param(
    [parameter( Mandatory=$false)]
    [string]$ADSite="$(([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name)",
    
	[parameter( Mandatory=$false)]
    [boolean]$w3svcFront=$false,
	
	[parameter( Mandatory=$false)]
    [boolean]$w3svcBack=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyAutoDiscover=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyEas=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyEcp=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyEws=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyMapi=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyOab=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyOwa=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyOwaCalendar=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyPowershell=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyRest=$false,

	[parameter( Mandatory=$false)]
    [boolean]$HttpProxyRpcHttp=$false,

	[parameter( Mandatory=$false)]
    [boolean]$MessageTracking=$false,

	[parameter( Mandatory=$false)]
    [boolean]$FrontEndConnectivity=$false,

	[parameter( Mandatory=$false)]
    [boolean]$FrontEndSMTPReceive=$false,

	[parameter( Mandatory=$false)]
    [boolean]$FrontEndSMTPSend=$false,
	
	[parameter( Mandatory=$false)]
    [DateTime] $start = [DateTime]::Today,
	
	[parameter( Mandatory=$false)]
    [DateTime] $end = $start.adddays(1)
)

Function Set-LogparserFile{

	function GetExchServer {
		#http://technet.microsoft.com/en-us/library/bb123496(v=exchg.80).aspx on the bottom there is a list of values
		param([array]$Roles,[string]$ADSite)
		Process {
			$valid = @("2","4","16","20","32","36","38","54","64","16385","16439")
			ForEach ($Role in $Roles){
				If (!($valid -contains $Role)) {
					Write-Output -fore red "Please use the following numbers: MBX=2,CAS=4,UM=16,HT=32,Edge=64 multirole servers:CAS/HT=36,CAS/MBX/HT=38,CAS/UM=20,E2k13 MBX=54,E2K13 CAS=16385,E2k13 CAS/MBX=16439"
					Break
				}
			}
			Function GetADSite {
				param([string]$Name)
				If (!($Name)) {
					[string]$Name = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name
				}
				$FilterADSite = "(&(objectclass=site)(Name=$Name))"
				$RootADSite= ([ADSI]'LDAP://RootDse').configurationNamingContext
				$SearcherADSite = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$RootADSite")
				$SearcherADSite.Filter = "$FilterADSite"
				$SearcherADSite.pagesize = 1000
				$ResultsADSite = $SearcherADSite.FindOne()
				$ResultsADSite
			}
			$Filter = "(&(objectclass=msExchExchangeServer)(msExchServerSite=$((GetADSite -Name $ADSite).properties.distinguishedname))(|"
			ForEach ($Role in $Roles){
				$Filter += "(msexchcurrentserverroles=$Role)"
			}
			$Filter += "))"
			$Root= ([ADSI]'LDAP://RootDse').configurationNamingContext
			$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Root")
			$Searcher.Filter = "$Filter"
			$Searcher.pagesize = 1000
			$Results = $Searcher.FindAll()
			$Results
		}
	}

	function CreateFoldernames {
		param([string]$file,[array]$servers)
		$folders = @()
		if ($file -like "C$*"){
			foreach ($server in $servers){
				$folders += "\\" + ($server.properties.name) + "\" + $file
			}
		}
		else
		{
			foreach ($server in $servers){
				$folders += "\\" + ($server.properties.name) + "\" + ($server.properties.msexchinstallpath).replace("C:\","C$\") + "\" + $file
			}
		}
		$folders
	}
	
	function ForLPS{
		param(
			[DateTime] $start = [DateTime]::Today,
			[DateTime] $end = $start.adddays(1),
			[Array] $folders
		)
		$files = @()
		
		foreach($folder in $folders){
			$files += (gci $folder | where { $_.LastWriteTime -gt $start -and $_.LastWriteTime -lt $end }).FullName
		}
		
		function LPLogFileCreate{
			param($files)
			$result=""
			foreach($file in $files){
				$result+="  <LPLogFile>`r`n"
				$result+="    <Filename>"+$file+"</Filename>`r`n"
				$result+="    <isChecked>true</isChecked>`r`n"
				$result+="  </LPLogFile>`r`n"
			}
			$result
		}
		
		$result = '<?xml version="1.0" encoding="utf-8"?>'+"`r`n"+'<ArrayOfLPLogFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">'+"`r`n"+(LPLogFileCreate -files $files)+'</ArrayOfLPLogFile>'
		$result | Set-Content -Path "$env:USERPROFILE\AppData\Roaming\ExLPT\Log Parser Studio\LPSFolders.tmp" -Encoding utf8
	}
	
	$Servers = GetExchServer -Roles 4,36,38,54,16439,16385 -ADSite $ADSite
	#$Servers.properties.name

	$FolderArray=@()

	if($w3svcFront){ $FolderArray = CreateFoldernames -file "C$\inetpub\logs\LogFiles\W3SVC1" -servers  $servers }
	elseif($w3svcBack){ $FolderArray = CreateFoldernames -file "C$\inetpub\logs\LogFiles\W3SVC2" -servers  $servers }
	elseif($HttpProxyAutoDiscover) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Autodiscover" -servers  $servers }
	elseif($HttpProxyEas) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Eas" -servers  $servers }
	elseif($HttpProxyEcp) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Ecp" -servers  $servers }
	elseif($HttpProxyEws) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Ews" -servers  $servers }
	elseif($HttpProxyMapi) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Mapi" -servers  $servers }
	elseif($HttpProxyOab){ $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Oab" -servers  $servers }
	elseif($HttpProxyOwa) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Owa" -servers  $servers }
	elseif($HttpProxyOwaCalendar) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\OwaCalendar" -servers  $servers }
	elseif($HttpProxyPowershell) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Powershell" -servers  $servers }
	elseif($HttpProxyRest) { $FolderArray = CreateFoldernames -file "Logging\HttpProxy\Rest" -servers  $servers }
	elseif($HttpProxyRpcHttp){ $FolderArray = CreateFoldernames -file "Logging\HttpProxy\RpcHttp" -servers  $servers }
	elseif($MessageTracking){ $FolderArray = CreateFoldernames -file "TransportRoles\Logs\MessageTracking" -servers  $servers }
	elseif($FrontEndConnectivity) { $FolderArray = CreateFoldernames -file "TransportRoles\Logs\FrontEnd\Connectivity" -servers  $servers }
	elseif($FrontEndSMTPReceive) { $FolderArray = CreateFoldernames -file "TransportRoles\Logs\FrontEnd\ProtocolLog\SmtpReceive" -servers  $servers }
	elseif($FrontEndSMTPSend) { $FolderArray = CreateFoldernames -file "TransportRoles\Logs\FrontEnd\ProtocolLog\SmtpSend" -servers  $servers }
	
	forlps -folders $FolderArray
}

Set-LogparserFile