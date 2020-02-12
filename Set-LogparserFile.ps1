$ADSite="$(([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name)"
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
$Servers = GetExchServer -Roles 4,36,38,54,16439,16385 -ADSite $ADSite

#$Servers.properties.name

$w3svcFront="C$\inetpub\logs\LogFiles\W3SVC1"
$w3svcBack="C$\inetpub\logs\LogFiles\W3SVC2"
$HttpProxyAutoDiscover="Logging\HttpProxy\Autodiscover"
$HttpProxyEas="Logging\HttpProxy\Eas"
$HttpProxyEcp="Logging\HttpProxy\Ecp"
$HttpProxyEws="Logging\HttpProxy\Ews"
$HttpProxyMapi="Logging\HttpProxy\Mapi"
$HttpProxyOab="Logging\HttpProxy\Oab"
$HttpProxyOwa="Logging\HttpProxy\Owa"
$HttpProxyOwaCalendar="Logging\HttpProxy\OwaCalendar"
$HttpProxyPowershell="Logging\HttpProxy\Powershell"
$HttpProxyRest="Logging\HttpProxy\Rest"
$HttpProxyRpcHttp="Logging\HttpProxy\RpcHttp"
$MessageTracking="TransportRoles\Logs\MessageTracking"
$FrontEndConnectivity="TransportRoles\Logs\FrontEnd\Connectivity"
$FrontEndSMTPReceive="TransportRoles\Logs\FrontEnd\ProtocolLog\SmtpReceive"
$FrontEndSMTPSend="TransportRoles\Logs\FrontEnd\ProtocolLog\SmtpSend"





