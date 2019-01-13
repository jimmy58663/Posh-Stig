<#
    Expected input is an array of custom PSObjects with the below properties:

    Hostname, IP, MAC, FQDN, Role, ObjectType, Vulnerabilities@{ VulnNum, Finding, Status, Comments }
#>

Function Out-StigCKL{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0)]
        [String]$FolderPath="$PSScriptRoot",
        [Parameter(Position=1,ValueFromPipeline=$true)]
        [PSObject[]]$InputObject
    )
    BEGIN{
        if (-not (Test-Path $FolderPath)){
            New-Item -Path $FolderPath -ItemType Directory -Force
        }
    }

    PROCESS{
        ForEach($Obj in $InputObject){

            Switch ($Obj.ObjectType){
                'VMware-VM'{
                    $FolderPath = $FolderPath + "\Virtual_Machine_STIG\"
                    $BlankCklName = 'Blank_VM6_STIG_V1_R1.ckl'
                }

                'ESXi'{
                    $FolderPath = $FolderPath + "\ESXi_STIG\"
                    $BlankCklName = 'Blank_ESXi60_STIG_V1_R4.ckl'            
                }

                'Windows2012R2'{
                    $FolderPath = $FolderPath + "\Windows_STIG\"
                    $BlankCklName = 'Blank_Windows2012R2_STIG_V2_R12.ckl'
                }

                'Windows2016'{
                    $FolderPath = $FolderPath + "\Windows_STIG\"
                    $BlankCklName = 'Blank_Windows2016_STIG_V1_R4.ckl'
                }

                'Default'{
                    $WShell = New-Object -ComObject Wscript.Shell
                    $IntButton = $WShell.Popup("The object type of the input object is not supported.",0,"Unsupported Object Type",0)
                    if ($IntButton -eq '1'){
                        exit
                    }
                }
            }

            $BlankCklPath = $FolderPath + $BlankCklName

            $CklName = $Obj.Hostname + ".ckl"
            $CklPath = $FolderPath + $CklName
            if (Test-Path $CklPath){
                $Xml = (Select-Xml -Path $CklPath -XPath / ).Node
            }
            else{
                if (Test-Path $BlankCklPath){
                    $Xml = (Select-Xml -Path $BlankCklPath -XPath / ).Node
                }
                else{
                    $WShell = New-Object -ComObject Wscript.Shell
                    $IntButton = $WShell.Popup("You are missing the blank checklist file. Please create a file at the following location: $blankcklpath with the correct name: $blankcklname",0,"Missing CKL File",0)
                    if ($IntButton -eq '1'){
                        exit
                    }
                }   
            }

            $Xml.CHECKLIST.ASSET.HOST_NAME = $Obj.Hostname.ToString()
            $Xml.CHECKLIST.ASSET.HOST_IP = $Obj.IPAddress.ToString()
            $Xml.CHECKLIST.ASSET.HOST_MAC = $Obj.MACAddress.ToString()
            $Xml.CHECKLIST.ASSET.HOST_FQDN = $Obj.FQDN.ToString()
            $Xml.CHECKLIST.ASSET.ROLE = $Obj.Role.ToString()

            $Vulns = $Xml.CHECKLIST.STIGS.iSTIG.VULN
            $Index = 0..($Vulns.Length - 1)

            ForEach ($i in $Index){
                $VulnNum = $Vulns[$i].STIG_DATA[0].ATTRIBUTE_DATA
                $XmlVuln = $Vulns[$i]
                $VulnInfo = $Obj.Vulnerabilities | Where-Object {$PSItem.VulnNum -eq $VulnNum}
                If ($VulnInfo){
                    $XmlVuln.FINDING_DETAILS = $VulnInfo.Finding.ToString()
                    $XmlVuln.STATUS = $VulnInfo.Status.ToString()
                    $XmlVuln.COMMENTS = $VulnInfo.Comments.ToString()
                }
            }

            $Xml.Save($CklPath)
        }
    }

    END{
    }
}