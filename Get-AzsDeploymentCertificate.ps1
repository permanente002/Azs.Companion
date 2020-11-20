param(
    [parameter(Mandatory = $true)] [string]$TenantId,
    [parameter(Mandatory = $true)] [string]$SubId,
    [parameter(Mandatory = $true)] [string]$KeyVaultName
)

#Elevating PowerShell sesson

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}
if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Your current PowerShell session is running elevated."
}
else {
    Write-Output "The Please elevate your PowerShell session and try again."
    break
}

## Login and set session to the Azure subscription you are working in
$AzContext = Get-AzContext

if ($AzContext.Subscription.Id -eq $SubId ) {
    $SetContext = Set-AzContext -TenantId $TenantId -SubscriptionId $SubId -ErrorAction SilentlyContinue
    if ($null -eq $SetContext) {
        Write-Output "$env:USERNAME current session is not set to the Azure Subscription Id $SubId.  Please login to continue"
        Login-AzAccount -SubscriptionId $SubId -TenantId $TenantId
        Set-AzContext -SubscriptionId $SubId -TenantId $TenantId
        (Get-AzContext).Subscription.Id
        (Get-AzContext).Subscription.Name

    }
    if ($null -ne $SetContext) {

        Write-Output "You appear to be logged in and the current session is set to the Azure Subscription Id '$SubId' "
    }

}
else {
    Write-Output "$env:USERNAME current session is not set to the Azure Subscription Id $SubId.  Please login to continue"
    Login-AzAccount
    Set-AzContext -SubscriptionId $SubId -TenantId $TenantId
    (Get-AzContext).Subscription.Id
    (Get-AzContext).Subscription.Name
}

#Creating cert store
$a = Get-Item Cert:\LocalMachine\Azs
if ($null -eq $a) { New-Item Cert:\LocalMachine\Azs }
if ($null -ne $a) {
    Remove-Item Cert:\LocalMachine\Azs -Recurse -Force
    New-Item Cert:\LocalMachine\Azs
}
###Create Deployment Folder
###
$RegionName = (Get-AzKeyVaultCertificate -VaultName $KeyVaultName | Select-Object -Property 'Name' | Where-Object -Property Name -Match -Value 'BLOB').Name.trim('BLOB')
$AzsDeploymentDate = get-date -Format yyyyMMdd
$AzsDeploymentPath = "C:\AzsDeployment\$RegionName\" + $AzsDeploymentDate
$AzsCertDeploymentPath = $AzsDeploymentPath + '\Certificates'


$checkAzsDeloymentPath = Get-Item -Path $AzsDeploymentPath -ErrorAction SilentlyContinue
$checkAzsCertDeploymentPath = Get-Item -Path $AzsCertDeploymentPath -ErrorAction SilentlyContinue
if ($null -eq $checkAzsDeloymentPath) {
    New-Item -Path $AzsDeploymentPath -ItemType Directory -InformationAction SilentlyContinue
}
if ($null -eq $checkAzsCertDeploymentPath) {
    New-Item -Path $AzsCertDeploymentPath -ItemType Directory -InformationAction SilentlyContinue
    $directories = 'ACSBlob', 'ACSQueue', 'ACSTable', 'Admin Extension Host', 'Admin Portal', 'ARM Admin', 'ARM Public', 'KeyVault', 'KeyVaultInternal', 'Public Extension Host', 'Public Portal'
    $destination = $AzsCertDeploymentPath
    $directories | foreach-Object { New-Item -Path (Join-Path $destination $PSITEM) -ItemType Directory -Force }
}
##
#Getting list of certificates
$AzsCertlist = (Get-AzKeyVaultCertificate -VaultName $KeyVaultName).Name
[string]$date = (Get-Date)
$output = " - Below is the list of certificates that will be downloaded: "
$msg = $date + $output
Write-Output $msg

$AzsCertlist


    
#Downloading Cert from AKV

foreach ($AzsCertName in $AzsCertList) {
    $PfxDlPath = $AzsCertDeploymentPath + "\" + $AzsCertName + ".pfx"

    $cert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $AzsCertName
    $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $cert.Name
    $secretValueText = '';
    $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
    try {
        $secretValueText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
    }
    $secretByte = [Convert]::FromBase64String($secretValueText)
    $x509Cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
    $x509Cert.Import($secretByte, "", "Exportable,PersistKeySet")
    $type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
    $pfxFileByte = $x509Cert.Export($type, $password)

    # Write to a file
    [System.IO.File]::WriteAllBytes($PfxDlPath, $pfxFileByte)

    #Importing to local cert store
    [string]$date = (Get-Date)
    $output = " - Importing the '$AzsCertName' PFX file."
    $msg = $date + $output
    Write-Output $msg
    
    Import-PfxCertificate -Exportable -CertStoreLocation Cert:\LocalMachine\Azs -FilePath $pfxDlPath -Verbose

}
#### Export PFX with password
[string]$date = (Get-Date)
$output = " - Checking the Azure Key Vault '$KeyVaultName' for the PFX password."
$msg = $date + $output
Write-Output $msg
$SecretName = 'PFX-' + $KeyVaultName
$pfxpasswordcheck = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -ErrorAction  SilentlyContinue ).secretvalue

if ($null -ne $pfxpasswordcheck) {
    [string]$date = (Get-Date)
    $output = " - The Azure Key Vault secret is available."
    $msg = $date + $output
    Write-Output $msg
    
    $pfxpassword = $pfxpasswordCheck
    $exportpfxlist = (Get-ChildItem $AzsCertDeploymentPath -Filter *.pfx).Name

    foreach ($pfxname in $exportpfxlist) {
        $pfxfilelocation = $AzsCertDeploymentPath + "\" + $pfxname
        $certThumbprint = (Get-PfxData -FilePath $pfxfilelocation | Select-Object -ExpandProperty EndEntityCertificates).Thumbprint
        [string]$date = (Get-Date)
        $output = " - Exporting '$pfxname' with password"
        $msg = $date + $output
        Write-Output $msg
        
        Get-ChildItem -Path "Cert:\LocalMachine\Azs\$certThumbprint" | Export-PfxCertificate -FilePath $pfxfilelocation -Password $pfxpassword -Verbose
        ## Export path for .PFX files needed for deployments
        if ($pfxname -eq ("$RegionName" + "ADMINHOSTING.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\Admin Extension Host\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "ADMINMANAGEMENT.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\ARM Admin\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "ADMINPORTAL.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\Admin Portal\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "ADMINVAULT.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\KeyVaultInternal\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "BLOB.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\ACSBlob\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "HOSTING.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\Public Extension Host\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "MANAGEMENT.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\ARM Public\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "PORTAL.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\Public Portal\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "QUEUE.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\ACSQueue\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "TABLE.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\ACSTable\$pfxname" }
        if ($pfxname -eq ("$RegionName" + "VAULT.pfx")) { Set-Variable -Name AzsDeployPath -Value "$AzsCertDeploymentPath\KeyVault\$pfxname" }
        [string]$date = (Get-Date)
        $output = " - Moving '$pfxname' to the deployment folder"
        $msg = $date + $output
        Write-Output $msg
        
        move-item -Path $pfxfilelocation -Destination $AzsDeployPath -Force -Verbose

    }

}
$a = Read-Host -Prompt "Do you want to proceed with the Azure Stack Certificate Validation?  Y/N"

if ($a -in ('Y', 'y', 'Yes', 'yes')) {
    if ($null -eq $externalFQDN) { $externalFQDN = Read-Host -Prompt "Please provide the Azure Stack External FQDN" }
    if ($null -eq $RegionName) { $RegionName = Read-Host -Prompt "Please provide the Azure Stack Region Name" }
    Invoke-AzsCertificateValidation -CertificateType deployment -CertificatePath $AzsCertDeploymentPath -ExternalFQDN $externalFQDN -RegionName $RegionName -IdentitySystem AAD -pfxPassword $pfxpassword

}