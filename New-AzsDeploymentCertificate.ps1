<#
.Synopsis
    New-AzsDeploymentCertificate.ps1 | This script will generate the standard set of Azure Stack Deployment Certificate Policies and submit them to an Azure Key Vault to be generated.

.Description
 

    Pre Requisites:  
        1.  Contributor access to the Azure Key Vault Resource Group and Contributor access to the Key Vault.
        2.  Your Azure Key Vault is registered with a Certificate Authority to generate signed certificates.

    This script will generate the standard set of Azure Stack Deployment Certificate Policies and submit them to an Azure Key Vault to be generated.
        
.Parameter TenantId
    Provide the Azure Subscription Tenant Id where the Azure Key Vault will be created.

.Parameter SubId
    Provide the Azure Subscription ID where the Azure Key Vault will be created.

.Parameter issuerName
    Provide the Certificate Authority Issuer name that will be using. (Issuer needs to be registered and on the list of available CAs in Azure Key Vault) 

    E.g. "RegionName"  + "External-FQDN.com" will create a Key Vault Name value of "RegionNameExternalFQDN"
.Parameter RegionName
    Provide the Azure Stack region name.  If a Region Name and External FQDN are provided.  A unique Key Vault name will be created based on the two joined values. Both a Region Name and External FQDN will need to be provided in order to auto generate a unique name. 

    E.g. "RegionName"  + "External-FQDN.com" will create a Key Vault Name value of "RegionNameExternalFQDN"

.Parameter externalFQDN

Provide the Azure Stack External FQDN.  If a Region Name and External FQDN are provided.  A unique Key Vault name will be created based on the two joined values.  Both a Region Name and External FQDN will need to be provided in order to auto generate a unique name.

    E.g. "RegionName"  + "External-FQDN.com" will create a Key Vault Name value of "RegionNameExternalFQDN"

.Parameter KeyVaultName
Provide an Azure Key Vault Name if you do not one auto generated based on Region Name and External FQDN.

.Parameter KeyVaultRgName
Provide the Key Vault Resource Group Name.  
If an existing Resource Group Name is provided.  The Key Vault will be created in the Resource Group name provided.
If the Resource Group Name does not exist.  A new Resource Group will be created.


.example 

    Example 1 
    
    
.example

    Example 2


.link
https://docs.microsoft.com/en-us/azure/key-vault/general/overview
https://docs.microsoft.com/en-us/azure/key-vault/certificates/about-certificates
https://docs.microsoft.com/en-us/azure-stack/operator/azure-stack-pki-certs?view=azs-2008
https://docs.microsoft.com/en-us/azure-stack/operator/azure-stack-validate-registration?view=azs-2008&tabs=az
#>

param(
    [parameter(Mandatory = $true)] [string]$TenantId,
    [parameter(Mandatory = $true)] [string]$SubId,
    [parameter(Mandatory = $true)] [string]$issuerName,
    [parameter(Mandatory = $true)] [string] $KeyVaultRgName,
    [parameter(Mandatory = $false)] [string]$RegionName,
    [parameter(Mandatory = $false)] [string]$externalFQDN,
    [parameter(Mandatory = $false)] [string]$KeyVaultName
    
)




#https://docs.microsoft.com/en-us/azure-stack/operator/azure-stack-validate-pki-certs?view=azs-2005
#Need to create paramaters for the below

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

#Standard naming convetion for Vault Name if Region name and External FQDN are provided.
if ('0' -eq $KeyVaultName.Length) {
    $RegionName = $RegionName.TrimStart('.')
    $externalFQDN = $externalFQDN.TrimStart('.')
    $a = $RegionName -replace "-"
    $b = $externalFQDN -replace "-"
    $c = $a + $b
    [array] $array = $c -Split ('\.')
    $arrcount = ($array.Count) - 2
    [string]$KeyVaultName = $array[0..$arrcount] -join ""
}

$AzsCertList = ("*.blob",
    "*.queue",
    "*.table",
    "*.adminhosting",
    "*.vault",
    "*.adminvault",
    "*.hosting",
    "adminportal",
    "adminmanagement",
    "management",
    "portal")
    
#Check if AKV exist.

if ('0' -ne $KeyVaultName.Length) {
    [string]$date = (Get-Date)
    $output = " - The Key Vault Name '$KeyVaultName' was provided.  Checking if the Key Vault Name '$KeyVaultName' exist."
    $msg = $date + $output
    Write-Output $msg
    
    $CheckAkvName = (Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultRgName -ErrorAction SilentlyContinue).VaultName
    if ($null -ne $CheckAkvName) {
        [string]$date = (Get-Date)
        $output = " - Key Vault Name $KeyVaultName exist."
        $msg = $date + $output
        Write-Output $msg 
        
    }
    if ($null -eq $CheckAkvName) {
        [string]$date = (Get-Date)
        $output = " - Key Vault Name $KeyVaultName does not exist.  Please check the spelling of the Region Name and FQDN or the Key Vault name provided and try again.."
        $msg = $date + $output
        Write-Output $msg
        
    }
}


#Check if CA proivder is available.

$ChkCaIssuer = Get-AzKeyVaultCertificateIssuer -VaultName $KeyVaultName | Where-Object { $_.Name -eq $issuerName -or $_.IssuerProvider -eq $issuerName }

if ($null -eq $ChkCaIssuer) {
    [string]$date = (Get-Date)
    $output = " - The Certificate Authority with the name $issuerName does not exist.  Proceeding to add the provider $issuerName."
    $msg = $date + $output
    Write-Output $msg
    
    Set-AzKeyVaultCertificateIssuer -VaultName $KeyVaultName -Name $issuerName -IssuerProvider $issuerName
    start-sleep 10
    [string]$date = (Get-Date)
    $output = " - The below CA provider was successfully created."
    $msg = $date + $output
    Write-Output $msg
    
    Get-AzKeyVaultCertificateIssuer -VaultName $KeyVaultName  -Name $issuerName
}
if ($nul -ne $ChkCaIssuer) {
    [string]$date = (Get-Date)
    $output = " - The below CA provider will be used to generate the new certificate."
    $msg = $date + $output
    Write-Output $msg
    
    $ChkCaIssuer
}
    


#Check if Certificates exist.  



### Checking to see if the Certname exist and removing if needed
$datetime = get-date -Format yyMMddhhmm
foreach ($AzsCert in $AzsCertList) {
    $CertName = $RegionName.ToLower() + $AzsCert.Trim("*.").ToUpper()

    $checkCertName = (Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $certname -ErrorAction SilentlyContinue).Name 
    if ($CertName -ne $checkCertName) { 
        [string]$date = (Get-Date)
        $output = " - The certifate name '$CertName' does not exist."
        $msg = $date + $output
        Write-Output $msg
    }
    if ($CertName -eq $checkCertName) {
        [string]$date = (Get-Date)
        $output = " - Skipping OEM VM login detail creation."
        $msg = $date + $output
        Write-Output $msg
        
    
        $a = read-host -Prompt "Proceed with delete Y/N"
    
        if ($a -in ('Yes', 'Y', 'y')) {
            [string]$date = (Get-Date)
            $output = " - Deleting the certificate '$CertName' from the '$KeyVaultName' Azure Key Vault."
            $msg = $date + $output
            Write-Output $msg
            
            Remove-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertName -Force -Verbose
            Start-Sleep -Seconds 10
            Remove-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertName -InRemovedState -Force -Verbose
    
            $b = (Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $certname -ErrorAction SilentlyContinue).Name
            if ($null -eq $b) { 
                [string]$date = (Get-Date)
                $output = " - The certificate was successfully deleted.  Proceeding with new certificate creation."
                $msg = $date + $output
                Write-Output $msg
            }
            if ($null -ne $b) { 
                [string]$date = (Get-Date)
                $output = " - The certificate still exist."
                $msg = $date + $output
                Write-Output $msg
            }
        }
        if ($a -notin ('Yes', 'Y', 'y')) {
            [string]$date = (Get-Date)
            $output = " - NO CERTIFICATES DELETED."
            $msg = $date + $output
            Write-Output $msg
            
        }
    }

}


### Certificate Creation

foreach ($AzsCert in $AzsCertList) {
    $CertName = $RegionName.ToLower() + $AzsCert.Trim("*.").ToUpper()
    $checkCertName = (Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $certname -ErrorAction SilentlyContinue).Name

    if ($CertName -eq $checkCertName) {
        $newcertname = $certname + $datetime
        [string]$date = (Get-Date)
        $output = " - A certificate with the name '$CertName' already exists in the '$KeyVaultName' Azure Key Vault.  A new certifacate with the name '$newcertname' will be created."
        $msg = $date + $output
        Write-Output $msg
        
        $CertSubjectName = "CN=" + "$AzsCert" + "." + "$RegionName" + "." + "$externalFQDN"
        $CertAltName = "$AzsCert" + "." + "$RegionName" + "." + "$externalFQDN"

        Set-AzKeyVaultCertificateIssuer -VaultName $KeyVaultName -IssuerProvider $providerName -Name $issuerName -Verbose
        $policy = New-AzKeyVaultCertificatePolicy `
            -SubjectName $CertSubjectName `
            -IssuerName $issuerName `
            -ValidityInMonths 12 `
            -RenewAtNumberOfDaysBeforeExpiry 60 `
            -DnsName @("$CertAltName") `
            -Verbose
        Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $newcertname -CertificatePolicy $policy -Verbose 
    }
    if ($CertName -ne $checkCertName) {
        $CertSubjectName = "CN=" + "$AzsCert" + "." + "$RegionName" + "." + "$externalFQDN"
        $CertAltName = "$AzsCert" + "." + "$RegionName" + "." + "$externalFQDN"

        Set-AzKeyVaultCertificateIssuer -VaultName $KeyVaultName -IssuerProvider $providerName -Name $issuerName
        $policy = New-AzKeyVaultCertificatePolicy `
            -SubjectName $CertSubjectName `
            -IssuerName $issuerName `
            -ValidityInMonths 12 `
            -RenewAtNumberOfDaysBeforeExpiry 60 `
            -DnsName @("$CertAltName") `
            -Verbose
        Add-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertName -CertificatePolicy $policy -Verbose
    }

}
start-sleep -Seconds 45

### Checking cert creation progress
foreach ($AzsCert in $AzsCertList) {
    $CertName = $RegionName.ToLower() + $AzsCert.Trim("*.").ToUpper()
    $newcertname = $certname + $datetime
    $checkforNewCertName = (Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $newcertname).Name

    if ($null -eq $checkforNewCertName) {
        $CertName = $RegionName.ToLower() + $AzsCert.Trim("*.").ToUpper() + $currentDate
        Get-AzKeyVaultCertificateOperation -VaultName $KeyVaultName -Name $certname -Verbose | Format-Table -Property Name, Status, Target
    }
    if ($null -ne $checkforNewCertName) {
        Get-AzKeyVaultCertificateOperation -VaultName $KeyVaultName -Name $newcertname -Verbose | Format-Table -Property Name, Status, Target
    }
}
