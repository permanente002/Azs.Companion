<#
.Synopsis
    New-AzsE2EDeploymentCertificate.ps1 | This script will create a new Azure Key Vault, Generate Azure stack Deployment Certificates, and  download them to your local machine for deployment.

.Description

     

    Pre Requisites:  
        Contributor access to the Azure Subscription where you plan to store Certificates and Secrets.
        Certifate Authority issuer/provider setup to sign your certificates.
        Latest Azure Stack Readiness checker powershell module installed (optional)
    
    This script will will do the following:
        
        Create an Azure Key Vault to store Azure Stack Certificates and Secrets.
        Generate Azure Stack Deployment Certificate policies and submit them to Azure Key Vault for generation.  (If you have a working CA provider is setup a signed certificate will be generated).
        Download the certificates to your local server
        Import/Export the certficate with a PFX password.  (By default when you download a certificate from Azure Key Vault there is no password.)
        Copy the PFX (w/ Password) to the required deployment folder.
        Prompt you to validate the certificate.  (requires the Azure Stack Readiness checker module to be installed.)

    The script will prompt for login details to the following accounts:

        HLH Account
        BMC Account
        Certificate PFX password
        PEP Azs Domain Account & Credentials
        OEM VM login details
    

.Parameter TenantId
    Provide the Azure Subscription Tenant Id where the Azure Key Vault will be created.

.Parameter SubId
    Provide the Azure Subscription ID where the Azure Key Vault will be created.

.Parameter IssuerName
    Provide the Azure Key Vault Issuer Name that will be used to issue the new certificates.

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

.Parameter AzLocation
Provide the Azure Location where you want to deploy the new Key Vault.  The default value is 'eastus2' if a value is not provided.

.example 

  
    
.example

    

.example

    


.link
https://docs.microsoft.com/en-us/azure/key-vault/general/overview
https://docs.microsoft.com/en-us/azure/key-vault/certificates/about-certificates
https://docs.microsoft.com/en-us/azure-stack/operator/azure-stack-pki-certs?view=azs-2008
https://docs.microsoft.com/en-us/azure-stack/operator/azure-stack-validate-registration?view=azs-2008&tabs=az

#>

param (
    [parameter(Mandatory = $true)] [string]$TenantId,
    [parameter(Mandatory = $true)] [string]$SubId,
    [parameter(Mandatory = $true)] [string]$KeyVaultRgName,
    [parameter(Mandatory = $true)] [string]$issuerName,
    [parameter(Mandatory = $false)] [string]$RegionName,
    [parameter(Mandatory = $false)] [string]$externalFQDN,
    [parameter(Mandatory = $false)] [string]$KeyVaultName,
    [parameter(Mandatory = $false)] [string]$AzLocation
    
)
#


###Elevating PowerShell sesson

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Output "The Please elevate your PowerShell session and try again.  " 
    break
}

if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Your current PowerShell session is running elevated."
}

$RegionName = $RegionName.ToLower()
$externalFQDN = $externalFQDN.ToLower()
$KeyVaultName = $KeyVaultName.ToLower()
if ('0' -eq $AzLocation.Length) { $AzLocation = 'eastus2' }

### Login and set session to the Azure subscription you are working in
$AzContext = Get-AzContext

if ($AzContext.Subscription.Id -eq $SubId ) {
    $SetContext = Set-AzContext -TenantId $TenantId -SubscriptionId $SubId -ErrorAction SilentlyContinue
    if ($null -eq $SetContext) {
        Write-Warning "$env:USERNAME current session is not set to the Azure Subscription Id $SubId.  Please login to continue"
        Login-AzAccount -SubscriptionId $SubId -TenantId $TenantId
        Set-AzContext -SubscriptionId $SubId -TenantId $TenantId
        (Get-AzContext).Subscription.Id
        (Get-AzContext).Subscription.Name

    }
    if ($null -ne $SetContext) {

        Write-Host "You appear to be logged in and the current session is set to the Azure Subscription Id '$SubId'" -ForegroundColor Yellow
    }

}
else {
    Write-Warning "$env:USERNAME current session is not set to the Azure Subscription Id $SubId.  Please login to continue"
    Login-AzAccount
    Set-AzContext -SubscriptionId $SubId -TenantId $TenantId
    (Get-AzContext).Subscription.Id
    (Get-AzContext).Subscription.Name
}
### Starting New Key Vault creation process.


$RegionName = $RegionName.ToLower()
$externalFQDN = $externalFQDN.ToLower()
$global:KeyVaultName = $KeyVaultName.ToLower()
if ('0' -eq $AzLocation.Length) { $AzLocation = 'eastus2' }

## Login and set session to the Azure subscription you are working in
$AzContext = Get-AzContext

if ($AzContext.Subscription.Id -eq $SubId ) {
    $SetContext = Set-AzContext -TenantId $TenantId -SubscriptionId $SubId -ErrorAction SilentlyContinue
    if ($null -eq $SetContext) {
        Write-Warning "$env:USERNAME current session is not set to the Azure Subscription Id $SubId.  Please login to continue"
        Login-AzAccount -SubscriptionId $SubId -TenantId $TenantId
        Set-AzContext -SubscriptionId $SubId -TenantId $TenantId
        (Get-AzContext).Subscription.Id
        (Get-AzContext).Subscription.Name

    }
    if ($null -ne $SetContext) {

        Write-Host "You appear to be logged in and the current session is set to the Azure Subscription Id '$SubId'" -ForegroundColor Yellow
    }

}
else {
    Write-Warning "$env:USERNAME current session is not set to the Azure Subscription Id $SubId.  Please login to continue"
    Login-AzAccount
    Set-AzContext -SubscriptionId $SubId -TenantId $TenantId
    (Get-AzContext).Subscription.Id
    (Get-AzContext).Subscription.Name
}
# Checking to see if the Resource Group exist.  Creating if it does not.
[string]$date = (Get-Date)
$output = " - Checking if the Resource Group name $KeyVaultRgName exist. "
$msg = $date + $output
Write-Output $msg

$CheckRgName = Get-AzResourceGroup -Name $KeyVaultRgName -ErrorAction SilentlyContinue
if ($null -ne $CheckRgName){
    [string]$date = (Get-Date)
    $output = " - The Resource Group name $KeyVaultRgName exist. "
    $msg = $date + $output
    Write-Output $msg
}

if ($null -eq $CheckRgName) {
    Write-Warning "The resource group name '$KeyVaultRgName' does not exist."
    $a = read-host -Prompt "Do you wan to proceed with creating a new Resource Group Y/N ?"
    
    if ($a -in ('Yes', 'Y', 'y')) {
        [string]$date = (Get-Date)
        $output = " - Proceeding to create the '$KeyVaultRgName' resource group"
        $msg = $date + $output
        Write-Output $msg
        
        New-AzResourceGroup -Name $KeyVaultRgName -Location $AzLocation
        Start-Sleep -Seconds 10
        $Stoploop = $false
        [int]$Retrycount = "0"
        $RetryWaitSecs = '60'
        
        Do {
            $RetryCount = $RetryCount + 1
            Try {
                [string]$date = (Get-Date)
                $output = " - Checking the state of Azure Resource Group creation."
                $msg = $date + $output
                write-output $msg

                $State = (Get-AzResourceGroup -Name $KeyVaultRgName -ErrorAction SilentlyContinue).ProvisioningState
                if ($state -ne 'Succeeded') { Throw "Azure Resource Group provisioning is still pending" }

                [string]$date = (Get-Date)
                $output = " - Azure Resource Group $KeyVaultRgName was created successfully."
                $msg = $date + $output
                write-output $msg
                $Stoploop = $true
            } 
        
            Catch {
                if ($Retrycount -gt 5) {
                    [string]$date = (Get-Date)
                    $output = " - Azure failed to succesfully create a new Resource Group in 5 minutes."
                    $msg = $date + $output
                    Write-Output $msg
                    $Stoploop = $true
                }
                else {
                    [string]$date = (Get-Date)
                    $output = " - The Azure Resource Group provisioning is still in progress. Checking status again in $RetryWaitSecs seconds."
                    $msg = $date + $output
                    write-output $msg   
                    start-sleep -Seconds $RetryWaitSecs
                    $Retrycount = $Retrycount + 1
                }
            }
        }
        While ($Stoploop -eq $false)
    }
    if ($a -notin ('Yes', 'Y', 'y')) {
        [string]$date = (Get-Date)
        $output = " - An Azure Resource Group is required in order create an Azure Key Vault.  Please retry with a valid Resoure Group name."
        $msg = $date + $output
        write-output $msg
        Break
    }
}

# Checking if Keyvault Name or Region and FQDN parameters were provided.
$AzSubscriptionName = (Get-AzContext -ErrorAction SilentlyContinue).Subscription.Name
## Creating AKV based on KeyVaultName parameters that were provided.
if ('0' -ne $KeyVaultName.Length) {
    [string]$date = (Get-Date)
    $output = " - The Key Vault Name '$KeyVaultName' was provided.  Checking to see if this Key Vault Exist."
    $msg = $date + $output
    write-output $msg
    
    $CheckAkvName = (Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultRgName -ErrorAction SilentlyContinue).VaultName
    if ($null -ne $CheckAkvName) {
        
        Write-Warning "Key Vault Name $KeyVaultName exist.  Please check the name again and provide a name that is not in use."
        Break
    }
    if ($null -eq $CheckAkvName) {
        [string]$date = (Get-Date)
        $output = " - Key Vault Name $KeyVaultName does not exist.  Proceeding with Key Vault creation."
        $msg = $date + $output
        write-output $msg
        
        New-AzKeyVault -Name $KeyVaultName -ResourceGroupName $KeyVaultRgName -Location "$AzLocation"  -Verbose
        Start-Sleep -Seconds 10
        Do {
            $RetryCount = $RetryCount + 1
            Try {
                [string]$date = (Get-Date)
                $output = " - Checking if the Key Vault '$KeyVaultName' is available."
                $msg = $date + $output
                write-output $msg
        
                $State = (Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultRgName -Verbose -ErrorAction SilentlyContinue).VaultName
                if ($state -ne $KeyVaultName) { Throw "Azure Key Vault provisioning is still pending" }
                [string]$date = (Get-Date)
                $output = " - The Azure Key Vault $KeyVaultName was created successfully."
                $msg = $date + $output
                write-output $msg
            
                $Stoploop = $true
            } 
            Catch {
                if ($Retrycount -gt 5) {
                    [string]$date = (Get-Date)
                    $output = " - Azure failed to succesfully create a new Key Vault in 5 minutes."
                    $msg = $date + $output
                    write-output $msg
            
                 
                    $Stoploop = $true
                }
                else {
                    [string]$date = (Get-Date)
                    $output = " - The Azure Key Vault provisioning is still in progress. Checking status again in $RetryWaitSecs seconds."
                    $msg = $date + $output
                    write-output $msg
            
                
                    start-sleep -Seconds $RetryWaitSecs
                    $Retrycount = $Retrycount + 1
                }
            }
        }
        While ($Stoploop -eq $false)
        

    }
}
else {
    if ('0' -eq $RegionName.Length) { 
        $RegionName = read-host -Prompt "Please proivde the Azure Stack Region name"
    
        if ($null -eq $RegionName) {
            [string]$date = (Get-Date)
            $output = " - Checking if the Key Vault '$KeyVaultName' is available"
            $msg = $date + $output
            Write-Output $msg
            Write-Warning "A region name was not provided.  Please pass the Azure Stack Region Name and External FQDN or provide an Azure Key Vault name you would like."
            break
        }
        if ('0' -eq $RegionName.Length) {
            [string]$date = (Get-Date)
            $output = " - Checking if the Key Vault '$KeyVaultName' is available"
            $msg = $date + $output
            Write-Output $msg
            Write-Warning "A region name was not provided.  Please pass the Azure Stack Region Name and External FQDN or provide an Azure Key Vault name you would like."
            break
        }
            
    }   
    
    if ('0' -eq $externalFQDN.Length) { 
        $externalFQDN = read-host -Prompt "Please proivde the Azure Stack external FQDN"
        if ($null -eq $externalFQDN) {
            [string]$date = (Get-Date)
            $output = " - Checking if the Key Vault '$KeyVaultName' is available"
            $msg = $date + $output
            Write-Output $msg
            Write-Warning "An external FQDN was not provided.  Please pass the Azure Region Name and External FQDN or provide an Azure Key Vault name you would like."
            break
        }
        if ('0' -eq $externalFQDN.Length) {
            [string]$date = (Get-Date)
            $output = " - Checking if the Key Vault '$KeyVaultName' is available"
            $msg = $date + $output
            Write-Output $msg
            Write-Warning "An external FQDN was not provided.  Please pass the Azure Stack Region Name and External FQDN or provide an Azure Key Vault name you would like."
            break
        }
        
    }
    #Standard naming convetion for Vault Name if Region name and External FQDN are provided.
    if ($false -eq $externalFQDN.Contains('.') ){
            
        Write-Warning "The external FQDN provided is not valid."
        break
    }
    $RegionName = $RegionName.TrimStart('.')
    $externalFQDN = $externalFQDN.TrimStart('.')
    $a = $RegionName -replace "-"
    $b = $externalFQDN -replace "-"
    $c = $a + $b
    [array] $array = $c -Split ('\.')
    $arrcount = ($array.Count) - 2
    $global:KeyVaultName = $array[0..$arrcount] -join ""
    
    if ($KeyVaultName.Length -gt 24) {
    
        $TrimendValue = $KeyVaultName.Substring(24)
        $KeyVaultName = $KeyVaultName.TrimEnd($TrimendValue)
        [string]$date = (Get-Date)
        $output = " - Checking if the Key Vault '$KeyVaultName' is available"
        $msg = $date + $output
        Write-Output $msg
        write-warning "The autogenerated name exceeds the alphanumeric characters limit.  Please pass a new Vault Name using the KeyVaultName parameter."
        Start-Sleep -Seconds 5
        Break
    }
    # Checking if Key Vault name exist.
    $CheckAkv = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultRgName -ErrorAction SilentlyContinue
    if ($null -eq $CheckAkv) {
        [string]$date = (Get-Date)
        $output = " - Key Vault Name $KeyVaultName does not exist.  Proceeding to create the following:`
            VaultName = $KeyVaultName`
            ResourceGroupName = $KeyVaultRgName`
            Location = $AzLocation`
            SubscriptionName =  $AzSubscriptionName"
        $msg = $date + $output
        Write-Output $msg
        
    }
    if ($null -ne $CheckAkv) { 
        [string]$date = (Get-Date)
        $output = " - Key Vault Name $KeyVaultName exist.  Please check the name and try again."
        $msg = $date + $output
        Write-Output $msg
        
        break
    }
}
# Create New Azure Key Vault
New-AzKeyVault -Name $KeyVaultName -ResourceGroupName $KeyVaultRgName -Location "EastUS"  -Verbose
Start-Sleep -Seconds 30
$Stoploop = $false
[int]$Retrycount = "0"
$RetryWaitSecs = '60'
Do {
    $RetryCount = $RetryCount + 1
    Try {
        [string]$date = (Get-Date)
        $output = " - Checking if the Key Vault '$KeyVaultName' is available"
        $msg = $date + $output
        Write-Output $msg
        $State = (Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultRgName -Verbose).VaultName
        if ($state -ne $KeyVaultName) { Throw "The Azure Key Vault provisioning is still pending" }
        [string]$date = (Get-Date)
        $output = " - The Azure Key Vault $KeyVaultName was created successfully."
        $msg = $date + $output
        Write-Output $msg
        
        $Stoploop = $true
    } 
        
    Catch {
        if ($Retrycount -gt 5) {
            
            Write-Warning "The Azure Key Vault provisioning for '$KeyVaultName' is taking longer than expected and further investigation is required." -ForegroundColor Red
            break
            $Stoploop = $true
        }
        else {
            [string]$date = (Get-Date)
            $output = " - The Azure Key Vault provisioning is still in progress. Checking status again in $RetryWaitSecs seconds"
            $msg = $date + $output
            Write-Output $msg
            start-sleep -Seconds $RetryWaitSecs
            $Retrycount = $Retrycount + 1
        }
    }
}
While ($Stoploop -eq $false)

# Setting Access Policy for current users
$Upn = (Get-AzContext).Account.Id

[string]$date = (Get-Date)
$output = " - Setting Azure Key Vault Access Policy for $Upn."
$msg = $date + $output
Write-Output $msg
Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $Upn -PermissionsToSecrets get, list, set -PermissionsToCertificates get, list, create, update, getissuers, setissuers, listissuers,purge -Verbose
[string]$date = (Get-Date)
$output = " - $Upn has been granted the following permissions for the $KeyVaultName Key Vault:
            Secrets | GET, LIST, SET
            Certificates | GET, LIST, CREATE, UPDATE, GETISSUERS, SETISSUERS, LISTISSUERS, PURGE"
$msg = $date + $output
Write-Output $msg
if ($null -ne $UserAccessPolicy){
    foreach ($Upn in $UserAccessPolicy){
        $Upn = Get-AzADUser -UserPrincipalName $Upn
        $UpnId = $Upn.Id
        $UserPrincipalName = $Upn.UserPrincipalName
        $DisplayName = $Upn.DisplayName
        [string]$date = (Get-Date)
        $output = " - Setting Azure Key Vault Access Policy for $UserPrincipalName."
        $msg = $date + $output
        Write-Output $msg
        Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $UpnId -PermissionsToSecrets get, list, set -PermissionsToCertificates get, list, create, update, getissuers, setissuers, listissuers -Verbose
        [string]$date = (Get-Date)
        $output = " - $DisplayName, $UserPrincipalName has been granted the following permissions for the $KeyVaultName Key Vault:
                Secrets | GET, LIST, SET
                Certificates | GET, LIST, CREATE, UPDATE, GETISSUERS, SETISSUERS, LISTISSUERS"
        $msg = $date + $output
        Write-Output $msg
    }


}

if ($null -ne $AccessPolicy){
    foreach ($Upn in $AccessPolicy) {
        $AdGroup = (Get-AzADGroup -DisplayName $Upn -Verbose)
        $AdGroupId = $AdGroup.Id
        $MailNickName = $AdGroup.MailNickname
        if ($null -eq $AdGroupId) {
            [string]$date = (Get-Date)
            $output = " - The AAD Group Display Name '$Upn' was NOT found.  "
            $msg = $date + $output
            Write-Output $msg
        }else{
            [string]$date = (Get-Date)
            $output = " - Setting Azure Key Vault Access Policy for $Upn."
            $msg = $date + $output
    
            Write-Output $msg
            Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $AdGroupId -PermissionsToSecrets get, list, set -PermissionsToCertificates get, list, create, update, getissuers, setissuers, listissuers -Verbose
            [string]$date = (Get-Date)
            $output = " - '$Upn' ($MailNickname , $AdGroupId)  has been granted the following permissions for the $KeyVaultName Key Vault:
                        SECRETS | GET, LIST, SET
                        CERTIFICATES | GET, LIST, CREATE, UPDATE, GETISSUERS, SETISSUERS, LISTISSUERS"
            $msg = $date + $output
            Write-Output $msg

        }
        
    }

}


Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $Upn -PermissionsToSecrets get, list, set -PermissionsToCertificates get, list, create, update, getissuers, setissuers, listissuers

# Creating Secrets.

$AccountList = @('BMC', 'PFX', 'PEP', 'OEMVM','HLH')

Foreach ($Account in $AccountList) {
    Write-Host "Do you want to procced with inputing the" -NoNewline
    Write-Host " [$Account] " -ForegroundColor Yellow  -NoNewline
    Write-Host "login details?" -NoNewline
    Write-Host " [Y/N] " -ForegroundColor Yellow -NoNewline
    [string]$InputResponse = Read-Host
    if ($InputResponse -in ('Yes', 'Y', 'y', 'yes')) {
        if ($Account -eq 'PFX') {
            Write-Host "Please enter the PASSWORD for: " -NoNewline
            Write-Host "[$Account]" -ForegroundColor Yellow -NoNewline
            $InputPassword = Read-Host -AsSecureString
            Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $Account -SecretValue $InputPassword -ContentType "$Account Certificate Password for $RegionName.$externalFQDN Azure Stack"
        }
        if ($Account -ne 'PFX') {
            Write-Host "Please enter the USERNAME for: " -NoNewline
            Write-Host "[$Account]" -ForegroundColor Yellow -NoNewline
            $InputUserName = Read-Host
            [string]$UserName = $Account + '-' + $InputUserName
            Write-Host "Please enter the PASSWORD for: " -NoNewline
            Write-Host "[$InputUserName]" -ForegroundColor Yellow -NoNewline
            $InputPassword = Read-Host -AsSecureString
            Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $UserName -SecretValue $InputPassword -ContentType "$Account Secret for $RegionName.$externalFQDN Azure Stack"
        }
    
    }
    else {
        [string]$date = (Get-Date)
        $output = " - Skipping Azure Key Vault secret creation for: $Account"
        $msg = $date + $output
        Write-Output $msg
    }
}
        
[string]$date = (Get-Date)
        $output = " - New Azure Key Vault Task - Finished"
        $msg = $date + $output
        write-output $msg

### STARTING CERTIFICATE CREATION #####

$AzsCertList = ("*.blob","*.queue")
<#
    "*.queue",
    "*.table",
    "*.adminhosting",
    "*.vault",
    "*.adminvault",
    "*.hosting",
    "adminportal",
    "adminmanagement",
    "management",
    "portal"
#>
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
if ($null -ne $ChkCaIssuer) {
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

##### DOWNLOADING CERTIFICATE AND EXPORTING WITH PFX #####

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
$SecretName = 'PFX'
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
    $externalFQDN = Read-Host -Prompt "Please provide the Azure Stack External FQDN" 
    $RegionName = Read-Host -Prompt "Please provide the Azure Stack Region Name" 
    Invoke-AzsCertificateValidation -CertificateType deployment -CertificatePath $AzsCertDeploymentPath -ExternalFQDN $externalFQDN -RegionName $RegionName -IdentitySystem AAD -pfxPassword $pfxpassword

}