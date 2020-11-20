<#
.Synopsis
    New-AzsKeyVault.ps1 | This script will create an Azure Key Vault to store Azure Stack Certificates and Secrets.

.Description

     

    Pre Requisites:  Contributor access to the Azure Subscription where you plan to store Certificates and Secrets.

    This script will create an Azure Key Vault to store Azure Stack Certificates and Secrets.
        
    The script will also prompt for login details to the following accounts:

        HLH Account
        BMC Account
        Certificate PFX password
        PEP Azs Domain Account & Credentials
        OEM VM login details
    

.Parameter TenantId
    Provide the Azure Subscription Tenant Id where the Azure Key Vault will be created.

.Parameter SubId
    Provide the Azure Subscription ID where the Azure Key Vault will be created.

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

    To create a new Key Vault and Resource Group in the EastUs2 location. 
    
    Example Parameters:
        TenantId = '01234'
        SubId = '56789'
        KeyVaultRgName = NewAkvRgName (If this resoure group does not exist a new one will be created.)
        RegionName = AzsRegion
        ExternalFQDN = AzsContoso.com (The region name and FQDN will be joined to generate the following AKV name:  'AzsRegionAzsContoso')
        Location = eastus2 (Since a Location value was not provided.  The default is 'eastus2')

    New-AzsKeyVault.ps1 -TenantId '01234' -SubId '56789' -KeyVaultRgName 'NewAkvRgName' -RegionName AzsRegion -externalFQDN AzsContoso.com 
    
    
.example

    To create a new Key Vault in an existing Resource Group in the EastUs2 location. 
    
    Example Parameters:
        TenantId = '01234'
        SubId = '56789'
        KeyVaultRgName = ExistingAkvRgName (If the resoure group does not exist a new one will be created.)
        RegionName = AzsRegion
        ExternalFQDN = AzsContoso.com (The region name and FQDN will be joined to generate the following AKV name:  'AzsRegionAzsContoso')
        Location = eastus2 (Since a Location value was not provided.  The default is 'eastus2')
    Command:
        New-AzsKeyVault.ps1 -TenantId '01234' -SubId '56789' -KeyVaultRgName 'ExistingAkvRgName' -RegionName AzsRegion -externalFQDN AzsContoso.com 

.example

    To create a new Key Vault in an existing Resource Group in the WestUs2 location. 
    
    Parameters:
        TenantId = '01234'
        SubId = '56789'
        KeyVaultRgName = ExistingAkvRgName (If the resoure group does not exist a new one will be created.)
        RegionName = AzsRegion
        ExternalFQDN = AzsContoso.com (The region name and FQDN will be joined to generate the following AKV name:  'AzsRegionAzsContoso')
        Location = westus2 (Since a Location value was not provided.  The default is 'eastus2')

    New-AzsKeyVault.ps1 -TenantId '01234' -SubId '56789' -KeyVaultRgName 'ExistingAkvRgName' -RegionName AzsRegion -externalFQDN AzsContoso.com -Location 'westus2'


.link
https://docs.microsoft.com/en-us/powershell/scripting/getting-started/getting-started-with-windows-powershell?view=powershell-7
https://github.com/powershell/powerhsell


#>
param (
    [parameter(Mandatory = $true)] [string]$TenantId,
    [parameter(Mandatory = $true)] [string]$SubId,
    [parameter(Mandatory = $true)] [string]$KeyVaultRgName,
    [parameter(Mandatory = $false)] [string]$RegionName,
    [parameter(Mandatory = $false)] [string]$externalFQDN,
    [parameter(Mandatory = $false)] [string]$KeyVaultName,
    [parameter(Mandatory = $false)] [string]$AzLocation
    
)
$RegionName = $RegionName.ToLower()
$externalFQDN = $externalFQDN.ToLower()
$KeyVaultName = $KeyVaultName.ToLower()
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
            Write-Warning "A region name was not provided.  Please pass the Azure Stack Region Name and External FQDN or provide an Azure Key Vault name you would like." -ForegroundColor Red
            break
        }
        if ('0' -eq $RegionName.Length) {
            [string]$date = (Get-Date)
            $output = " - Checking if the Key Vault '$KeyVaultName' is available"
            $msg = $date + $output
            Write-Output $msg
            Write-Warning "A region name was not provided.  Please pass the Azure Stack Region Name and External FQDN or provide an Azure Key Vault name you would like." -ForegroundColor Red
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
            Write-Warning "An external FQDN was not provided.  Please pass the Azure Region Name and External FQDN or provide an Azure Key Vault name you would like." -ForegroundColor Red
            break
        }
        if ('0' -eq $externalFQDN.Length) {
            [string]$date = (Get-Date)
            $output = " - Checking if the Key Vault '$KeyVaultName' is available"
            $msg = $date + $output
            Write-Output $msg
            Write-Warning "An external FQDN was not provided.  Please pass the Azure Stack Region Name and External FQDN or provide an Azure Key Vault name you would like." -ForegroundColor Red
            break
        }
    }
    #Standard naming convetion for Vault Name if Region name and External FQDN are provided.
    $RegionName = $RegionName.TrimStart('.')
    $externalFQDN = $externalFQDN.TrimStart('.')
    $a = $RegionName -replace "-"
    $b = $externalFQDN -replace "-"
    $c = $a + $b
    [array] $array = $c -Split ('\.')
    $arrcount = ($array.Count) - 2
    [string]$KeyVaultName = $array[0..$arrcount] -join ""
    
    if ($KeyVaultName.Length -gt 24) {
    
        $TrimendValue = $KeyVaultName.Substring(24)
        $KeyVaultName = $KeyVaultName.TrimEnd($TrimendValue)
        [string]$date = (Get-Date)
        $output = " - Checking if the Key Vault '$KeyVaultName' is available"
        $msg = $date + $output
        Write-Output $msg
        write-warning "The autogenerated name exceeds the alphanumeric characters limit.  Please pass a new Vault Name using the KeyVaultName parameter." -ForegroundColor Red
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
#$TeamSGName =  ''
#$TeamSG = (Get-AzADGroup -DisplayName $TeamSgName).Id
[string]$date = (Get-Date)
$output = " - Setting Azure Key Vault Access Policy"
$msg = $date + $output
Write-Output $msg

Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -UserPrincipalName $Upn -PermissionsToSecrets get, list, set -PermissionsToCertificates get, list, create, update, getissuers, setissuers, listissuers
#Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $TeamSG -PermissionsToSecrets get, list, set -PermissionsToCertificates get, list, create, update, getissuers, setissuers, listissuers

# Creating Secrets.

$AccountList = @('BMC', 'PFX', 'PEP', 'OEM VM','HLH')

Foreach ($Account in $AccountList){
Write-Host "Do you want to procced with inputing the" -NoNewline
Write-Host " [$Account] " -ForegroundColor Yellow  -NoNewline
Write-Host "login details?" -NoNewline
Write-Host " [Y/N] " -ForegroundColor Yellow -NoNewline
[string]$InputResponse = Read-Host
if ($InputResponse -in ('Yes', 'Y', 'y', 'yes')) {

    Write-Host "Please enter the USERNAME for: " -NoNewline
    Write-Host "[$Account]" -ForegroundColor Yellow -NoNewline
    $InputUserName = Read-Host
    Write-Host "Please enter the PASSWORD for: " -NoNewline
    Write-Host "[$InputUserName]" -ForegroundColor Yellow -NoNewline
    $InputPassword = Read-Host -AsSecureString
    Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $Account -SecretValue $InputPassword -ContentType "$Account Password"
    }else {
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

###NEED TO PROMPT FOR CA ISSUER Setup