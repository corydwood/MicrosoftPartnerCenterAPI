<#
.Synopsis
    Gets an Azure Active Directory authentication token using the Azure Directory Authentication Library.
.DESCRIPTION
    Long description
.EXAMPLE
    Get-MPCAzureADToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -ResourceUri https://api.partnercenter.microsoft.com -Credential (Get-Credential) -Domain netgain.onmicrosoft.com
#>
function Get-MPCAzureADToken {
    [CmdletBinding()]
    Param(
        # ID of application created in Azure Active Directory
        [Parameter(Mandatory=$true)]
        [string]$ApplicationID,
        # Azure AD Domain
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        # Uri of the resource to request the token for
        [Parameter(Mandatory=$true)]
        [string]$ResourceUri,
        [pscredential]$Credential,
        $Secret,
        [switch]$NullTokenCache,
        $CustomTokenCache,
        [switch]$FileCache,
        [string]$RedirectUri = 'http://localhost'
    )
    Write-Verbose 'Getting Azure AD token'
    $adalPath = Join-Path -Path $PSScriptRoot -ChildPath '\Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
    $adalPlatformPath = Join-Path -Path $PSScriptRoot -ChildPath '\Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'
    Add-Type -Path $adalPath
    Add-Type -Path $adalPlatformPath
    if ($Credential -or $Secret) {
        $body = @{
            resource = $ResourceUri
            client_id = $ApplicationID
        }
        if ($Credential) {
            $body.grant_type = 'password'
            $body.username = $Credential.UserName
            $body.password = $Credential.GetNetworkCredential().Password
        }
        elseif ($Secret) {
            $body.grant_type = 'client_credentials'
            $body.client_secret = $secret
        }
        $params = @{
            Uri = "https://login.microsoftonline.com/$Domain/oauth2/token"
            Method = 'Post'
            Body = $body
        }
        Write-Output (Invoke-RestMethod @params)
    }
    else {
        if ($NullTokenCache) {
            $authenticationContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/$Domain/",$null)
        }
        elseif ($CustomTokenCache) {
            $authenticationContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/$Domain/",$CustomTokenCache)
        }
        elseif ($FileCache) {
            $assemblies = (
                (Join-Path -Path $PSScriptRoot -ChildPath '\Microsoft.IdentityModel.Clients.ActiveDirectory.dll'),
                (Join-Path -Path $PSScriptRoot -ChildPath '\Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'),
                "System.Runtime, Version=4.0.0.0,Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a",
                "System.Security"
            )
            $source = @"
                using Microsoft.IdentityModel.Clients;
                using Microsoft.IdentityModel.Clients.ActiveDirectory;
                using System.IO;
                using System.Security.Cryptography;
        
                namespace TodoListClient
                {
                
                    // This is a simple persistent cache implementation for a desktop application.
                    // It uses DPAPI for storing tokens in a local file.
                    public class FileCache : TokenCache
                    {
                        public string CacheFilePath;
                        private static readonly object FileLock = new object();
                
                        // Initializes the cache against a local file.
                        // If the file is already rpesent, it loads its content in the ADAL cache
                        public FileCache(string filePath)
                        {
                            CacheFilePath = filePath;
                            this.AfterAccess = AfterAccessNotification;
                            this.BeforeAccess = BeforeAccessNotification;
                            lock (FileLock)
                            {
                                this.Deserialize(File.Exists(CacheFilePath) ? ProtectedData.Unprotect(File.ReadAllBytes(CacheFilePath), null, DataProtectionScope.CurrentUser) : null);
                            }
                        }
                
                        // Empties the persistent store.
                        public override void Clear()
                        {
                            base.Clear();
                            File.Delete(CacheFilePath);
                        }
                
                        // Triggered right before ADAL needs to access the cache.
                        // Reload the cache from the persistent store in case it changed since the last access.
                         void BeforeAccessNotification(TokenCacheNotificationArgs args)
                        {
                            lock (FileLock)
                            {
                                this.Deserialize(File.Exists(CacheFilePath) ?  ProtectedData.Unprotect(File.ReadAllBytes(CacheFilePath),null,DataProtectionScope.CurrentUser) : null);
                            }
                        }
                
                        // Triggered right after ADAL accessed the cache.
                        void AfterAccessNotification(TokenCacheNotificationArgs args)
                        {
                            // if the access operation resulted in a cache update
                            if (this.HasStateChanged)
                            {
                                lock (FileLock)
                                {                    
                                    // reflect changes in the persistent store
                                    File.WriteAllBytes(CacheFilePath, ProtectedData.Protect(this.Serialize(),null,DataProtectionScope.CurrentUser));
                                    // once the write operation took place, restore the HasStateChanged bit to false
                                    this.HasStateChanged = false;
                                }                
                            }
                        }
                    }
                
                }
"@
            try {
                Add-Type -TypeDefinition $source -ReferencedAssemblies $assemblies
            }
            catch {}
            $cache = New-Object TodoListClient.FileCache("c:\temp\$Domain.dat")
            $authenticationContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/$Domain/",$cache)
        }
        else {
            $authenticationContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext("https://login.windows.net/$Domain/")
        }
        $token = $authenticationContext.AcquireTokenSilentAsync($ResourceUri, $ApplicationID)
        Start-Sleep -Seconds 1
        if ($token.Exception) {
            $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList 'Auto'
            $token = $authenticationContext.AcquireTokenAsync($ResourceUri, $ApplicationID, $RedirectUri, $platformParameters)
            if ($token.Exception) {
                throw $token.Exception
            }
            else {
                $token.Wait()
                Write-Output $token.Result
            }
        }
        else {
            $token.Wait()
            Write-Output $token.Result
        }
    }
}

<#
.Synopsis
    Gets a Microsoft Partner Center token when given an Azure Active Directory token.
.DESCRIPTION
    Long description
.EXAMPLE
    Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential) -PartnerDomainPrefix netgain
#>
function Get-MPCToken {
    [CmdletBinding()]
    Param(
        # ID of application created in Azure Active Directory
        [Parameter(Mandatory=$true)]
        [string]$ApplicationID,
        # Partner domain prefix for onmicrosoft.com domain
        [Parameter(Mandatory=$true)]
        [string]$PartnerDomainPrefix,
        $MpcAzureAdToken,
        [pscredential]$Credential,
        [switch]$NullTokenCache,
        $CustomTokenCache,
        [switch]$FileCache

    )
    if (!$MpcAzureAdToken) {
        $getMPCAzureADTokenParams = @{
            ApplicationID = $ApplicationID
            Domain = "$PartnerDomainPrefix.onmicrosoft.com"
            ResourceUri = 'https://api.partnercenter.microsoft.com'
            ErrorAction = 'Stop'
        }
        if ($NullTokenCache) {
            $getMPCAzureADTokenParams.NullTokenCache = $true
        }
        elseif ($CustomTokenCache) {
            $getMPCAzureADTokenParams.CustomTokenCache = $CustomTokenCache
        }
        elseif ($FileCache) {
            $getMPCAzureADTokenParams.FileCache = $true
        }
        if ($Credential) {
            $getMPCAzureADTokenParams.Credential = $Credential
            $MpcAzureAdToken = (Get-MPCAzureADToken @getMPCAzureADTokenParams).access_token
        }
        else {
            $MpcAzureAdToken = (Get-MPCAzureADToken @getMPCAzureADTokenParams).AccessToken
        }
    }
    $params = @{
        Uri = 'https://api.partnercenter.microsoft.com/generatetoken'
        Headers = @{Authorization = "Bearer $MPCAzureADToken"}
        Method = 'Post'
        Body = 'grant_type=jwt_token'
    }
    Write-Verbose 'Getting Microsoft Partner Center token'
    Write-Output ((Invoke-WebRequest @params).Content | ConvertFrom-Json)
}

<#
.Synopsis
    Checks the domain availability for the given onmicrosoft.com domain prefix.
.DESCRIPTION
    Long description
.EXAMPLE
    $mpcToken = Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential)
    Get-MPCDomainAvailability -CustomerDomainPrefix 'mydomain' -MPCToken $mpcToken.access_token
#>
function Get-MPCDomainAvailability {
    [CmdletBinding()]
    Param(
        # Customer domain prefix for onmicrosoft.com domain
        [Parameter(Mandatory=$true)]
        [string]$CustomerDomainPrefix,
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/validations/checkdomainavailability/$CustomerDomainPrefix"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Verbose 'Checking domain availability'
    $result = (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
    if ($result -eq $true) {Write-Verbose "$CustomerDomainPrefix.onmicrosoft.com available."}
    else {Write-Verbose "$($CustomerDomainPrefix.onmicrosoft.com) not available."}
    $result
}

<#
.Synopsis
    Creates a new customer in the Microsoft Partner Center.
.DESCRIPTION
    Long description
.EXAMPLE
    $mpcToken = Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential)
    New-MPCCustomer -CustomerDomainPrefix mydomain -MPCToken $mpcToken.access_token -CompanyName 'My Company' -FirstName 'John' -LastName 'Doe' `
    -Email 'John.Doe@MyAlternateDomain.com -PhoneNumber 5555555555 -AddressLine1 '1 Microsoft Way' -City Redmond -State WA -PostalCode 98052
#>
function New-MPCCustomer {
    [CmdletBinding()]
    Param(
        # Customer domain prefix for onmicrosoft.com domain
        [Parameter(Mandatory=$true)]
        [string]$CustomerDomainPrefix,
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Name of company/organization
        [Parameter(Mandatory=$true)]
        [string]$CompanyName,
        # The first name of a contact at the customer's company/organization
        [Parameter(Mandatory=$true)]
        [string]$FirstName,
        # The last name of a contact at the customer's company/organization
        [Parameter(Mandatory=$true)]
        [string]$LastName,
        # The email address of a contact at the customer's company/organization
        [Parameter(Mandatory=$true)]
        [string]$Email,
        # The phone number of a contact at the customer's company/organization
        [Parameter(Mandatory=$true)]
        [string]$PhoneNumber,
        # Address line 1 of a contact at the customer's company/organization
        [Parameter(Mandatory=$true)]
        [string]$AddressLine1,
        # Address line 2 of a contact at the customer's company/organization
        [string]$AddressLine2,
        # Address line 3 of a contact at the customer's company/organization
        [string]$AddressLine3,
        # City of a contact at the customer's company/organization
        [Parameter(Mandatory=$true)]
        [string]$City,
        # State of a contact at the customer's company/organization
        [Parameter(Mandatory=$true)]
        [string]$State,
        # Postal/zip code of a contact at the customer's company/organization
        [Parameter(Mandatory=$true)]
        [string]$PostalCode,
        # Country of a contact at the customer's company/organization
        [string]$Country = 'US',
        # The preferred culture for communication and currency, such as "en-us"
        [string]$Culture = 'EN-US',
        # The preferred language for communication
        [string]$Language = 'En'
    )
    $mpcCustomerObject = [pscustomobject]@{
        CompanyProfile = @{
            Domain = "$CustomerDomainPrefix.onmicrosoft.com"
        }
        BillingProfile = @{
            Email = $Email
            Culture = $Culture
            Language = $Language
            CompanyName = $CompanyName
            DefaultAddress = @{
                Country = $Country
                City = $City
                State = $State
                AddressLine1 = $AddressLine1
                PostalCode = $PostalCode
                FirstName = $FirstName
                LastName = $LastName
                PhoneNumber = $PhoneNumber
            }
        }
    }
    if ($AddressLine2) {$mpcCustomerObject.BillingProfile.DefaultAddress.AddressLine2 = $AddressLine2}
    if ($AddressLine3) {$mpcCustomerObject.BillingProfile.DefaultAddress.AddressLine3 = $AddressLine3}
    $mpcCustomerJson = $mpcCustomerObject | ConvertTo-Json
    $params = @{
        Uri = 'https://api.partnercenter.microsoft.com/v1/customers'
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Post'
        Body = $mpcCustomerJson
        ContentType = 'application/json'
    }
    Write-Verbose 'Creating customer'
    Write-Output (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}

<#
.Synopsis
    Gets a list of offers available in the Microsoft Partner Center
.DESCRIPTION
    Long description
.EXAMPLE
    $mpcToken = Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential)
    Get-MPCOffers -MPCToken $mpcToken.access_token
#>
function Get-MPCOffers {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Country where offer applies
        [string]$Country = 'US'
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/offers?country=$Country"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Verbose 'Getting offers'
    Write-Output (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}

<#
.Synopsis
    Creates a new order in the Microsoft Partner Center.
.DESCRIPTION
    Long description
.EXAMPLE
    $mpcToken = Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential)
    $mpcOffer = (Get-MPCOffers -MPCToken $mpcToken.access_token).items | select -First 1
    New-MPCOrder -MPCToken $mpcToken.access_token -CustomerID e2dcbfa5-cc31-4062-a76f-34b4c2e92a72 -OfferID $mpcOffer.id -Quantity 5
#>
function New-MPCOrder {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Customer ID
        [Parameter(Mandatory=$true)]
        [string]$CustomerID,
        # Offer ID
        [Parameter(Mandatory=$true)]
        [string]$OfferID,
        # The number of licenses
        [Parameter(Mandatory=$true)]
        [int]$Quantity
    )
    $orderJson = [pscustomobject]@{
        ReferenceCustomerId = $CustomerID
        LineItems = @(
            @{
                LineItemNumber = 0
                OfferId = $OfferID
                Quantity = $Quantity
            }
        )
        Attributes = @{
            ObjectType = "Order"
        }
    } | ConvertTo-Json
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerID/orders"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Post'
        ContentType = 'application/json'
        Body = $orderJson
    }
    Write-Verbose 'Creating order'
    Write-Output (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}

<#
.Synopsis
    Removes a customer from the Microsoft Partner Center.
.DESCRIPTION
    Long description
.EXAMPLE
    $mpcToken = Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential)
    Remove-MPCCustomer -MPCToken $mpcToken.access_token -CustomerID e2dcbfa5-cc31-4062-a76f-34b4c2e92a72
#>
function Remove-MPCCustomer {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Customer ID
        [Parameter(Mandatory=$true)]
        [string]$CustomerID
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerID"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Delete'
        ContentType = 'application/json'
    }
    Write-Verbose 'Removing customer'
    Write-Output (Invoke-WebRequest @params).Content | ConvertFrom-Json
}

<#
.Synopsis
    Gets a customer from the Microsoft Partner Center.
.DESCRIPTION
    Long description
.EXAMPLE
    $mpcToken = Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential)
    Get-MPCCustomer -MPCToken $mpcToken.access_token -Domain netgaintest1.onmicrosoft.com
#>
function Get-MPCCustomer {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Custom or onmicrosoft.com domain
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    $Uri = @"
https://api.partnercenter.microsoft.com/v1/customers?size=0&filter={"Field":"Domain","Value":"$Domain","Operator":"starts_with"}
"@
    $params = @{
        Uri = $Uri
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Verbose 'Getting customer'
    Write-Output (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}

<#
.Synopsis
    Gets customer subscriptions from the Microsoft Partner Center.
.DESCRIPTION
    Long description
.EXAMPLE
    $mpcToken = Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential)
    Get-MPCSubscriptions -MPCToken $mpcToken.access_token -CustomerID e2dcbfa5-cc31-4062-a76f-34b4c2e92a72
#>
function Get-MPCSubscriptions {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Customer ID
        [Parameter(Mandatory=$true)]
        [string]$CustomerID
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerID/subscriptions"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Verbose 'Getting subscriptions'
    Write-Output (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}

<#
.Synopsis
    Updates a customer's subscription in the Microsoft Partner Center.
.DESCRIPTION
    Long description
.EXAMPLE
    $mpcToken = Get-MPCToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential)
    $mpcSubscription = (Get-MPCSubscriptions -MPCToken $mpcToken.access_token -CustomerID e2dcbfa5-cc31-4062-a76f-34b4c2e92a72).items | select -First 1
    Update-MPCSubscription -MPCToken $mpcToken -CustomerID e2dcbfa5-cc31-4062-a76f-34b4c2e92a72 -Subscription $mpcSubscription -Quantity 5
#>
function Update-MPCSubscription {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Customer ID
        [Parameter(Mandatory=$true)]
        [string]$CustomerID,
        # Object containing subscription information. Received from Get-MPCSubscriptions.
        [Parameter(Mandatory=$true)]
        [pscustomobject]$Subscription,
        # The quantity of licenses to set the subscription to.
        [Parameter(Mandatory=$true)]
        [string]$Quantity
    )
    $Subscription.quantity = $Quantity
    # Must be removed to prevent error
    $Subscription.psobject.Properties.Remove('billingCycle')
    $body = $Subscription | ConvertTo-Json
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerID/subscriptions/$($Subscription.id)"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Patch'
        ContentType = 'application/json'
        Body = $body
    }
    Write-Verbose 'Updating quantity on subscription'
    Write-Output (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}
function Get-MPCAzureUsage {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Customer ID
        [Parameter(Mandatory=$true)]
        [string]$CustomerID,
        # Subscription ID
        [Parameter(Mandatory=$true)]
        [pscustomobject]$SubscriptionID,
        # Start time
        [Parameter(Mandatory=$true)]
        [datetime]$StartTime,
        # End time
        [Parameter(Mandatory=$true)]
        [datetime]$EndTime,
        # Defines the granularity of usage aggregations
        [Parameter()]
        [ValidateSet('daily','hourly')]
        [string]$Granularity
    )
    $universalSortableStartTime = Get-Date -Date $StartTime -Format u
    $universalSortableEndTime = Get-Date -Date $EndTime -Format u
    $baseUri = 'https://api.partnercenter.microsoft.com/v1/'
    $uri = $baseUri + "customers/$CustomerID/subscriptions/$SubscriptionID/utilizations/azure?" +
        "start_time=$universalSortableStartTime&end_time=$universalSortableEndTime"
    if ($Granularity) {
        $uri += "&granularity=$Granularity"
    }
    $headers = @{Authorization = "Bearer $MPCToken"}
    $params = @{
        Uri = $uri
        Headers = $headers
        Method = 'Get'
        ContentType = 'application/json'
    }
    $items = @()
    $totalCount = 0
    $result = (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
    $items += $result.items
    $totalCount += $result.totalCount
    if ($result.links.next) {
        do {
            $params2 = $params.Clone()
            $params2.Uri = $baseUri + $result.links.next.uri
            $headers2 = $headers.Clone()
            $headers2.Add($result.links.next.headers.key, $result.links.next.headers.value)
            $params2.Headers = $headers2
            $result = (Invoke-WebRequest @params2).Content.Substring(1) | ConvertFrom-Json
            $items += $result.items
            $totalCount += $result.totalCount
        }
        until ($null -eq $result.links.next)
    }
    $output = [pscustomobject]@{
        totalCount = $totalCount
        items = $items
        links = $result.links
    }
    Write-Output $output
}
function Get-MPCCustomerServiceCostsSummary {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Customer ID
        [Parameter(Mandatory=$true)]
        [string]$CustomerID
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerID/servicecosts/mostrecent"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Output ($result = Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}
function Get-MPCCustomerUsageSummary {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Customer ID
        [Parameter(Mandatory=$true)]
        [string]$CustomerID
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerID/usagesummary"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Output ($result = Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}
function Get-MPCSubscriptionUsage {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken,
        # Customer ID
        [Parameter(Mandatory=$true)]
        [string]$CustomerID,
        # Subscription ID
        [Parameter(Mandatory=$true)]
        [pscustomobject]$SubscriptionID
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerID/subscriptions/$SubscriptionID/usagerecords/resources"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Output ($result = Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}
function Get-MPCInvoices {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/invoices"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Output ($result = Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}
function Get-MPCAzurePrices {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken
    )
    $params = @{
        Uri = "https://api.partnercenter.microsoft.com/v1/ratecards/azure"
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Output ($result = Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}
function Get-MPCCustomers {
    [CmdletBinding()]
    Param(
        # Microsoft Partner Center authentication token
        [Parameter(Mandatory=$true)]
        [string]$MPCToken
    )
    $Uri = 'https://api.partnercenter.microsoft.com/v1/customers'
    $params = @{
        Uri = $Uri
        Headers = @{Authorization = "Bearer $MPCToken"}
        Method = 'Get'
        ContentType = 'application/json'
    }
    Write-Verbose 'Getting customers'
    Write-Output (Invoke-WebRequest @params).Content.Substring(1) | ConvertFrom-Json
}
