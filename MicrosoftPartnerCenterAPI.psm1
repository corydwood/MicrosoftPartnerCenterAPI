<#
.Synopsis
    Gets an Azure Active Directory authentication token.
.DESCRIPTION
    Long description
.EXAMPLE
    Get-MPCAzureADToken -ApplicationID f5e4f291-6e60-48c0-bc2e-e72e9a3a0464 -Credential (Get-Credential) -DomainPrefix netgain
#>
function Get-MPCAzureADToken {
    [CmdletBinding()]
    Param(
        # ID of application created in Azure Active Directory
        [Parameter(Mandatory=$true)]
        [string]$ApplicationID,
        # User credential to access Azure Active Directory
        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,
        # Partner domain prefix for onmicrosoft.com domain
        [Parameter(Mandatory=$true)]
        [string]$DomainPrefix
    )
    $username = $Credential.Username
    $password = $Credential.GetNetworkCredential().Password
    $body = "resource=https://api.partnercenter.microsoft.com&client_id=$ApplicationID&grant_type=password&username=$Username&password=$Password&scope=openid"
    Write-Verbose 'Getting Azure AD token'
    $mpcAzureAdTokenRequest = Invoke-WebRequest -Uri https://login.windows.net/$DomainPrefix.onmicrosoft.com/oauth2/token -Method Post -Body $body
    Write-Output ($mpcAzureAdTokenRequest.Content | ConvertFrom-Json)
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
        # User credential to access Azure Active Directory
        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,
        # Partner domain prefix for onmicrosoft.com domain
        [Parameter(Mandatory=$true)]
        [string]$PartnerDomainPrefix
    )
    $mpcAzureAdToken = Get-MPCAzureADToken -ApplicationID $ApplicationID -Credential $Credential -DomainPrefix $PartnerDomainPrefix -ErrorAction Stop
    $params = @{
        Uri = 'https://api.partnercenter.microsoft.com/generatetoken'
        Headers = @{Authorization = "Bearer $($MPCAzureADToken.access_token)"}
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
    New-MPCOrder -MPCToken $mpcToken.access_token -CustomerID e2dcbfa5-cc31-4062-a76f-34b4c2e92a72 -OfferID $mpcOffer -Quantity 5
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
