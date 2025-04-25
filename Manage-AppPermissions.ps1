#Requires -Modules Az.Accounts, Az.KeyVault

<#
.SYNOPSIS
Manages application consent and permissions for a multi-tenant application across partner-managed customer tenants.

.DESCRIPTION
This script performs the following actions:
1. Retrieves the application's client secret from Azure Key Vault.
2. Obtains an initial refresh token via interactive login (required once per session or until refresh token expiry).
3. Uses the refresh token to acquire access tokens for Microsoft Graph and Partner Center APIs.
4. Retrieves a list of customer tenants from Partner Center.
5. **Ensures required DELEGATED permissions consent exists** via the Partner Center API for each customer (requires appropriate GDAP roles). This creates or updates the consent grant for Graph Delegated permissions like AppRoleAssignment.ReadWrite.All and Application.ReadWrite.All.
6. For each customer tenant (excluding partner):
    a. Obtains a Graph API access token specific to that customer tenant using the APP'S identity via the refresh token.
    b. Finds the Application's Service Principal (SPN) in the customer tenant.
    c. Finds the Object ID (Principal ID) of the target resource APIs (e.g., Microsoft Graph).
    d. Checks existing APPLICATION permissions (App Roles) granted directly to the service principal. Handles cases where no permissions exist yet or cannot be read initially.
    e. Grants any missing APPLICATION permissions defined in 'PermissionManifest.json' (requires the app to have AppRoleAssignment.ReadWrite.All application permission itself, which the script attempts to grant first if missing).

.PARAMETER AppId
The Application (client) ID of your multi-tenant application registration.

.PARAMETER AppName
The Display Name of your multi-tenant application registration (used for SPN lookup if needed, primarily for verbose logging).

.PARAMETER KeyVaultSubscriptionId
The Azure Subscription ID where the Key Vault resides.

.PARAMETER KeyVaultName
The name of the Azure Key Vault containing the application's client secret.

.PARAMETER KeyVaultSecretName
The name of the secret in Azure Key Vault that stores the application's client secret value.

.PARAMETER PermissionManifestPath
The file path to the JSON manifest defining the required APPLICATION permissions (Roles). See script comments/article for format.

.PARAMETER PartnerTenantId
The Tenant ID (GUID or domain name like 'yourpartner.onmicrosoft.com') of the Partner organization where the app is registered. Defaults are illustrative.

.PARAMETER RedirectUri
The Redirect URI configured in the App Registration used for the interactive login flow. Must match exactly. Defaults to 'http://localhost:8400'.

.EXAMPLE
.\Manage-AppPermissions.ps1 `
    -AppId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -AppName "My Cross-Tenant App" `
    -KeyVaultSubscriptionId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
    -KeyVaultName "mypartner-kv-secrets" `
    -KeyVaultSecretName "MyCrossTenantApp-ClientSecret" `
    -PermissionManifestPath ".\PermissionManifest.json" `
    -PartnerTenantId "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz" `
    -RedirectUri "http://localhost:8400" `
    -Verbose

.NOTES
- Requires Az.Accounts and Az.KeyVault PowerShell modules.
- Requires interactive login by a user with sufficient GDAP permissions over customer tenants for Step 5 (Partner Center Consent).
- The user running the script needs 'Get'/'List' permissions on secrets in the specified Key Vault.
- The PermissionManifest.json file defines the target state for APPLICATION permissions (type: Role).
- Step 6d/6e: The script attempts to read existing Application Roles granted to the app's SPN. If this fails (e.g., the app initially lacks the 'AppRoleAssignment.Read.All' Application permission), it assumes no roles are granted and attempts to grant the bootstrap 'AppRoleAssignment.ReadWrite.All' Application role first (if defined in the manifest). It then proceeds to grant other roles from the manifest. A second run might be necessary for full convergence if the bootstrap permission grant succeeded but reading permissions failed initially.
- Ensure the Redirect URI parameter matches one registered in the Azure AD App Registration.
- TimeoutSec parameter added to Invoke-RestMethod calls for potentially long-running operations.

#>
[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [guid]$AppId,

    [Parameter(Mandatory=$true)]
    [string]$AppName,

    [Parameter(Mandatory=$true)]
    [string]$KeyVaultSubscriptionId,

    [Parameter(Mandatory=$true)]
    [string]$KeyVaultName,

    [Parameter(Mandatory=$true)]
    [string]$KeyVaultSecretName,

    [Parameter(Mandatory=$true)]
    [string]$PermissionManifestPath,

    [string]$PartnerTenantId = "82ebfa44-6039-41ea-8687-2ee221497c7c", # Specify Partner's Tenant ID

    [string]$RedirectUri = "http://localhost:8400" # Must match Redirect URI in App Reg
)

#region Helper Functions

# --- Get-AppSecretFromKeyVault ---
function Get-AppSecretFromKeyVault {
    param (
        [Parameter(Mandatory=$true)][string]$SubscriptionId, [Parameter(Mandatory=$true)][string]$VaultName,
        [Parameter(Mandatory=$true)][string]$SecretName, [Parameter(Mandatory=$true)][string]$TenantId
    )
    $currentContext = Get-AzContext
    if ($null -eq $currentContext -or $currentContext.Subscription.Id -ne $SubscriptionId -or $currentContext.Tenant.Id -ne $TenantId) {
        Write-Warning "Not connected to the correct Azure context (Tenant: $TenantId, Subscription: $SubscriptionId)."
        try { Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId -UseDeviceAuthentication }
        catch { Write-Error "Failed to connect to Azure. Please connect manually to Tenant '$TenantId' and Subscription '$SubscriptionId' and rerun the script."; throw $_ }
        Write-Verbose "Successfully connected to Azure Tenant '$TenantId', Subscription '$SubscriptionId'."
    } else { Write-Verbose "Already connected to correct Azure context (Tenant: $($currentContext.Tenant.Id), Subscription: $($currentContext.Subscription.Id))." }
    try { Write-Verbose "Retrieving secret '$SecretName' from Key Vault '$VaultName'..."; $secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -AsPlainText -ErrorAction Stop; Write-Verbose "Secret retrieved successfully."; return $secret }
    catch { Write-Error "Failed to retrieve secret '$SecretName' from Key Vault '$VaultName'. Error: $($_.Exception.Message)"; throw $_ }
}

# --- Get-InitialRefreshToken ---
function Get-InitialRefreshToken {
    param (
        [Parameter(Mandatory=$true)][string]$TenantId, [Parameter(Mandatory=$true)][guid]$ClientId,
        [Parameter(Mandatory=$true)][string]$ClientSecret, [Parameter(Mandatory=$true)][string]$RedirectUri,
        # Scopes needed for the USER: Partner Center API access, basic Graph read, and offline_access for refresh token
        [string[]]$Scopes = @( "https://api.partnercenter.microsoft.com/user_impersonation", "https://graph.microsoft.com/User.Read", "offline_access" )
    )
    $scopeString = [uri]::EscapeDataString(($scopes -join " ")); Write-Verbose "DEBUG: Scopes being requested for initial auth: $($scopes -join " ")"
    $authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?client_id=$ClientId&response_type=code&redirect_uri=$([uri]::EscapeDataString($RedirectUri))&response_mode=query&scope=$scopeString&prompt=consent" # Added prompt=consent for clarity
    Write-Host "Opening browser for interactive login and consent. Please authenticate and copy the *full* redirected URL from your browser's address bar after successful login." -ForegroundColor Yellow
    try { Start-Process $authUrl } catch { Write-Warning "Could not automatically open browser. Please manually navigate to:"; Write-Host $authUrl }

    $redirectedUrl = Read-Host "Paste the full redirected URL here"
    Write-Host "DEBUG: URL pasted by user: '$redirectedUrl'" -ForegroundColor Magenta # Debugging user input

    $uri = $null; try { Write-Verbose "Attempting to parse '$redirectedUrl' as System.Uri..."; $uri = [System.Uri]$redirectedUrl; Write-Verbose "Successfully parsed as URI. Query part: '$($uri.Query)'" }
    catch { Write-Error "Invalid URL pasted. Could not parse as System.Uri. Error: $($_.Exception.Message)"; throw "Halting script: Invalid URL provided." }

    $queryHashtable = $null
    if ([string]::IsNullOrWhiteSpace($uri.Query)) { Write-Warning "URI query string is empty."; $queryHashtable = @{} }
    else {
        try {
            Write-Verbose "Attempting to parse query string: '$($uri.Query)' using PowerShell native method..."
            $queryString = $uri.Query.TrimStart('?'); $pairs = $queryString -split '&'; $queryHashtable = @{}
            foreach ($pair in $pairs) {
                 $keyValue = $pair -split '=', 2;
                 if ($keyValue.Length -eq 2) {
                     $key = try { [System.Net.WebUtility]::UrlDecode($keyValue[0]) } catch { $keyValue[0] }
                     $value = try { [System.Net.WebUtility]::UrlDecode($keyValue[1]) } catch { $keyValue[1] }
                     $queryHashtable[$key] = $value;
                     Write-Verbose "Parsed Pair: Key='$key', Value='$value'"
                } elseif ($keyValue.Length -eq 1 -and -not [string]::IsNullOrWhiteSpace($keyValue[0])) {
                     $key = try { [System.Net.WebUtility]::UrlDecode($keyValue[0]) } catch { $keyValue[0] }
                     $queryHashtable[$key] = $null;
                     Write-Verbose "Parsed Pair (no value): Key='$key'"
                }
            }
            Write-Host "DEBUG: Parsed query parameters (Hashtable):" -ForegroundColor Magenta
            if ($queryHashtable.Count -gt 0) { $queryHashtable.GetEnumerator() | ForEach-Object { Write-Host "  - Key: '$($_.Name)' , Value: '$($_.Value)'" -ForegroundColor Magenta } } else { Write-Host "  - Hashtable is empty after parsing." -ForegroundColor Magenta }
        } catch { Write-Error "Could not parse query string from URL using PowerShell native method. Error: $($_.Exception.Message)"; $queryHashtable = $null }
    }

    $authorizationCode = $null
    if ($queryHashtable -ne $null) {
        if ($queryHashtable.ContainsKey('code')) { $authorizationCode = $queryHashtable['code']; Write-Verbose "Found 'code' key in query parameters." }
        elseif ($queryHashtable.ContainsKey('error')) { $errorCode = $queryHashtable['error']; $errorDescription = if($queryHashtable.ContainsKey('error_description')) { $queryHashtable['error_description'] } else { '(No description provided)' }; Write-Error "Error returned in redirected URL. Error Code: '$errorCode', Description: '$errorDescription'"; throw "Halting script: Authentication failed. Error received in redirect URL." }
        else { if ($queryHashtable.Keys.Count -eq 0) { Write-Warning "Query parameters parsed, but no keys were found." } else { Write-Warning "Query parameters parsed, but neither 'code' nor 'error' key was found among keys: $($queryHashtable.Keys -join ', ')" } }
    } else { Write-Warning "Query Hashtable is null (parsing failed), cannot check for 'code' or 'error' keys." }

    if ([string]::IsNullOrWhiteSpace($authorizationCode)) { throw "Could not extract authorization code from the provided URL. Ensure you pasted the full URL after redirection and that it did not contain an error, or check previous parsing errors." }
    Write-Verbose "Authorization code successfully extracted."

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    # Exchange the authorization code for tokens, including a refresh token.
    # DO NOT request specific resource scopes here; the code grant handles the scopes requested initially.
    $body = @{ grant_type="authorization_code"; client_id=$ClientId; client_secret=$ClientSecret; code=$authorizationCode; redirect_uri=$RedirectUri }

    try {
        Write-Verbose "Exchanging authorization code for tokens...";
        $response = Invoke-RestMethod -Method POST -Uri $tokenEndpoint -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop -TimeoutSec 120 # Added TimeoutSec
        Write-Host "Initial Refresh Token obtained successfully." -ForegroundColor Green; return $response.refresh_token
    } catch {
        # Detailed error handling for token exchange
        $errorMessage = "No specific error message captured."; $rawErrorResponse = "N/A"; $requestBodySent = "N/A"; $responseStream = $null; $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode
             Write-Verbose "Token exchange failed with Status Code: $statusCode"
            try {
                $responseStream = $_.Exception.Response.GetResponseStream()
                if ($responseStream -ne $null -and $responseStream.CanRead) { $reader = [System.IO.StreamReader]::new($responseStream); $rawErrorResponse = $reader.ReadToEnd(); $reader.Dispose() } else { $rawErrorResponse = "Response stream was null or not readable." }
                if ($responseStream -ne $null) { $responseStream.Dispose() }
            } catch { $rawErrorResponse = "Could not read raw response stream. Read Error: $($_.Exception.Message)"; if ($responseStream -ne $null) { try { $responseStream.Dispose() } catch {} } }

            if ($rawErrorResponse -ne "N/A" -and $rawErrorResponse -notmatch "Could not read raw response stream|Response stream was null" -and $rawErrorResponse.Trim().StartsWith("{") -and $rawErrorResponse.Trim().EndsWith("}")) {
                try { $errorObject = $rawErrorResponse | ConvertFrom-Json; $errorMessage = "Parsed Error: $($errorObject.error), Description: $($errorObject.error_description)" }
                catch { $errorMessage = "Failed to parse raw response from token endpoint as JSON. Status Code: $statusCode. Parsing Error: $($_.Exception.Message)" }
            } else { $errorMessage = "Token endpoint error. Status Code: $statusCode. Raw response was not parsed as JSON." }

        } elseif ($_.Exception) { $errorMessage = $_.Exception.Message } else { $errorMessage = "Unknown error during token exchange."}
        try { $requestBodySent = $body | ConvertTo-Json -Depth 3 } catch { $requestBodySent = "Could not convert request body to JSON for display."}
        Write-Error "Failed to exchange authorization code for tokens." -ErrorAction Continue; Write-Error "Specific Error: $errorMessage" -ErrorAction Continue
        Write-Host "-------------------- Request Details (Token Exchange) --------------------" -ForegroundColor DarkYellow; Write-Host "Endpoint URI: $tokenEndpoint" -ForegroundColor DarkYellow; Write-Host "Request Body Sent: $requestBodySent" -ForegroundColor DarkYellow
        Write-Host "-------------------- Raw Error Response (Token Exchange) -------------------" -ForegroundColor DarkYellow; Write-Host $rawErrorResponse -ForegroundColor DarkYellow; Write-Host "------------------------------------------------------------------------" -ForegroundColor DarkYellow
        throw "Halting script: Failed to obtain initial refresh token."
    }
}

# --- Get-AccessTokenUsingRefreshToken ---
function Get-AccessTokenUsingRefreshToken {
    param (
        [Parameter(Mandatory=$true)][string]$TenantId, [Parameter(Mandatory=$true)][guid]$ClientId,
        [Parameter(Mandatory=$true)][string]$ClientSecret, [Parameter(Mandatory=$true)][string]$RefreshToken,
        [Parameter(Mandatory=$true)][string]$Scope # e.g., "https://graph.microsoft.com/.default" or "https://api.partnercenter.microsoft.com/.default"
    )
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{ client_id=$ClientId; client_secret=$ClientSecret; scope=$Scope; refresh_token=$RefreshToken; grant_type="refresh_token" }
    try {
        Write-Verbose "Requesting Access Token for scope '$Scope' in tenant '$TenantId' using Refresh Token..."; $response = Invoke-RestMethod -Method POST -Uri $tokenEndpoint -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop -TimeoutSec 120 # Added TimeoutSec
        Write-Verbose "Access Token obtained successfully for scope '$Scope'."; return $response.access_token
    } catch {
        # Detailed error handling for refresh token exchange
        $errorMessage = "No specific error message captured."; $rawErrorResponse = "N/A"; $statusCode = $null; $responseStream = $null
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode;
            Write-Verbose "Refresh token exchange failed with Status Code: $statusCode"
            try {
                $responseStream = $_.Exception.Response.GetResponseStream(); if ($responseStream -ne $null -and $responseStream.CanRead) { $reader = [System.IO.StreamReader]::new($responseStream); $rawErrorResponse = $reader.ReadToEnd(); $reader.Dispose() } else { $rawErrorResponse = "Response stream was null or not readable." }; if ($responseStream -ne $null) { $responseStream.Dispose() }
            } catch { $rawErrorResponse = "Could not read raw response stream (Refresh Token). Read Error: $($_.Exception.Message)"; if ($responseStream -ne $null) { try { $responseStream.Dispose() } catch {} } }

             if ($rawErrorResponse -ne "N/A" -and $rawErrorResponse -notmatch "Could not read raw response stream|Response stream was null" -and $rawErrorResponse.Trim().StartsWith("{") -and $rawErrorResponse.Trim().EndsWith("}")) {
                 try { $errorObject = $rawErrorResponse | ConvertFrom-Json; $errorMessage = "Parsed Error: $($errorObject.error), Description: $($errorObject.error_description)" }
                 catch { $errorMessage = "Failed to parse raw response from token endpoint as JSON (Refresh Token). Status Code: $statusCode. Parsing Error: $($_.Exception.Message)" }
            } else { $errorMessage = "Refresh Token endpoint error. Status Code: $statusCode. Raw response was not parsed as JSON." }

        } elseif ($_.Exception) { $errorMessage = $_.Exception.Message } else { $errorMessage = "Unknown error during token acquisition." }
        Write-Error "Failed to obtain Access Token using Refresh Token for scope '$Scope' in tenant '$TenantId'." -ErrorAction Continue; Write-Error "Specific Error: $errorMessage" -ErrorAction Continue
        Write-Host "--- Raw Error Response (Get-AccessTokenUsingRefreshToken) ---" -ForegroundColor DarkYellow; Write-Host $rawErrorResponse -ForegroundColor DarkYellow; Write-Host "-----------------------------------------------------------" -ForegroundColor DarkYellow
        if ($errorMessage -match 'invalid_grant' -or $errorMessage -match 'refresh token is expired' -or $errorMessage -match 'AADSTS70008' -or $statusCode -eq [System.Net.HttpStatusCode]::BadRequest) { Write-Warning "The refresh token may have expired or be invalid for tenant '$TenantId' / scope '$Scope'. You might need to rerun the script to get a new one via interactive login." }
        throw $_ # Rethrow to halt execution in the main script if needed
    }
}

# --- Invoke-PartnerCenterAppConsent ---
function Invoke-PartnerCenterAppConsent {
    param(
        [Parameter(Mandatory=$true)][string]$PartnerCenterAccessToken, # Token obtained acting as the Partner User
        [Parameter(Mandatory=$true)][string]$CustomerTenantId,
        [Parameter(Mandatory=$true)][guid]$TargetAppId, # The App ID of YOUR multi-tenant app
        # Define the specific DELEGATED Graph permissions needed for the subsequent steps
        [Parameter(Mandatory=$true)][string[]]$RequiredDelegatedScopes = @("AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All")
    )
    # This API grants DELEGATED permissions for Microsoft Graph (00000003-...)
    $graphApiEnterpriseAppId = "00000003-0000-0000-c000-000000000000"
    $scopeString = ($RequiredDelegatedScopes -join ",");
    # The payload tells Partner Center API: Grant these delegated scopes for the Graph API, for our Target Application, within this Customer's tenant.
    $consentPayload = @{
        applicationId = $TargetAppId.ToString(); # Your multi-tenant App ID
        applicationGrants = @(
            @{
                enterpriseApplicationId = $graphApiEnterpriseAppId; # Target API (Microsoft Graph)
                scope = $scopeString # Comma-separated DELEGATED scopes
            }
            # Add other APIs here if needed, e.g., legacy Azure AD Graph
        )
    } | ConvertTo-Json -Depth 5

    $uri = "https://api.partnercenter.microsoft.com/v1/customers/$CustomerTenantId/applicationconsents";
    $headers = @{ Authorization = "Bearer $PartnerCenterAccessToken"; Accept = 'application/json'; 'Content-Type'= 'application/json' }

    Write-Verbose "Attempting to grant/update delegated consent via Partner Center POST for App '$TargetAppId' with scopes '$scopeString' in tenant '$CustomerTenantId'."; Write-Verbose "Using Partner Center API URI: $uri"

    try {
        Invoke-RestMethod -Uri $uri -Headers $headers -Method POST -Body $consentPayload -ContentType 'application/json' -ErrorAction Stop -TimeoutSec 120 # Added TimeoutSec
        Write-Host "Successfully granted/updated Partner Center delegated consent for App '$TargetAppId' in customer tenant '$CustomerTenantId'." -ForegroundColor Green; return $true
    }
    catch {
        $errorMessage = "No specific error message captured."; $rawErrorResponse = "N/A"; $statusCode = $null; $responseStream = $null

        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode
            Write-Verbose "Partner Center API call failed with Status Code: $statusCode"
            try {
                $responseStream = $_.Exception.Response.GetResponseStream(); if ($responseStream -ne $null -and $responseStream.CanRead) { $reader = [System.IO.StreamReader]::new($responseStream); $rawErrorResponse = $reader.ReadToEnd(); $reader.Dispose() } else { $rawErrorResponse = "Response stream was null or not readable." }; if ($responseStream -ne $null) { $responseStream.Dispose() }
            } catch { $rawErrorResponse = "Could not read raw response stream. Read Error: $($_.Exception.Message)"; if ($responseStream -ne $null) { try { $responseStream.Dispose() } catch {} } }

            if ($rawErrorResponse -ne "N/A" -and $rawErrorResponse -notmatch "Could not read raw response stream|Response stream was null" -and $rawErrorResponse.Trim().StartsWith("{") -and $rawErrorResponse.Trim().EndsWith("}")) {
                 try {
                     $errorObject = $rawErrorResponse | ConvertFrom-Json; $pcErrorCode = $errorObject | Select-Object -ExpandProperty code -ErrorAction SilentlyContinue; $pcErrorDesc = $errorObject | Select-Object -ExpandProperty description -ErrorAction SilentlyContinue; if (-not $pcErrorDesc) { $pcErrorDesc = $errorObject | Select-Object -ExpandProperty message -ErrorAction SilentlyContinue }; if (-not $pcErrorDesc) { $pcErrorDesc = $errorObject | Select-Object -ExpandProperty error -ErrorAction SilentlyContinue }; if ($pcErrorDesc -is [PSCustomObject]){ $pcErrorDesc = $pcErrorDesc | ConvertTo-Json -Depth 2 }; $errorMessage = "Parsed Error: Code='$pcErrorCode', Description='$pcErrorDesc'"
                 } catch { $errorMessage = "Failed to parse raw response from Partner Center API as JSON. Status Code: $statusCode. Parsing Error: $($_.Exception.Message)" }
            } else { $errorMessage = "Partner Center API error. Status Code: $statusCode. Raw response was not parsed as JSON." }

        } elseif ($_.Exception) { $errorMessage = $_.Exception.Message } else { $errorMessage = "Unknown error during Partner Center API call." }

        if ($statusCode -eq [System.Net.HttpStatusCode]::Forbidden -or $statusCode -eq [System.Net.HttpStatusCode]::Unauthorized -or $errorMessage -match 'Authorization_RequestDenied' -or $errorMessage -match 'authorization has been denied') { Write-Warning "Received status code $statusCode or authorization error. Often indicates missing/insufficient GDAP permissions/roles for the logged-in user over customer '$CustomerTenantId'."}

        # 409 Conflict usually means the exact consent grant already exists. Treat as success for script flow.
        if ($statusCode -eq [System.Net.HttpStatusCode]::Conflict) {
            Write-Warning "Partner Center consent likely already exists with matching scopes (Conflict 409) for App '$TargetAppId' in tenant '$CustomerTenantId'. (Detailed error: $errorMessage)";
            Write-Host "--- Raw Partner Center Response (Conflict) ---" -ForegroundColor DarkYellow; Write-Host $rawErrorResponse -ForegroundColor DarkYellow; Write-Host "--------------------------------------------" -ForegroundColor DarkYellow
            return $true # Treat conflict as success for script flow
        }

        # For any other error
        Write-Error "Failed Partner Center API Call: Invoke-PartnerCenterAppConsent for customer '$CustomerTenantId'." -ErrorAction Continue; Write-Error "Specific Error Message: $errorMessage" -ErrorAction Continue
        Write-Host "-------------------- Raw Partner Center Error Response -------------------" -ForegroundColor DarkYellow; Write-Host $rawErrorResponse -ForegroundColor DarkYellow; Write-Host "------------------------------------------------------------------------" -ForegroundColor DarkYellow
        return $false # Indicate failure
    }
}

# --- Get-ServicePrincipalObjectId ---
function Get-ServicePrincipalObjectId {
    param (
        [Parameter(Mandatory=$true)][string]$GraphAccessToken,
        [Parameter(ParameterSetName='ByAppId', Mandatory=$true)][guid]$AppId,
        [Parameter(ParameterSetName='ByAppName', Mandatory=$true)][string]$AppName,
        [Parameter(Mandatory=$true)][string]$TenantIdForVerbose # For logging context
    )
    $headers = @{ Authorization = "Bearer $GraphAccessToken"; Accept = 'application/json'; 'ConsistencyLevel' = 'eventual' } # ConsistencyLevel needed for some filters
    if ($PSCmdlet.ParameterSetName -eq 'ByAppId') { $filter = "appId eq '$($AppId.ToString())'"; $lookupValue = $AppId.ToString() }
    else { $filter = "displayName eq '$($AppName -replace "'", "''")'"; $lookupValue = $AppName } # Handle single quotes in names

    # Select only needed properties
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=" + [uri]::EscapeDataString($filter) + "&`$select=id,appId,displayName"
    Write-Verbose "Looking up Service Principal '$lookupValue' in tenant '$TenantIdForVerbose' using filter '$filter' via URI: $uri"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop -TimeoutSec 120 # Added TimeoutSec
        if ($response.value.Count -eq 1) { Write-Verbose "Found Service Principal. ID: $($response.value[0].id)"; return $response.value[0].id }
        elseif ($response.value.Count -gt 1) { Write-Warning "Multiple SPNs match '$lookupValue' in tenant '$TenantIdForVerbose'. Returning first found: $($response.value[0].id)."; return $response.value[0].id }
        else { Write-Warning "Service Principal '$lookupValue' not found in tenant '$TenantIdForVerbose'."; return $null }
    } catch {
        # Improved Catch Block
        $errorMessage = "No specific error message captured."; $rawErrorResponse = "N/A"; $statusCode = $null; $responseStream = $null
         if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode
            Write-Verbose "Get SPN failed with Status Code: $statusCode"
            try {
                $responseStream = $_.Exception.Response.GetResponseStream(); if ($responseStream -ne $null -and $responseStream.CanRead) { $reader = [System.IO.StreamReader]::new($responseStream); $rawErrorResponse = $reader.ReadToEnd(); $reader.Dispose() } else { $rawErrorResponse = "Response stream was null or not readable." } ; if ($responseStream -ne $null) { $responseStream.Dispose() }
            } catch { $rawErrorResponse = "Could not read raw response stream (Get SPN). Read Error: $($_.Exception.Message)"; if ($responseStream -ne $null) { try { $responseStream.Dispose() } catch {} } }

            if ($rawErrorResponse -ne "N/A" -and $rawErrorResponse -notmatch "Could not read raw response stream|Response stream was null" -and $rawErrorResponse.Trim().StartsWith("{") -and $rawErrorResponse.Trim().EndsWith("}")) {
                try { $errorObject = $rawErrorResponse | ConvertFrom-Json; $errorMessage = "Parsed Error: $($errorObject.error.message)" } # Common Graph error structure
                catch { $errorMessage = "Failed to parse Graph error response as JSON (Get SPN). Status Code: $statusCode. Parsing Error: $($_.Exception.Message)" }
            } else { $errorMessage = "Get SPN error. Status Code: $statusCode. Raw response not parsed as JSON." }
        } elseif ($_.Exception) { $errorMessage = $_.Exception.Message } else { $errorMessage = "Unknown error querying Service Principals." }
        Write-Error "Failed to query Service Principals for '$lookupValue' in tenant '$TenantIdForVerbose'. Error: $errorMessage"; Write-Host "--- Raw Error Response (Get-ServicePrincipalObjectId) ---" -ForegroundColor DarkYellow; Write-Host $rawErrorResponse -ForegroundColor DarkYellow; Write-Host "-------------------------------------------------------" -ForegroundColor DarkYellow
        return $null # Indicate failure
    }
}

# --- Get-AppGrantedApplicationPermissions ---
function Get-AppGrantedApplicationPermissions {
    param (
        [Parameter(Mandatory=$true)][string]$GraphAccessToken, # Use APP's identity token for the customer tenant
        [Parameter(Mandatory=$true)][guid]$ServicePrincipalObjectId, # The Object ID of YOUR app's SPN in the customer tenant
        [Parameter(Mandatory=$true)][string]$TenantIdForVerbose # For logging context
    )
    # This endpoint lists app roles assigned TO the specified service principal
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalObjectId/appRoleAssignments"
    $headers = @{ Authorization = "Bearer $GraphAccessToken"; Accept = 'application/json' }
    Write-Verbose "Getting current APPLICATION role assignments for Service Principal '$ServicePrincipalObjectId' in tenant '$TenantIdForVerbose' using URI $uri"

    try {
        $allAssignments = @(); $pagedUri = $uri
        do {
            Write-Verbose "Fetching app role assignments page: $pagedUri"
            $response = Invoke-RestMethod -Method Get -Uri $pagedUri -Headers $headers -ErrorAction Stop -TimeoutSec 120 # Added TimeoutSec
            if ($response.value) { $allAssignments += $response.value }; $pagedUri = $response.'@odata.nextLink'
        } while ($pagedUri)
        Write-Verbose "Found $($allAssignments.Count) application role assignments."
        # Return only the IDs of the roles assigned
        return $allAssignments | Select-Object -ExpandProperty AppRoleId -ErrorAction SilentlyContinue
    } catch {
        # Improved Catch Block
        $errorMessage = "No specific error message captured."; $rawErrorResponse = "N/A"; $statusCode = $null; $responseStream = $null
         if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode
            Write-Verbose "Get App Roles failed with Status Code: $statusCode"
            try {
                $responseStream = $_.Exception.Response.GetResponseStream(); if ($responseStream -ne $null -and $responseStream.CanRead) { $reader = [System.IO.StreamReader]::new($responseStream); $rawErrorResponse = $reader.ReadToEnd(); $reader.Dispose() } else { $rawErrorResponse = "Response stream was null or not readable." } ; if ($responseStream -ne $null) { $responseStream.Dispose() }
            } catch { $rawErrorResponse = "Could not read raw response stream (Get App Roles). Read Error: $($_.Exception.Message)"; if ($responseStream -ne $null) { try { $responseStream.Dispose() } catch {} } }

            if ($rawErrorResponse -ne "N/A" -and $rawErrorResponse -notmatch "Could not read raw response stream|Response stream was null" -and $rawErrorResponse.Trim().StartsWith("{") -and $rawErrorResponse.Trim().EndsWith("}")) {
                 try { $errorObject = $rawErrorResponse | ConvertFrom-Json; $errorMessage = "Parsed Error: $($errorObject.error.message)" }
                 catch { $errorMessage = "Failed to parse Graph error response as JSON (Get App Roles). Status Code: $statusCode. Parsing Error: $($_.Exception.Message)" }
            } else { $errorMessage = "Get App Roles error. Status Code: $statusCode. Raw response not parsed as JSON." }

            # Specific check for Forbidden - often means the app itself lacks AppRoleAssignment.Read(Write).All Application permission
             if ($statusCode -eq [System.Net.HttpStatusCode]::Forbidden -or $errorMessage -match 'Authorization_RequestDenied' -or $errorMessage -match 'Insufficient privileges') {
                 Write-Warning "Received Forbidden (403) or Authorization_RequestDenied error when trying to read app role assignments for SPN '$ServicePrincipalObjectId'."
                 Write-Warning "This LIKELY means the application SPN '$ServicePrincipalObjectId' is MISSING the 'AppRoleAssignment.Read.All' or 'AppRoleAssignment.ReadWrite.All' APPLICATION permission (Type: Role) in tenant '$TenantIdForVerbose'."
                 Write-Warning "The script will attempt to grant 'AppRoleAssignment.ReadWrite.All' first if it's in the manifest."
             }
        } elseif ($_.Exception) { $errorMessage = $_.Exception.Message } else { $errorMessage = "Unknown error getting app role assignments."}
        Write-Error "Failed to get application role assignments for SPN '$ServicePrincipalObjectId' in tenant '$TenantIdForVerbose'. Error: $errorMessage";
        Write-Host "--- Raw Error Response (Get-AppGrantedApplicationPermissions) ---" -ForegroundColor DarkYellow; Write-Host $rawErrorResponse -ForegroundColor DarkYellow; Write-Host "-----------------------------------------------------------------" -ForegroundColor DarkYellow
        # --- Return $null on failure --- indicates roles could not be determined
        return $null
    }
}

# --- Grant-ApplicationPermission ---
function Grant-ApplicationPermission {
    param (
        [Parameter(Mandatory=$true)][string]$GraphAccessToken, # Use APP's identity token for customer tenant
        [Parameter(Mandatory=$true)][guid]$AppServicePrincipalObjectId, # The Object ID of YOUR app's SPN
        [Parameter(Mandatory=$true)][guid]$ResourceApiObjectId, # The Object ID of the TARGET API's SPN (e.g., Microsoft Graph SPN)
        [Parameter(Mandatory=$true)][guid]$AppRoleId, # The ID of the Application Permission (Role) to grant
        [Parameter(Mandatory=$true)][string]$TenantIdForVerbose, # For logging context
        [Parameter(Mandatory=$true)][string]$PermissionNameForVerbose # For logging context (can be Role ID if name unknown)
    )
    # This endpoint creates an assignment of an app role TO a service principal
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$AppServicePrincipalObjectId/appRoleAssignments"
    $headers = @{ Authorization = "Bearer $GraphAccessToken"; 'Content-Type' = 'application/json' }
    # Body: Assign this role ($AppRoleId) from this resource API ($ResourceApiObjectId) to this principal ($AppServicePrincipalObjectId)
    $body = @{
        principalId = $AppServicePrincipalObjectId.ToString(); # Who gets the permission (Your App SPN)
        resourceId = $ResourceApiObjectId.ToString(); # The SPN of the API offering the role (e.g., Graph SPN)
        appRoleId = $AppRoleId.ToString() # The specific Role ID to assign
    } | ConvertTo-Json

    Write-Verbose "Attempting to grant APPLICATION permission (AppRoleID: $AppRoleId, Name: $PermissionNameForVerbose) to SPN '$AppServicePrincipalObjectId' for resource SPN '$ResourceApiObjectId' in tenant '$TenantIdForVerbose'."
    Write-Verbose "Using Grant App Role URI: $uri"
    Write-Verbose "Request Body: $body"

    if ($PSCmdlet.ShouldProcess("Tenant $TenantIdForVerbose | Grant AppRole '$PermissionNameForVerbose' ($AppRoleId) to SPN '$AppServicePrincipalObjectId' targeting resource '$ResourceApiObjectId'", "Grant Application Permission")) {
        try {
            Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $body -ContentType "application/json" -ErrorAction Stop -TimeoutSec 120 # Added TimeoutSec
            Write-Host "Successfully granted application permission '$PermissionNameForVerbose' in tenant '$TenantIdForVerbose'." -ForegroundColor Green; return $true
        } catch {
            # Improved Catch Block
            $errorMessage = "No specific error message captured."; $rawErrorResponse = "N/A"; $statusCode = $null; $responseStream = $null
             if ($_.Exception.Response) {
                $statusCode = $_.Exception.Response.StatusCode
                Write-Verbose "Grant App Role failed with Status Code: $statusCode"
                try {
                    $responseStream = $_.Exception.Response.GetResponseStream(); if ($responseStream -ne $null -and $responseStream.CanRead) { $reader = [System.IO.StreamReader]::new($responseStream); $rawErrorResponse = $reader.ReadToEnd(); $reader.Dispose() } else { $rawErrorResponse = "Response stream was null or not readable." } ; if ($responseStream -ne $null) { $responseStream.Dispose() }
                } catch { $rawErrorResponse = "Could not read raw response stream (Grant App Role). Read Error: $($_.Exception.Message)"; if ($responseStream -ne $null) { try { $responseStream.Dispose() } catch {} } }

                if ($rawErrorResponse -ne "N/A" -and $rawErrorResponse -notmatch "Could not read raw response stream|Response stream was null" -and $rawErrorResponse.Trim().StartsWith("{") -and $rawErrorResponse.Trim().EndsWith("}")) {
                    try { $errorObject = $rawErrorResponse | ConvertFrom-Json; $errorMessage = "Parsed Error: $($errorObject.error.message)" }
                    catch { $errorMessage = "Failed to parse Graph error response as JSON (Grant App Role). Status Code: $statusCode. Parsing Error: $($_.Exception.Message)" }
                } else { $errorMessage = "Grant App Role error. Status Code: $statusCode. Raw response not parsed as JSON." }

                # Check for common permission errors
                if ($statusCode -eq [System.Net.HttpStatusCode]::Forbidden -or $errorMessage -match 'Authorization_RequestDenied' -or $errorMessage -match 'Insufficient privileges') {
                     Write-Warning "Received Forbidden (403) or Authorization error when trying to grant permission '$PermissionNameForVerbose'."
                     Write-Warning "Ensure the application SPN '$AppServicePrincipalObjectId' has the 'AppRoleAssignment.ReadWrite.All' APPLICATION permission (Type: Role) in tenant '$TenantIdForVerbose'."
                 }
                 # Check if assignment already exists (sometimes reported differently than expected)
                 if ($errorMessage -match 'Permission being assigned already exists on the object') {
                     Write-Warning "Grant failed for '$PermissionNameForVerbose' because the assignment likely already exists for SPN '$AppServicePrincipalObjectId'."
                     # Consider returning $true here if this should not be treated as a failure
                 }

            } elseif ($_.Exception) { $errorMessage = $_.Exception.Message } else { $errorMessage = "Unknown error granting application permission."}
            Write-Error "Failed to grant application permission '$PermissionNameForVerbose' in tenant '$TenantIdForVerbose'. Error: $errorMessage"; Write-Host "--- Raw Error Response (Grant-ApplicationPermission) ---" -ForegroundColor DarkYellow; Write-Host $rawErrorResponse -ForegroundColor DarkYellow; Write-Host "--------------------------------------------------------" -ForegroundColor DarkYellow
            return $false # Indicate failure
        }
    } else { Write-Warning "Skipped granting permission '$PermissionNameForVerbose' due to -WhatIf."; return $false } # Return false for WhatIf
}

#endregion Helper Functions

# --- Main Script ---

# Set error action preference to Stop to halt on unexpected function errors
# $ErrorActionPreference = 'Stop' # Consider uncommenting for production runs
$ProgressPreference = 'SilentlyContinue'
Write-Verbose "Script starting. PartnerTenantId = $PartnerTenantId, AppId = $AppId"

# Define the standard DELEGATED Graph scopes we want granted via Partner Center / GDAP
# These allow the logged-in partner user (via the script) to manage app assignments/consent in customer tenants
$requiredPartnerCenterDelegatedGraphScopes = @(
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All"
)
$graphApiAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph App ID (used for looking up SPN and in manifest)
# Define the specific AppRoleAssignment permission needed for the app to self-manage permissions
$appRoleAssignmentReadWriteAllRoleId_AppPerm = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" # Guid for Graph AppRoleAssignment.ReadWrite.All (Type=Role)

# --- 1. Get Secret ---
Write-Host "`nStep 1: Retrieving Application Secret from Key Vault..." -ForegroundColor Green
$clientSecret = $null;
try {
    $clientSecret = Get-AppSecretFromKeyVault -SubscriptionId $KeyVaultSubscriptionId -VaultName $KeyVaultName -SecretName $KeyVaultSecretName -TenantId $PartnerTenantId -ErrorAction Stop
} catch {
    Write-Error "Halting script: Failed during secret retrieval. Error: $($_.Exception.Message)"; exit 1
};
if ([string]::IsNullOrWhiteSpace($clientSecret)) {
    Write-Error "Halting script: Could not retrieve client secret (returned empty/null). Check Key Vault name, secret name, and permissions."; exit 1
};
Write-Host "Application Secret retrieved."

# --- 2. Get Initial Refresh Token (Interactive) ---
Write-Host "`nStep 2: Obtaining Initial Refresh Token (Interactive Login Required)..." -ForegroundColor Green
$Global:InitialRefreshToken = $null;
try {
    # Request scopes needed for Partner Center API (user_impersonation) and basic graph read + offline access
    $Global:InitialRefreshToken = Get-InitialRefreshToken -TenantId $PartnerTenantId -ClientId $AppId -ClientSecret $clientSecret -RedirectUri $RedirectUri -ErrorAction Stop
} catch {
    Write-Error "Halting script: Failed to obtain initial refresh token during call to Get-InitialRefreshToken. Error: $($_.Exception.Message)"; exit 1
};
if ([string]::IsNullOrWhiteSpace($Global:InitialRefreshToken)) {
    Write-Error "Halting script: Refresh Token is empty after attempting to obtain it. Interactive login may have failed or code extraction issue."; exit 1
};
Write-Host "Refresh Token ready."

# --- 3. Get Partner Center Access Token ---
# This token represents the INTERACTIVE USER acting via Partner Center
Write-Host "`nStep 3: Obtaining Partner Center Access Token (User Context)..." -ForegroundColor Green
$partnerCenterAccessToken = $null;
try {
    # Scope for Partner Center API
    $partnerCenterAccessToken = Get-AccessTokenUsingRefreshToken -TenantId $PartnerTenantId -ClientId $AppId -ClientSecret $clientSecret -RefreshToken $Global:InitialRefreshToken -Scope 'https://api.partnercenter.microsoft.com/.default' -ErrorAction Stop
} catch {
    Write-Error "Halting script: Could not obtain Partner Center access token. Error: $($_.Exception.Message)"; exit 1
};
if ([string]::IsNullOrWhiteSpace($partnerCenterAccessToken)) {
    Write-Error "Halting script: Partner Center Access Token is empty after attempting to obtain it."; exit 1
};
Write-Host "Partner Center Access Token obtained."

# --- 4. Get Customers from Partner Center ---
Write-Host "`nStep 4: Retrieving customer list from Partner Center..." -ForegroundColor Green
$allCustomers = @()
$pcCustomersUri = "https://api.partnercenter.microsoft.com/v1/customers";
$pcHeaders = @{ Authorization = "Bearer $partnerCenterAccessToken"; Accept = 'application/json' }
try {
    do {
         Write-Verbose "Fetching customers from URI: $pcCustomersUri";
         $customerResponse = Invoke-RestMethod -Uri $pcCustomersUri -Headers $pcHeaders -Method Get -TimeoutSec 120 -ErrorAction Stop; # Added TimeoutSec
         if ($customerResponse -and $customerResponse.items) { $allCustomers += $customerResponse.items } else { Write-Verbose "No 'items' property found in customer response chunk or response was null." };
         $continuationToken = $null;
         # Handle potential variations in nextLink structure
         if ($customerResponse -and $customerResponse.links -and $customerResponse.links.next) {
             if($customerResponse.links.next.headers -and $customerResponse.links.next.headers.'MS-ContinuationToken') {
                $continuationToken = $customerResponse.links.next.headers.'MS-ContinuationToken'
             }
             if ($continuationToken) {
                 Write-Verbose "Found continuation token.";
                 # Rebuild headers for next request with the token
                 $pcHeaders = @{ Authorization = "Bearer $partnerCenterAccessToken"; Accept = 'application/json'; 'MS-ContinuationToken' = $continuationToken };
                 # Ensure the URI is correctly formed for the next page
                 if ($customerResponse.links.next.uri) {
                     if ($customerResponse.links.next.uri.StartsWith("http")) { $pcCustomersUri = $customerResponse.links.next.uri }
                     else { $pcCustomersUri = "https://api.partnercenter.microsoft.com" + $customerResponse.links.next.uri } # Prepend base URL if relative
                 } else {$pcCustomersUri = $null} # Stop if URI is missing
             } else { Write-Verbose "No continuation token found in headers. Ending customer retrieval."; $pcCustomersUri = $null }
        } else { Write-Verbose "No 'links' or 'links.next' property found. Ending customer retrieval."; $pcCustomersUri = $null }
    } while ($pcCustomersUri);
    Write-Host "Retrieved $($allCustomers.Count) customers."
} catch {
    # Improved Catch Block for Get Customers
    $errorMessage = "No specific error message captured."; $rawErrorResponse = "N/A"; $statusCode = $null; $responseStream = $null
     if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode
        Write-Verbose "Get Customers failed with Status Code: $statusCode"
        try {
            $responseStream = $_.Exception.Response.GetResponseStream(); if ($responseStream -ne $null -and $responseStream.CanRead) { $reader = [System.IO.StreamReader]::new($responseStream); $rawErrorResponse = $reader.ReadToEnd(); $reader.Dispose() } else { $rawErrorResponse = "Response stream was null or not readable." } ; if ($responseStream -ne $null) { $responseStream.Dispose() }
        } catch { $rawErrorResponse = "Could not read raw response stream (Get Customers). Read Error: $($_.Exception.Message)"; if ($responseStream -ne $null) { try { $responseStream.Dispose() } catch {} } }

        if ($rawErrorResponse -ne "N/A" -and $rawErrorResponse -notmatch "Could not read raw response stream|Response stream was null" -and $rawErrorResponse.Trim().StartsWith("{") -and $rawErrorResponse.Trim().EndsWith("}")) {
            try { $errorObject = $rawErrorResponse | ConvertFrom-Json; $errorMessage = "Parsed Error: $($errorObject.error), Description: $($errorObject.error_description)" } # Adjust props if needed for PC errors
            catch { $errorMessage = "Failed to parse Partner Center error response as JSON (Get Customers). Status Code: $statusCode. Parsing Error: $($_.Exception.Message)" }
        } else { $errorMessage = "Get Customers error. Status Code: $statusCode. Raw response not parsed as JSON." }
    } elseif ($_.Exception) { $errorMessage = $_.Exception.Message } else { $errorMessage = "Unknown error retrieving customers."};
    Write-Error "Halting script: Failed to retrieve customers from Partner Center. Error: $errorMessage"; Write-Host "--- Raw Error Response (Get Customers) ---" -ForegroundColor DarkYellow; Write-Host $rawErrorResponse -ForegroundColor DarkYellow; Write-Host "------------------------------------------" -ForegroundColor DarkYellow; exit 1
}

# --- 5. Create/Update DELEGATED Permissions via Partner Center API ---
Write-Host "`nStep 5: Ensuring DELEGATED Graph Permissions via Partner Center (Requires GDAP)..." -ForegroundColor Green
$consentSuccessCount = 0; $consentFailCount = 0; $consentSkippedCount = 0
foreach ($customer in $allCustomers) {
    $customerTenantId = $customer.companyProfile | Select-Object -ExpandProperty tenantId -ErrorAction SilentlyContinue;
    $customerName = $customer.companyProfile | Select-Object -ExpandProperty companyName -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($customerTenantId)) { Write-Warning "Skipping customer entry for Partner Consent due to missing tenantId."; $consentSkippedCount++; continue };
    if ([string]::IsNullOrWhiteSpace($customerName)) { $customerName = "(Name Missing)" }

    Write-Verbose "Checking customer '$customerName' (Tenant ID: $customerTenantId) against Partner Tenant ID: $PartnerTenantId"
    # Skip processing for the partner's own tenant
    if ($customerTenantId -eq $PartnerTenantId) {
        Write-Host "Skipping Partner Center Consent processing for own partner tenant: '$customerName' ($customerTenantId)" -ForegroundColor Cyan; $consentSkippedCount++; continue
    }
    # Validate Tenant ID format
    if (-not ($customerTenantId -as [guid])) {
        Write-Warning "Skipping invalid Tenant ID '$customerTenantId' (not a GUID) for customer '$customerName'."; $consentSkippedCount++; continue
    }

    Write-Host "Processing Partner Center DELEGATED Consent for: '$customerName' ($customerTenantId)'..." -ForegroundColor Cyan
    # Call the function to grant/update the required DELEGATED Graph scopes
    if (Invoke-PartnerCenterAppConsent -PartnerCenterAccessToken $partnerCenterAccessToken -CustomerTenantId $customerTenantId -TargetAppId $AppId -RequiredDelegatedScopes $requiredPartnerCenterDelegatedGraphScopes) {
        $consentSuccessCount++
    } else {
        $consentFailCount++;
        Write-Warning "Failed granting/updating Partner Center DELEGATED consent for '$customerName'. Check GDAP roles and previous logs. Subsequent APPLICATION permission grants (Step 6) for this tenant may fail."
    }
    Start-Sleep -Milliseconds 500 # Small delay to avoid throttling
} # End foreach customer for Step 5
Write-Host "Partner Center DELEGATED Consent Summary: Success/Updated/Conflict=$consentSuccessCount, Failures=$consentFailCount, Skipped(Partner/Invalid)=$consentSkippedCount" -ForegroundColor Yellow


# --- 6. Granting APPLICATION Permissions (Roles) via Microsoft Graph API ---
Write-Host "`nStep 6: Granting APPLICATION Permissions (Roles) via Microsoft Graph API..." -ForegroundColor Green
Write-Host "Loading permission manifest from '$PermissionManifestPath'..."
if (!(Test-Path $PermissionManifestPath)) { Write-Error "Halting script: Permission manifest file not found at '$PermissionManifestPath'."; exit 1 };
$requiredPermissionsManifest = $null;
try {
    $requiredPermissionsManifest = Get-Content $PermissionManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Halting script: Failed to load or parse permission manifest '$PermissionManifestPath'. Error: $($_.Exception.Message)"; exit 1
};
if (-not $requiredPermissionsManifest -or -not $requiredPermissionsManifest.PSObject.Properties.Name -contains 'requiredResourceAccess') {
    Write-Error "Halting script: Invalid permission manifest format. Expected a root object with a 'requiredResourceAccess' array property in '$PermissionManifestPath'."; exit 1
};
Write-Host "Permission manifest loaded. Ensuring it contains 'AppRoleAssignment.ReadWrite.All' (Type: Role) for Graph API is recommended for self-management." -ForegroundColor Cyan

# Initialize counters for the results of application permission grants
$appPermissionResults = @{ Success = 0; Failed = 0; Skipped = 0; AlreadyGranted = 0 };
$totalPermissionGrantsAttempted = 0 # Count permissions listed in manifest (excluding non-Roles)

foreach ($customer in $allCustomers) {
    $customerTenantId = $customer.companyProfile | Select-Object -ExpandProperty tenantId -ErrorAction SilentlyContinue;
    $customerName = $customer.companyProfile | Select-Object -ExpandProperty companyName -ErrorAction SilentlyContinue
     if ([string]::IsNullOrWhiteSpace($customerTenantId)) { Write-Warning "Skipping customer entry for App Permissions grant due to missing tenantId."; $appPermissionResults.Skipped++; continue };
     if ([string]::IsNullOrWhiteSpace($customerName)) { $customerName = "(Name Missing)" }

    Write-Verbose "Checking customer '$customerName' (Tenant ID: $customerTenantId) against Partner Tenant ID: $PartnerTenantId for App Permission Grant"
    # Skip processing for the partner's own tenant
    if ($customerTenantId -eq $PartnerTenantId) {
        Write-Host "Skipping APPLICATION Permission processing for own partner tenant: '$customerName' ($customerTenantId)" -ForegroundColor Cyan; $appPermissionResults.Skipped++; continue
    }
    Write-Host "-----------------------------------------------------"; Write-Host "Processing APPLICATION Permissions for: '$customerName' ($customerTenantId)" -ForegroundColor Cyan
    if (-not ($customerTenantId -as [guid])) {
        Write-Warning "Skipping invalid Tenant ID '$customerTenantId' for customer '$customerName' (App Permission Grant)."; $appPermissionResults.Skipped++; continue
    }

    # --- 6a. Get Customer Graph Token (APP Identity) ---
    # This token represents the APPLICATION itself acting within the customer tenant
    $appIdentityGraphToken = $null
    try {
        Write-Verbose "Getting APP's identity Graph token for customer tenant '$customerTenantId' using Refresh Token...";
        # Scope for Graph API, using .default to get all consented application permissions
        $appIdentityGraphToken = Get-AccessTokenUsingRefreshToken -TenantId $customerTenantId -ClientId $AppId -ClientSecret $clientSecret -RefreshToken $Global:InitialRefreshToken -Scope 'https://graph.microsoft.com/.default' -ErrorAction Stop
    } catch {
        Write-Warning "Could not obtain APP'S identity Graph token for tenant '$customerTenantId' ($customerName). Skipping application permission grants for this tenant. Error: $($_.Exception.Message) (Check if initial login/refresh token is valid & consented for this tenant, or if app principal exists)."; $appPermissionResults.Skipped++; continue # Skip this tenant
    }
    if ([string]::IsNullOrWhiteSpace($appIdentityGraphToken)) {
        Write-Warning "Obtained null/empty APP'S identity Graph token for tenant '$customerTenantId' ($customerName). Skipping grants for this tenant."; $appPermissionResults.Skipped++; continue # Skip this tenant
    }
    Write-Verbose "Obtained APP'S identity Graph token for customer tenant $customerTenantId."

    # --- 6b. Find App Service Principal (Your App's SPN in Customer Tenant) ---
    $appSpObjectId_Step6 = $null
    try {
        $appSpObjectId_Step6 = Get-ServicePrincipalObjectId -GraphAccessToken $appIdentityGraphToken -AppId $AppId -TenantIdForVerbose $customerTenantId -ErrorAction Stop
    } catch {
        Write-Warning "Failed to find App Service Principal (Step 6b) for App ID '$AppId' in tenant '$customerTenantId' ($customerName). Error: $($_.Exception.Message). Skipping grants for this tenant."; $appPermissionResults.Skipped++; continue # Skip this tenant
    }
    if (!$appSpObjectId_Step6) {
        Write-Warning "Could not find SPN (Step 6b) for App ID '$AppId' in tenant '$customerTenantId' ($customerName). Ensure Step 5 (Partner Consent) succeeded or App SPN exists. Skipping grants for this tenant."; $appPermissionResults.Skipped++; continue # Skip this tenant
    }
    Write-Verbose "Found App SPN ObjectId in customer tenant $customerTenantId: $appSpObjectId_Step6"

    # --- 6d. Get Current Application Permissions Granted to Your App's SPN ---
    Write-Verbose "Attempting to retrieve current application permissions granted TO SPN '$appSpObjectId_Step6'..."
    $currentAppRoleIdsSet = [System.Collections.Generic.HashSet[guid]]::new()
    $retrievedRoleIds = $null # Variable to hold the result from the function

    try {
        # Call the function which returns an array of GUIDs or $null on failure
        $retrievedRoleIds = Get-AppGrantedApplicationPermissions -GraphAccessToken $appIdentityGraphToken -ServicePrincipalObjectId $appSpObjectId_Step6 -TenantIdForVerbose $customerTenantId -ErrorAction Stop

        if ($null -ne $retrievedRoleIds) {
             # Success or empty list retrieved. Process the result.
             # Ensure $retrievedRoleIds is treated as an array, even if only one GUID was returned. Filter nulls/empties just in case.
             $guidArray = @($retrievedRoleIds) | Where-Object { $_ -is [guid] }
             if ($guidArray.Count -gt 0) {
                 # Use the HashSet constructor that accepts an IEnumerable<T>
                 $currentAppRoleIdsSet = [System.Collections.Generic.HashSet[guid]]::new([guid[]]$guidArray)
                 Write-Verbose "Successfully populated HashSet with $($currentAppRoleIdsSet.Count) existing assigned Role IDs."
             } else {
                 Write-Verbose "Successfully queried App Roles, but none are currently assigned to SPN '$appSpObjectId_Step6'."
                 # $currentAppRoleIdsSet remains empty
             }
        } else {
             # Function returned $null, indicating failure to retrieve roles.
             # This often happens if the app lacks AppRoleAssignment.Read.All initially.
             Write-Warning "Get-AppGrantedApplicationPermissions failed (returned null) for SPN '$appSpObjectId_Step6'. Assuming no roles assigned or unable to read. Will attempt to grant bootstrap permission if needed."
             # $currentAppRoleIdsSet remains empty HashSet, script will proceed to try granting
        }
    } catch {
        # Catch unexpected errors from the function call itself (should be caught inside, but as a fallback)
        Write-Warning "Error calling Get-AppGrantedApplicationPermissions for SPN '$appSpObjectId_Step6'. Error: $($_.Exception.Message). Assuming no roles assigned or unable to read."
        # $currentAppRoleIdsSet remains empty HashSet
    }
    Write-Verbose "Current App Role ID count determined before granting: $($currentAppRoleIdsSet.Count)"

    # --- 6e. Compare and Grant Missing Application Permissions from Manifest ---
     if (-not $requiredPermissionsManifest.requiredResourceAccess) { Write-Warning "Manifest '$PermissionManifestPath' has no 'requiredResourceAccess' array defined at the root. No permissions to process."; continue } # Skip tenant if manifest is empty/malformed

    Write-Verbose "Starting loop to grant permissions from manifest..."
    $bootstrapPermissionGrantedThisRun = $false # Track if we add the bootstrap perm now
    $manifestContainsBootstrapPermission = $false # Check if manifest requests it

    # --- Find Microsoft Graph Resource SPN ONCE for this tenant ---
    $graphResourceApiSpObjectId = $null
    try {
        $graphResourceApiSpObjectId = Get-ServicePrincipalObjectId -GraphAccessToken $appIdentityGraphToken -AppId $graphApiAppId -TenantIdForVerbose $customerTenantId -ErrorAction Stop
    } catch { Write-Warning "Could not find Microsoft Graph SPN ObjectId in tenant '$customerTenantId'. Error: $($_.Exception.Message). Cannot grant Graph permissions." }
    if (!$graphResourceApiSpObjectId) { Write-Warning "Skipping Microsoft Graph permission grants for tenant '$customerTenantId' as Graph SPN was not found." }

    # --- Pre-check and Grant Bootstrap Permission FIRST if needed and possible ---
    if ($graphResourceApiSpObjectId) { # Only attempt if Graph SPN was found
        $graphResourceEntry = $requiredPermissionsManifest.requiredResourceAccess | Where-Object { $_.resourceAppId -eq $graphApiAppId }
        if ($graphResourceEntry -and $graphResourceEntry.resourceAccess) {
            $bootstrapPermEntry = $graphResourceEntry.resourceAccess | Where-Object { $_.id -eq $appRoleAssignmentReadWriteAllRoleId_AppPerm -and $_.type -eq 'Role'}
            if ($bootstrapPermEntry) {
                $manifestContainsBootstrapPermission = $true
                $requiredBootstrapRoleId = [guid]$bootstrapPermEntry.id
                Write-Verbose "Manifest contains bootstrap permission 'AppRoleAssignment.ReadWrite.All' ($requiredBootstrapRoleId). Checking grant status..."

                if (-not $currentAppRoleIdsSet.Contains($requiredBootstrapRoleId)) {
                     Write-Host "Attempting to grant bootstrap permission 'AppRoleAssignment.ReadWrite.All' ($requiredBootstrapRoleId) as it appears missing..." -ForegroundColor Yellow
                     $grantBootstrapSuccess = $false
                     try {
                         # Use the Graph token representing the App's identity
                         $grantBootstrapSuccess = Grant-ApplicationPermission `
                            -GraphAccessToken $appIdentityGraphToken `
                            -AppServicePrincipalObjectId $appSpObjectId_Step6 `
                            -ResourceApiObjectId $graphResourceApiSpObjectId `
                            -AppRoleId $requiredBootstrapRoleId `
                            -TenantIdForVerbose $customerTenantId `
                            -PermissionNameForVerbose "AppRoleAssignment.ReadWrite.All [Bootstrap]" `
                            -ErrorAction Stop
                     } catch { Write-Warning "Grant-ApplicationPermission call failed unexpectedly for bootstrap permission. Error: $($_.Exception.Message)" } # Catch should ideally be inside function

                     if ($grantBootstrapSuccess) {
                         Write-Host "Bootstrap permission AppRoleAssignment.ReadWrite.All granted successfully." -ForegroundColor Green
                         $appPermissionResults.Success++
                         $bootstrapPermissionGrantedThisRun = $true
                         # Add it to the set so we don't try again in the main loop and count it correctly later
                         $currentAppRoleIdsSet.Add($requiredBootstrapRoleId) | Out-Null
                     } else {
                         Write-Error "Failed to grant bootstrap permission AppRoleAssignment.ReadWrite.All. Subsequent application permission grants might fail."
                         $appPermissionResults.Failed++
                         # Do not increment $totalPermissionGrantsAttempted here, as it's handled in the main loop below if present
                     }
                } else {
                     Write-Verbose "Bootstrap permission AppRoleAssignment.ReadWrite.All already exists."
                     # Don't count as success/failure here, wait for main loop check for 'AlreadyGranted' count
                }
            } else { Write-Verbose "AppRoleAssignment.ReadWrite.All (Role) not found in manifest for Graph resource."}
        } else { Write-Verbose "Microsoft Graph resource or its resourceAccess not found/defined in manifest."}
    } # End if Graph SPN found check for bootstrap

    # --- Now loop through ALL resources and permissions in the manifest ---
    foreach ($resource in $requiredPermissionsManifest.requiredResourceAccess) {
        if (-not $resource.PSObject.Properties.Name -contains 'resourceAppId' -or [string]::IsNullOrWhiteSpace($resource.resourceAppId)) { Write-Warning "Skipping resource entry in manifest because 'resourceAppId' is missing or empty."; continue }
        $resourceApiAppId = $resource.resourceAppId; Write-Verbose "Processing resource API: $resourceApiAppId (Main Loop)"

        # --- Find the Resource API's Service Principal ---
        $resourceApiSpObjectId = $null
        if ($resourceApiAppId -eq $graphApiAppId) {
            $resourceApiSpObjectId = $graphResourceApiSpObjectId # Reuse if it's Graph and we found it earlier
        } else {
            # Find SPN for other APIs if listed
            try { $resourceApiSpObjectId = Get-ServicePrincipalObjectId -GraphAccessToken $appIdentityGraphToken -AppId $resourceApiAppId -TenantIdForVerbose $customerTenantId -ErrorAction Stop }
            catch { Write-Warning "Failed to find SPN (Main Loop) for Resource API '$resourceApiAppId' in tenant '$customerTenantId'. Error: $($_.Exception.Message). Skipping grants for this resource." }
        }

        if (!$resourceApiSpObjectId) {
            Write-Warning "Could not find SPN (Main Loop) for Resource API '$resourceApiAppId' in tenant '$customerTenantId'. Skipping grants for this resource.";
            # Estimate skipped count based on manifest entries for this resource
            if ($resource.PSObject.Properties.Name -contains 'resourceAccess' -and $resource.resourceAccess) {
                 $skippedPermissions = ($resource.resourceAccess | Where-Object {$_.type -eq 'Role'}).Count
                 $appPermissionResults.Skipped += $skippedPermissions
                 Write-Verbose "Incremented skipped count by $skippedPermissions for resource $resourceApiAppId"
            }
            continue # Skip to next resource in manifest
        }
        Write-Verbose "Found Resource API SPN ObjectId for '$resourceApiAppId': $resourceApiSpObjectId"

        if (-not $resource.PSObject.Properties.Name -contains 'resourceAccess' -or !$resource.resourceAccess) { Write-Verbose "No 'resourceAccess' array defined for resource '$resourceApiAppId' in manifest."; continue }

        # --- Loop through each permission requested for this resource ---
        foreach ($permission in $resource.resourceAccess) {
            # Validate permission entry structure
            if (-not $permission.PSObject.Properties.Name -contains 'id' -or [string]::IsNullOrWhiteSpace($permission.id) -or
                -not $permission.PSObject.Properties.Name -contains 'type' -or [string]::IsNullOrWhiteSpace($permission.type)) {
                Write-Warning "Skipping permission under resource '$resourceApiAppId' because 'id' or 'type' is missing/empty.";
                $appPermissionResults.Skipped++; continue
            }

            # We only care about APPLICATION permissions (Type: Role)
            if ($permission.type -ne 'Role') {
                Write-Verbose "Skipping non-application permission (Type: $($permission.type)) ID: $($permission.id)"; continue
            }

            # Validate the permission ID is a GUID
            if (!($permission.id -as [guid])) {
                Write-Warning "Skipping invalid permission ID '$($permission.id)' (not a GUID) under resource '$resourceApiAppId'.";
                $appPermissionResults.Skipped++; continue
            }

            $requiredAppRoleId = [guid]$permission.id;
            # Use ID as name for logging if a friendly name isn't easily available
            $permissionName = $permission.id

             # Increment total attempted grants from manifest
            $totalPermissionGrantsAttempted++

             # --- Check if this permission is the bootstrap one AND was granted this run ---
             # If so, it's already counted as 'Success', don't count again as 'AlreadyGranted'.
             if ($manifestContainsBootstrapPermission -and $requiredAppRoleId -eq $requiredBootstrapRoleId -and $resourceApiAppId -eq $graphApiAppId -and $bootstrapPermissionGrantedThisRun) {
                 Write-Verbose "Bootstrap permission $requiredAppRoleId was granted in pre-check this run. Skipping main loop check."
                 continue # Already counted as success
             }

            # --- Check if permission is already granted ---
            if ($currentAppRoleIdsSet.Contains($requiredAppRoleId)) {
                Write-Verbose "APPLICATION Permission '$permissionName' ($requiredAppRoleId) already granted for resource '$resourceApiAppId'."
                $appPermissionResults.AlreadyGranted++
            } else {
                # --- Grant the missing Application permission ---
                Write-Host "Attempting to grant missing APPLICATION permission '$permissionName' ($requiredAppRoleId) for resource '$resourceApiAppId'..."
                $grantSuccess = $false
                try {
                    $grantSuccess = Grant-ApplicationPermission `
                        -GraphAccessToken $appIdentityGraphToken `
                        -AppServicePrincipalObjectId $appSpObjectId_Step6 `
                        -ResourceApiObjectId $resourceApiSpObjectId `
                        -AppRoleId $requiredAppRoleId `
                        -TenantIdForVerbose $customerTenantId `
                        -PermissionNameForVerbose $permissionName `
                        -ErrorAction Stop
                } catch { Write-Warning "Grant-ApplicationPermission call failed unexpectedly for permission '$permissionName'. Error: $($_.Exception.Message)" } # Catch should ideally be inside function

                if ($grantSuccess) {
                     $appPermissionResults.Success++
                     # Optional: Add to the set if needed for complex multi-stage logic (not strictly needed here)
                     # $currentAppRoleIdsSet.Add($requiredAppRoleId) | Out-Null
                } else {
                     $appPermissionResults.Failed++
                }
            }
             Start-Sleep -Milliseconds 200 # Small delay between grants
        } # End foreach permission
    } # End foreach resource in manifest

    Start-Sleep -Milliseconds 500 # Delay between tenants
} # End foreach customer

Write-Host "-----------------------------------------------------"
Write-Host "Application Permission Grant Summary:" -ForegroundColor Yellow
Write-Host "Total Application Permissions (Roles) processed from Manifest: $totalPermissionGrantsAttempted"
Write-Host "Successfully Granted (including bootstrap if added this run): $($appPermissionResults.Success)" -ForegroundColor Green
Write-Host "Already Granted (Skipped): $($appPermissionResults.AlreadyGranted)" -ForegroundColor Cyan
Write-Host "Failed: $($appPermissionResults.Failed)" -ForegroundColor Red
Write-Host "Skipped (Partner Tenant / Invalid Tenant / API issues / Missing Target SPN / Missing Manifest Entry): $($appPermissionResults.Skipped)" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------"
Write-Host "Script finished."

# Cleanup sensitive variables from the session
Remove-Variable clientSecret, Global:InitialRefreshToken, partnerCenterAccessToken, appIdentityGraphToken -ErrorAction SilentlyContinue
Write-Verbose "Sensitive variables removed from session."
