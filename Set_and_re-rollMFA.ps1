#Powershell script to force logout of user, set mfa enforced and require MFA re-registration.
#Will read user list from users.csv
#Justin Pastor 2025(Converted to Microsoft Graph PowerShell)

# IMPORTANT:
# This script requires specific cmdlets from the Microsoft.Graph PowerShell module.
# If you don't have the module installed, run: Install-Module Microsoft.Graph -Scope CurrentUser
# This version uses Invoke-MgGraphRequest for more robust authentication method removal and sign-out.

# For a comprehensive guide on setting up Conditional Access policies in Microsoft Entra ID, refer to:
# https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview

#——————————————————————————————————————————
# Prerequisites
#——————————————————————————————————————————
# Install-Module Microsoft.Graph -Scope CurrentUser # if you haven't already
# Microsoft has deprecated Set-MsolUser; Conditional Access policies are now the recommended way to require MFA for accessing cloud apps.
#——————————————————————————————————————————

#——————————————————————————————————————————
# Ensure only the necessary Microsoft Graph modules are loaded and connected
#——————————————————————————————————————————
try {
    # Import the specific Microsoft Graph sub-modules required.
    # Microsoft.Graph.Authentication provides Connect-MgGraph and Invoke-MgGraphRequest
    # Microsoft.Graph.Users provides Get-MgUser and Get-MgUserAuthenticationMethod
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop

    # Verify that the modules are loaded
    if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
        throw "The 'Microsoft.Graph.Authentication' module failed to load."
    }
    if (-not (Get-Module -Name Microsoft.Graph.Users)) {
        throw "The 'Microsoft.Graph.Users' module failed to load."
    }

    # Connect to Microsoft Graph.
    # The 'User.Read.All' scope is needed to read user information.
    # The 'User.ReadWrite.All' scope is needed to modify user properties (like revoking sign-ins).
    # The 'UserAuthenticationMethod.ReadWrite.All' scope is needed to manage authentication methods.
    # The 'User.RevokeSessions.All' scope is needed for revoking sign-in sessions.
    # Policy.Read.All is added for accessing authentication requirements (beta endpoint).
    Connect-MgGraph -Scopes "User.Read.All", "User.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All", "User.RevokeSessions.All", "Policy.Read.All" -ErrorAction Stop

    Write-Host "Microsoft Graph modules loaded and connected successfully." -ForegroundColor Green

}
catch {
    Write-Host "ERROR: Could not load necessary Microsoft Graph modules or connect to Microsoft Graph. Please check module installation, permissions, and try again.`n$($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# Path to input CSV and log CSV
$CsvPath = "C:\temp\users.csv"
$LogPath = "C:\temp\MFA_enforcement_log.csv"

# Remove any existing log
if (Test-Path $LogPath) { Remove-Item $LogPath }

# Read users from CSV
# Ensure your users.csv has a column named 'UserPrincipalName'
$Users = Import-Csv -Path $CsvPath

# Prepare log storage
$LogEntries = @()

foreach ($u in $Users) {
    $upn = $u.UserPrincipalName
    Write-Host "Processing ${upn}..." -ForegroundColor Cyan

    # Flags for our log
    $mfaMethodsCleared    = $false
    $tokensRevoked        = $false
    $mfaState             = "N/A" # New column
    $mfaDefaultMethod     = "N/A" # New column
    $errorOccurred        = @() # Changed to array to capture multiple errors

    try {
        # 1. Get the user from Microsoft Graph
        # We need the user's Id (GUID) for subsequent operations.
        $user = Get-MgUser -UserId $upn -ErrorAction Stop
        if (-not $user) { throw "User not found in Microsoft Graph." }

        # 2. Get current MFA status (before any changes)
        try {
            $MFAStateUri = "/beta/users/$($user.Id)/authentication/requirements"
            $MFAData = Invoke-MgGraphRequest -Uri $MFAStateUri -Method GET -ErrorAction Stop
            $mfaState = $MFAData.PerUserMfaState
        }
        catch {
            $errorMsg = "Error getting MFA state for $($upn): $($_.Exception.Message)"
            $errorOccurred += $errorMsg
            Write-Host "  !! $($errorMsg)" -ForegroundColor Yellow
            $mfaState = "Failed to retrieve"
        }

        try {
            $DefaultMFAUri = "/beta/users/$($user.Id)/authentication/signInPreferences"
            $DefaultMFAMethodData = Invoke-MgGraphRequest -Uri $DefaultMFAUri -Method GET -ErrorAction Stop

            if ($DefaultMFAMethodData.userPreferredMethodForSecondaryAuthentication) {
                $mfaDefaultMethod = $DefaultMFAMethodData.userPreferredMethodForSecondaryAuthentication
                Switch ($mfaDefaultMethod) {
                    "push" { $mfaDefaultMethod = "Microsoft Authenticator app" }
                    "oath" { $mfaDefaultMethod = "Authenticator app or hardware token" }
                    "voiceMobile" { $mfaDefaultMethod = "Mobile phone (Voice)" }
                    "voiceAlternateMobile" { $mfaDefaultMethod = "Alternate mobile phone (Voice)" }
                    "voiceOffice" { $mfaDefaultMethod = "Office phone (Voice)" }
                    "sms" { $mfaDefaultMethod = "SMS" }
                    Default { $mfaDefaultMethod = "Unknown method" }
                }
            } else {
                $mfaDefaultMethod = "Not Configured"
            }
        }
        catch {
            $errorMsg = "Error getting default MFA method for $($upn): $($_.Exception.Message)"
            $errorOccurred += $errorMsg
            Write-Host "  !! $($errorMsg)" -ForegroundColor Yellow
            $mfaDefaultMethod = "Failed to retrieve"
        }

        # 3. Clear existing MFA registrations (force re-registration)
        # Get all authentication methods for the user
        $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue

        if ($authMethods.Count -gt 0) {
            Write-Host "  • Found $($authMethods.Count) existing MFA methods. Attempting to clear..." -ForegroundColor Yellow
            $methodsClearedSuccessfully = 0 # Track successful deletions
            foreach ($method in $authMethods) {
                # Ensure the method object itself is not null
                if (-not $method) {
                    $errorMsg = "Skipped processing a null authentication method object for user $($upn)."
                    $errorOccurred += $errorMsg
                    Write-Host "    !! $($errorMsg)" -ForegroundColor Red
                    continue # Skip to the next iteration
                }

                try {
                    # Determine the specific API endpoint based on the authentication method type
                    $methodType = $method.OdataType.Replace('#microsoft.graph.', '')
                    $apiEndpoint = $null

                    switch ($methodType) {
                        "phoneAuthenticationMethod" {
                            $apiEndpoint = "/v1.0/users/$($user.Id)/authentication/phoneMethods/$($method.Id)"
                        }
                        "microsoftAuthenticatorAuthenticationMethod" {
                            $apiEndpoint = "/v1.0/users/$($user.Id)/authentication/microsoftAuthenticatorMethods/$($method.Id)"
                        }
                        "softwareOathAuthenticationMethod" {
                            $apiEndpoint = "/v1.0/users/$($user.Id)/authentication/softwareOathMethods/$($method.Id)"
                        }
                        "fido2AuthenticationMethod" {
                            $apiEndpoint = "/v1.0/users/$($user.Id)/authentication/fido2Methods/$($method.Id)"
                        }
                        "emailAuthenticationMethod" {
                            $apiEndpoint = "/v1.0/users/$($user.Id)/authentication/emailMethods/$($method.Id)"
                        }
                        # Add other authentication method types if needed
                        default {
                            $errorMsg = "Unsupported authentication method type encountered: $($methodType). Skipping deletion."
                            $errorOccurred += $errorMsg
                            Write-Host "    !! $($errorMsg)" -ForegroundColor Red
                            continue # Skip to the next method
                        }
                    }

                    # Ensure the method ID is not null before attempting to remove
                    if ($method.Id -and $apiEndpoint) {
                        Write-Host "    - Attempting to delete $($methodType) with ID $($method.Id) via API: $($apiEndpoint)" -ForegroundColor DarkYellow
                        Invoke-MgGraphRequest -Method DELETE -Uri $apiEndpoint -ErrorAction Stop

                        Write-Host "    - Cleared method: $($methodType)" -ForegroundColor Green
                        $methodsClearedSuccessfully++ # Increment counter on success
                    } else {
                        $errorMsg = "Skipped clearing a method with a missing ID or invalid API endpoint for type $($methodType)."
                        $errorOccurred += $errorMsg
                        Write-Host "    !! $($errorMsg)" -ForegroundColor Red
                    }
                }
                catch {
                    # Capture specific error for this method, but continue processing others
                    $errorMessage = $_.Exception.Message
                    $fullErrorDetails = $_ | Out-String # Get full error object details
                    $methodTypeForError = if ($method.OdataType) { $method.OdataType.Replace('#microsoft.graph.', '') } else { "Unknown Method Type" }
                    $errorMsg = "Error clearing method $($methodTypeForError) for $($upn): $($errorMessage)"
                    $errorOccurred += $errorMsg
                    Write-Host "    !! $($errorMsg)" -ForegroundColor Red
                    Write-Host "    DEBUG: Full error object for method clearing attempt:`n$($fullErrorDetails)" -ForegroundColor DarkGray
                }
            }
            if ($methodsClearedSuccessfully -gt 0) {
                Write-Host "  • Successfully cleared $($methodsClearedSuccessfully) MFA methods for re-registration." -ForegroundColor Green
                $mfaMethodsCleared = $true
            } else {
                $errorMsg = "  • No MFA methods were successfully cleared for $($upn). This may be due to API limitations (e.g., cannot delete default phone method) or other errors."
                $errorOccurred += $errorMsg
                Write-Host "  !! $($errorMsg)" -ForegroundColor Yellow
                $mfaMethodsCleared = $false
            }
        }
        else {
            $infoMsg = "  • No existing MFA methods found by Get-MgUserAuthenticationMethod for this user. No re-registration needed via deletion."
            $errorOccurred += $infoMsg # Add as informational message to error log for clarity
            Write-Host "  • $($infoMsg)" -ForegroundColor Yellow
            $mfaMethodsCleared = $false # No methods to clear, so flag remains false
        }

        # 4. Revoke refresh tokens (force sign-out)
        # Use Invoke-MgGraphRequest to call the revokeSignInSessions API
        # Explicitly adding /v1.0 to the URI as per debug output
        $revokeSignInSessionsUri = "/v1.0/users/$($user.Id)/revokeSignInSessions"
        Write-Host "  • Attempting to revoke refresh tokens via API: $($revokeSignInSessionsUri)" -ForegroundColor DarkYellow
        try {
            Invoke-MgGraphRequest -Method POST -Uri $revokeSignInSessionsUri -ErrorAction Stop
            Write-Host "  • Revoked all refresh tokens." -ForegroundColor Green
            $tokensRevoked = $true
        }
        catch [Microsoft.Graph.PowerShell.Runtime.RestException] {
            Write-Host "DEBUG: Caught RestException for $($upn). Exception details: $_.Exception | Response: $($_.Exception.Response | ConvertTo-Json)" -ForegroundColor DarkGray
            $restEx = $_.Exception
            $statusCode = $null
            if ($restEx.Response -and $restEx.Response.StatusCode) {
                $statusCode = $restEx.Response.StatusCode
            }

            if ($statusCode -eq 404) {
                $errorMsg = "No active sign-in sessions found for user $($upn) to revoke (HTTP 404 Not Found). This may be expected if the user has no active sessions."
                $errorOccurred += $errorMsg
                Write-Host "  !! $($errorMsg)" -ForegroundColor Yellow # Log as warning
                $tokensRevoked = $true # Consider it successful for the purpose of the script's goal
            } else {
                # Re-throw other types of RestExceptions as critical errors
                $errorMsg = "Error revoking refresh tokens for $($upn): $($restEx.Message) (HTTP Status: $($statusCode))"
                $errorOccurred += $errorOccurred
                Write-Host "  !! $($errorMsg)" -ForegroundColor Red
                throw $restEx # Re-throw to be caught by the outer catch
            }
        }
        catch {
            # Catch any other non-RestException errors during token revocation
            Write-Host "DEBUG: Caught generic exception for $($upn). Full error object: " -ForegroundColor DarkGray
            $_ | Format-List * | Out-String | Write-Host -ForegroundColor DarkGray
            Write-Host "DEBUG: Inner exception details: " -ForegroundColor DarkGray
            $_.Exception | Format-List * | Out-Host -ForegroundColor DarkGray # Changed to Out-Host for better console output

            $errorMsg = "An unexpected error occurred during token revocation for $($upn): $($_.Exception.Message)"
            $errorOccurred += $errorMsg
            Write-Host "  !! $($errorMsg)" -ForegroundColor Red
            throw $_.Exception # Re-throw to be caught by the outer catch
        }

        # Build successful log entry
        $entry = [PSCustomObject][ordered]@{
            Timestamp           = (Get-Date).ToString("s")
            UserPrincipalName   = $upn
            MFAState            = $mfaState # New column
            MFADefaultMethod    = $mfaDefaultMethod # New column
            MFA_MethodsCleared  = $mfaMethodsCleared
            Tokens_Revoked      = $tokensRevoked
            Error               = if ($errorOccurred.Count -gt 0) { $errorOccurred -join "`n" } else { $null }
        }
    }
    catch {
        # Log any error for the entire user processing
        $entry = [PSCustomObject][ordered]@{
            Timestamp           = (Get-Date).ToString("s")
            UserPrincipalName   = $upn
            MFAState            = $mfaState # Include even if error in main block
            MFADefaultMethod    = $mfaDefaultMethod # Include even if error in main block
            MFA_MethodsCleared  = $mfaMethodsCleared
            Tokens_Revoked      = $tokensRevoked
            Error               = $_.Exception.Message
        }
        Write-Host ("  !! Error processing " + $upn + ": " + $_.Exception.Message) -ForegroundColor Red
    }

    $LogEntries += $entry
    Write-Host ""
}

# Export log and show gridview
$LogEntries | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
$LogEntries | Out-GridView -Title "MFA Enforcement Log (Microsoft Graph)"

Write-Host "All done. Log written to $LogPath" -ForegroundColor Magenta
