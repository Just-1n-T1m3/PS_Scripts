#Powershell script to force logout of user, set mfa enforced and require MFA re-registration. Will read user list from users.csv
#Justin Pastor 2025

#——————————————————————————————————————————
# Prerequisites
#——————————————————————————————————————————
# Install‑Module AzureAD, MSOnline   # if you haven’t already  
#——————————————————————————————————————————

# Connect to Azure AD Graph
Connect-AzureAD

# Connect to MSOnline (for per‑user MFA controls)
Connect-MsolService

# Path to your input CSV (must have header "UserPrincipalName")
$CsvPath = "C:\tsa\users.csv"

# Path where your log will be written
$LogPath = "C:\tsa\MFA_enforcement_log.csv"

# If a previous log exists, remove it so we start fresh
if (Test-Path $LogPath) {
    Remove-Item $LogPath
}

# Read all users from the CSV
$Users = Import-Csv -Path $CsvPath

# Create an array to hold log entries
$LogEntries = @()

foreach ($u in $Users) {
    $upn = $u.UserPrincipalName
    Write-Host "Processing $upn..." -ForegroundColor Cyan

    # Default flags
    $mfaWasAlreadyEnabled = $false
    $mfaEnforcedNow       = $false

    try {
        # 1) Check and enforce per‑user MFA
        $msol = Get-MsolUser -UserPrincipalName $upn
        $reqs = $msol.StrongAuthenticationRequirements

        if ($reqs.Count -eq 0 -or $reqs.State -ne "Enabled") {
            $req = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
            $req.RelyingParty = "*"
            $req.State        = "Enabled"

            Set-MsolUser -UserPrincipalName $upn `
                         -StrongAuthenticationRequirements @($req)

            $mfaEnforcedNow = $true
            Write-Host "  • MFA enforced" -ForegroundColor Green
        }
        else {
            $mfaWasAlreadyEnabled = $true
            Write-Host "  • MFA already enforced" -ForegroundColor Yellow
        }

        # 2) Clear existing MFA registrations
        Set-MsolUser -UserPrincipalName $upn -StrongAuthenticationMethods @()
        Write-Host "  • Cleared registered MFA methods" -ForegroundColor Green

        # 3) Revoke all refresh tokens (force sign‑out)
        Revoke-AzureADUserAllRefreshToken -ObjectId $msol.ObjectId
        Write-Host "  • Revoked all refresh tokens" -ForegroundColor Green

        # Build a log entry for this user
        $entry = [PSCustomObject][ordered]@{
            Timestamp            = (Get-Date).ToString("s")
            UserPrincipalName    = $upn
            MFA_AlreadyEnabled   = $mfaWasAlreadyEnabled
            MFA_EnforcedNow      = $mfaEnforcedNow
            MFA_MethodsCleared   = $true
            Tokens_Revoked       = $true
            Error                = $null
        }
    }
    catch {
        # In case anything goes wrong, log the error message
        $entry = [PSCustomObject][ordered]@{
            Timestamp            = (Get-Date).ToString("s")
            UserPrincipalName    = $upn
            MFA_AlreadyEnabled   = $mfaWasAlreadyEnabled
            MFA_EnforcedNow      = $mfaEnforcedNow
            MFA_MethodsCleared   = $false
            Tokens_Revoked       = $false
            Error                = $_.Exception.Message
        }
        Write-Host "  !! Error processing $upn: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Add this entry to our log array
    $LogEntries += $entry

    Write-Host ""
}

# After the loop, write out the log to CSV
$LogEntries | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8

# pop up a grid view window so you can review interactively
$LogEntries | Out-GridView -Title "MFA Enforcement Log"

Write-Host "All done.  Log written to $LogPath" -ForegroundColor Magenta
