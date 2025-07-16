<#
    .SYNOPSIS
    Get-MFAReport.ps1

    .DESCRIPTION
    Export Microsoft 365 per-user MFA report with Micrososoft Graph PowerShell.

    .LINK
    www.alitajran.com/export-office-365-users-mfa-status-with-powershell/

    .NOTES
    Written by: ALI TAJRAN
    Website:    www.alitajran.com
    LinkedIn:   linkedin.com/in/alitajran

    .CHANGELOG
    V1.00, 04/04/2021 - Initial version
    V2.00, 08/04/2024 - Rewritten for Microsoft Graph PowerShell
	V2.5  07/14/2024 - Added license audit and last login date by J Pastor
#>
# Connect to Microsoft Graph with the required scopes
Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","Policy.ReadWrite.AuthenticationMethod","UserAuthenticationMethod.Read.All"

# CSV export file path
$CSVfile = "C:\temp\MFAUsers.csv"

# Get properties
$Properties = @(
    'Id',
    'DisplayName',
    'UserPrincipalName',
    'UserType',
    'Mail',
    'ProxyAddresses',
    'AccountEnabled',
    'CreatedDateTime'
)

# Get all users
[array]$Users = Get-MgUser -All -Property $Properties | Select-Object $Properties

# Initialize the report list
$Report = [System.Collections.Generic.List[Object]]::new()

# Check if any users were retrieved
if (-not $Users) {
    Write-Host "No users found. Exiting script." -ForegroundColor Red
    return
}

# Initialize progress counter
$counter = 0
$totalUsers = $Users.Count

# build a mapping of your tenant’s SKUs (optional)
$skuMap = @{}
Get-MgSubscribedSku | ForEach-Object { $skuMap[$_.SkuId] = $_.SkuPartNumber }


# Loop through each user and get their MFA settings
foreach ($User in $Users) {
    $counter++

    # Calculate percentage completion
    $percentComplete = [math]::Round(($counter / $totalUsers) * 100)

    # Define progress bar parameters with user principal name
    $progressParams = @{
        Activity        = "Processing Users"
        Status          = "User $($counter) of $totalUsers - $($User.UserPrincipalName) - $percentComplete% Complete"
        PercentComplete = $percentComplete
    }

    Write-Progress @progressParams

    # Get MFA settings
    $MFAStateUri = "https://graph.microsoft.com/beta/users/$($User.Id)/authentication/requirements"
    $Data = Invoke-MgGraphRequest -Uri $MFAStateUri -Method GET

    # Get the default MFA method
    $DefaultMFAUri = "https://graph.microsoft.com/beta/users/$($User.Id)/authentication/signInPreferences"
    $DefaultMFAMethod = Invoke-MgGraphRequest -Uri $DefaultMFAUri -Method GET

    # Determine the MFA default method
    if ($DefaultMFAMethod.userPreferredMethodForSecondaryAuthentication) {
        $MFAMethod = $DefaultMFAMethod.userPreferredMethodForSecondaryAuthentication
        Switch ($MFAMethod) {
            "push" { $MFAMethod = "Microsoft authenticator app" }
            "oath" { $MFAMethod = "Authenticator app or hardware token" }
            "voiceMobile" { $MFAMethod = "Mobile phone" }
            "voiceAlternateMobile" { $MFAMethod = "Alternate mobile phone" }
            "voiceOffice" { $MFAMethod = "Office phone" }
            "sms" { $MFAMethod = "SMS" }
            Default { $MFAMethod = "Unknown method" }
        }
    }
    else {
        $MFAMethod = "Not Enabled"
    }

    # Filter only the aliases
    $Aliases = ($User.ProxyAddresses | Where-Object { $_ -clike "smtp*" } | ForEach-Object { $_ -replace "smtp:", "" }) -join ', '
	
	# ── Instead of signInActivity ──
    try {
        $signIn = Get-MgAuditLogSignIn `
            -Filter "userId eq '$($User.Id)'" `
            -Sort  "createdDateTime desc" `
            -Top   1
        $lastLogin = $signIn.CreatedDateTime
    }
    catch {
        # in case no sign-in record or permission issue
        $lastLogin = $null
    }
	# pull license details
    $licenseDetails = Get-MgUserLicenseDetail -UserId $User.Id
    # extract SKU names
    $licenseNames = $licenseDetails |
        Select-Object -ExpandProperty SkuPartNumber -Unique
    # Create a report line for each user
    $ReportLine = [PSCustomObject][ordered]@{
        UserPrincipalName = $User.UserPrincipalName
        DisplayName       = $User.DisplayName
        MFAState          = $Data.PerUserMfaState
        MFADefaultMethod  = $MFAMethod
        PrimarySMTP       = $User.Mail
        Aliases           = $Aliases
        UserType          = $User.UserType
        AccountEnabled    = $User.AccountEnabled
		LastLoginDate     = $lastLogin
		Licenses          = ($licenseNames -join ', ')
        CreatedDateTime   = $User.CreatedDateTime
    }
    $Report.Add($ReportLine)
}

# Complete the progress bar
Write-Progress -Activity "Processing Users" -Completed

# Display the report in a grid view
$Report | Out-GridView -Title "Microsoft 365 per-user MFA Report"

# Export the report to a CSV file
$Report | Export-Csv -Path $CSVfile -NoTypeInformation -Encoding utf8
Write-Host "Microsoft 365 per-user MFA Report is in $CSVfile" -ForegroundColor Cyan
