#Requires -Version 5.0
<#
    .SYNOPSIS
    
    Detect Accounts Impacted By The MFA Enforcement October 15, 2025 and Early 2025

    .MORE INFORMATION
    https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication

    .NOTES
    VERSION: 2409

    .COPYRIGHT
    @mortenknudsendk on Twitter | mok@mortenknudsen.net
    Blog: https://mortenknudsen.net
    
    .LICENSE
    Licensed under the MIT license.

    .WARRANTY
    Use at your own risk, no warranty given!
#>

#####################################################################
# Variables
#####################################################################

    $LogDaysToSearch = 90
    $File_Overview = ".\Identity_Overview.xlsx"
    $File_Events   = ".\Identity_Overview_Events.xlsx"

    $AppInScope = @(
                      [PSCustomObject]@{
                                          AppId = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
                                          AppName = "Azure Portal"
                                          EnforceMent = "Oct 15, 2024"
                                       }
                      [PSCustomObject]@{
                                          AppId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
                                          AppName = "Azure CLI"
                                          EnforceMent = "Early 2025"
                                       }
                      [PSCustomObject]@{
                                          AppId = "1950a258-227b-4e31-a9cf-717495945fc2"
                                          AppName = "Azure Powershell"
                                          EnforceMent = "Early 2025"
                                       }
                      [PSCustomObject]@{
                                          AppId = "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa"
                                          AppName = "Azure Mobile App"
                                          EnforceMent = "Early 2025"
                                       }
                   )


#####################################################################
# Microsoft Graph
#####################################################################

    write-host ""
    Write-host "Step 1/8: Checking Microsoft Powershell Modules"

    $InstalledModules = Get-InstalledModule
    If ("Microsoft.Graph.Beta" -notin $InstalledModules.Name)
        {
            # Beta-module contains more info than normal module - why ? Good question, but that is a fact !
            Install-module Microsoft.Graph.Beta
        }
    If ("ImportExcel" -notin $InstalledModules.Name)
        {
            # ImportExcel - Used for Excel file reporting
            #   Github: https://github.com/dfinke/ImportExcel
            #   Powershell Gallery: https://www.powershellgallery.com/packages/ImportExcel

            Install-module ImportExcel
        }

#####################################################################
# Microsoft Graph
#####################################################################

    write-host ""
    Write-host "Step 2/8: Connectivity to Microsoft Graph"

    Connect-MgGraph -scopes Directory.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All


#####################################################################
# Step 3: Get SignIn Events from Entra ID SignInLog
#####################################################################

    import-module Microsoft.Graph.Beta.Reports

    write-host ""
    Write-host "Step 3/8: Checking Sign-in logs for last $($LogDaysToSearch) day(s) - looking for interactive sign-ins"

    $SearchDateFrom = (Get-date) - (New-TimeSpan -Days $LogDaysToSearch)
    $SearchDateFrom = Get-date $SearchDateFrom -format yyyy-MM-ddTHH:mm:ssZ

    $LogEvents = [System.Collections.ArrayList]@()
    $TotalEvents = 0
    ForEach ($Entry in $AppInScope)
        {
            $Events = @()
            write-host ""
            Write-host "  Searching for events for app [ $($Entry.AppName) ] ... Please Wait !"

            $AppId = [guid]$Entry.AppId
            $Events = Get-MgBetaAuditLogSignIn -Filter "(AppId eq '$($AppId)') and (createdDateTime ge $SearchDateFrom)" -All

            $TotalEvents = $TotalEvents + $Events.Count

            write-host "  Found $($Events.Count) event(s)"
            $Add = $LogEvents.add($Events)
        }

    If ($LogEvents)
        {
            write-host ""
            write-host "  Found $($TotalEvents) total event(s)"

            $LogEvents_Users_unique = $LogEvents.UserPrincipalName | Sort-Object -Unique

            write-host ""
            write-host "  Found $($LogEvents_Users_unique.count) unique user(s) with sign-ins"
            write-host ""
        }

#########################################################################################################
# Step 4: Get AuthenticationMethods from the users doing interactive sign-ins
#########################################################################################################

    write-host ""
    write-host "Step 4/8: Getting Authentication Methods from Entra ID .... Please Wait !"

    $UsersAuthMethods = Get-MgBetaReportAuthenticationMethodUserRegistrationDetail -All

    If ($UsersAuthMethods)
        {
            write-host ""
            write-host "  Found $($UsersAuthMethods.count) authentication methods"
            write-host ""
            write-host "  Converting UserAuthenticationMethod array to hash-table for faster searching as hash-tables per definition must be unique"

            $UsersAuthMethods_Hash = [ordered]@{}
            $UsersAuthMethods | ForEach-Object { $UsersAuthMethods_Hash.add($_.UserPrincipalName,$_)}
        }

#####################################################################
# Step 5: Get user info
#####################################################################

    write-host ""
    write-host "Step 5/8: Getting User info from Entra ID .... Please Wait !"

    $Users = Get-MgBetaUser -All -property AccountEnabled, id, givenname, surname, userprincipalname, AssignedLicenses, AssignedPlans, Authentication, Devices, CreatedDateTime, Department, Identities, InvitedBy, IsResourceAccount, JoinedTeams, JoinedGroups, LastPasswordChangeDateTime, LicenseDetails, Mail, Manager, MobilePhone, OfficeLocation, PasswordPolicies, ProxyAddresses, UsageLocation, OnPremisesDistinguishedName, OnPremisesExtensionAttributes, OnPremisesSyncEnabled, displayname, signinactivity `
                            | select-object id, givenname, surname, userprincipalname, OnPremisesDistinguishedName, AccountEnabled, displayname, AssignedLicenses, AssignedPlans, Authentication, Devices, CreatedDateTime, Department, Identities, InvitedBy, IsResourceAccount, JoinedTeams, JoinedGroups, LastPasswordChangeDateTime, LicenseDetails, Mail, Manager, MobilePhone, OfficeLocation, PasswordPolicies, ProxyAddresses, UsageLocation, OnPremisesSyncEnabled, `
                            @{name='LastSignInDateTime'; expression = {$_.signinactivity.lastsignindatetime}}, `
                            @{name='LastNonInteractiveSignInDateTime'; expression = {$_.signinactivity.LastNonInteractiveSignInDateTime}}, `
                            @{name='AuthPhoneMethods'; expression = {$_.authentication.PhoneMethods}}, `
                            @{name='AuthMSAuthenticator'; expression = {$_.authentication.MicrosoftAuthenticatorMethods}}, `
                            @{name='AuthPassword'; expression = {$_.authentication.PasswordMethods}}

    If ($Users)
        {
            write-host ""
            write-host "  Found $($Users.count) users"
            write-host ""
            write-host "  Converting User array to hash-table for faster searching as hash-tables per definition must be unique"

            $Users_Hash = [ordered]@{}
            $Users | ForEach-Object { $Users_Hash.add($_.UserPrincipalName,$_)}
        }
    
#####################################################################
# Step 6: Correlate date - build array
#####################################################################

    Write-host ""
    Write-host "Step 6/8: Correlating data-sources into user array for validation & reporting purpose .... Please Wait !"
    Write-host ""

    # Get license details from Microsoft - https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
    $LicenseTranslationTable = Invoke-WebRequest -Method Get -UseBasicParsing -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" | ConvertFrom-Csv

    $UserInfoArray = [System.Collections.ArrayList]@()
    $UsersTotal = $Users.count

    $Users | ForEach-Object -Begin  {
            $i = 0
    } -Process {
            
            # Default values
            $User = $_
            $SignInsDetected = $false

            write-host "  Processing $($User.DisplayName)"

            #------------------------------------------------------------------------------------------------
            # Sign-in Events
               If ($User.UserPrincipalName -in $LogEvents_Users_unique)
                    {
                        $SignInsDetected = $true
                    }

            #------------------------------------------------------------------------------------------------
            # Authentication Methods
                
                If ($UsersAuthMethods)
                    {
                        $AuthMethods = $UsersAuthMethods_Hash[$user.UserPrincipalName]
                    }

            #------------------------------------------------------------------------------------------------
            # Get Licenses

                # Get user licenses
                    $LicenseInfo = @()
                    ForEach ($License in $User.AssignedLicenses)
                        {
                            $LicenseInfo += $LicenseTranslationTable | where { $_.Guid -eq $License.SkuID }
                        }
                    If ($LicenseInfo)
                        {
                            $UserLicenseInfo_List = (($LicenseInfo."???Product_Display_Name" | Sort-Object -Unique) -join ",")
                        }

                    $LicenseInfo = $LicenseInfo.String_ID | Sort-Object -Unique
                    $UserAssignedPlans = $User.AssignedPlans

            #------------------------------------------------------------------------------------------------
            # Building array

            $Object = [PSCustomObject]@{
                                            Id                                           = $User.Id
                                            GivenName                                    = $User.GivenName
                                            SurName                                      = $User.Surname
                                            UserPrincipalName                            = $User.UserPrincipalName
                                            DisplayName                                  = $User.DisplayName
                                            AccountEnabled                               = $User.AccountEnabled
                                            Mail                                         = $User.Mail
                                            SignInsDetectedMSAdminPortals                = $SignInsDetected
                                            IsAdmin                                      = $AuthMethods.IsAdmin
                                            DefaultMfaMethod                             = $AuthMethods.DefaultMfaMethod
                                            MethodsRegistered                            = $AuthMethods.MethodsRegistered -join ','
                                            IsMfaCapable                                 = $AuthMethods.IsMfaCapable
                                            IsMfaRegistered                              = $AuthMethods.IsMfaRegistered
                                            IsPasswordlessCapable                        = $AuthMethods.IsPasswordlessCapable
                                            IsSsprCapable                                = $AuthMethods.IsSsprCapable
                                            IsSsprEnabled                                = $AuthMethods.IsSsprEnabled
                                            IsSsprRegistered                             = $AuthMethods.IsSsprRegistered
                                            IsSystemPreferredAuthenticationMethodEnabled = $AuthMethods.IsSystemPreferredAuthenticationMethodEnabled
                                            AuthMethodsLastUpdatedDateTime               = $AuthMethods.LastUpdatedDateTime
                                            Cloud_LastSignInDateTime                     = $User.LastSignInDateTime
                                            Cloud_LastNonInteractiveSignInDateTime       = $User.LastNonInteractiveSignInDateTime
                                            Cloud_PasswordPolicies                       = $User.PasswordPolicies
                                            ActiveDirectoryDistinguishedName             = $User.OnPremisesDistinguishedName
                                            UserLicenseList                              = $UserLicenseInfo_List
                                        }
            $Result = $UserInfoArray.add($object)

            # Increment the $i counter variable which is used to create the progress bar.
            $i = $i+1

            # Determine the completion percentage
            $Completed = ($i/$UsersTotal) * 100
            Write-Progress -Activity "Correlating User Info" -Status "Progress:" -PercentComplete $Completed
            } -End {
                
                Write-Progress -Activity "Correlating User Info" -Status "Ready" -Completed
            }


#####################################################################
# Step 7: Build conclusions
#####################################################################

    $DaysLastSignInCheck = (Get-date) - (New-TimeSpan -Days 90)

    Write-host ""
    Write-host "Step 7/8: Building conclusions .... Please Wait !"

    # Scoping
        $UserInfoArray_Scoped = $UserInfoArray | Where-Object { $_.DisplayName -notlike "On-Premises Directory Synchronization Service Account" }

    #--------------------------------------------------------------------------------------------------------
    # IMPACT: Accounts that will have impact, when Microsoft enforce MFA Requirement (sign-ins was detected)
        $Impact_MFA_Enforcement = $UserInfoArray_Scoped | Where-Object { ( (!($_.IsMfaRegistered)) -and ($_.SignInsDetectedMSAdminPortals) -and ($_.AccountEnabled) ) }

        write-host ""
        write-host "Check 1: Active account, MFA missing, cloud sign-ins during last 90 days, Sign-in events against MS admin portals detected last $($LogDaysToSearch) day(s)"

        If ($Impact_MFA_Enforcement)
            {
                write-host ""
                Write-host "Users ($(($Impact_MFA_Enforcement | measure-object).count)) that will be impacted by MFA enforcement (sign-ins detected):" -ForegroundColor Yellow

                $Impact_MFA_Enforcement | Select-Object DisplayName,UserPrincipalName | Out-Default
            }
        Else
            {
                write-host "No issues found !" -ForegroundColor Green
                write-host ""
            }

    #--------------------------------------------------------------------------------------------------------
    # INVESTIGATION NEEDED: Accounts that are missing MFA registration - SignIn during Last 90 days - Account Active
        $MissingMFA_ActiveAccount_RecentSignIns = $UserInfoArray_Scoped | Where-Object { ( (!($_.IsMFARegistered) -and (!($_.SignInsDetectedMSAdminPortals)) -and ($_.Cloud_LastSignInDateTime -gt $DaysLastSignInCheck)) ) }

        write-host ""
        write-host "Check 2: Active account, MFA missing, cloud sign-ins during last 90 days, no sign-in events against MS admin portals"

        If ($MissingMFA_ActiveAccount_RecentSignIns)
            {
                write-host ""
                Write-host "Users ($(($MissingMFA_ActiveAccount_RecentSignIns | measure-object).count)) that MAY be impacted by MFA enforcement if account may do interactive login against MS admin Portals (no events detected):" -ForegroundColor Yellow

                $MissingMFA_ActiveAccount_RecentSignIns | Select-object DisplayName, UserPrincipalName | Out-Default
            }
        Else
            {
                write-host "No issues found !" -ForegroundColor Green
                write-host ""
            }

    #--------------------------------------------------------------------------------------------------------
    # INVESTIGATION NEEDED: Accounts that are missing MFA registration - SignIn during Last 90 days - Account Active - MFA not capable
    # MFA NOT capable: Users registered and enabled for a strong authentication method in Microsoft Entra ID. Either a user or an admin may register an authentication method on behalf of a user. 
    # Authentication methods are enabled by authentication method policy or multifactor authentication service settings

        $MissingMFA_ActiveAccount_RecentSignIns_MfaNotCapable = $UserInfoArray_Scoped | Where-Object { ( (!($_.IsMfaRegistered) -and (!($_.SignInsDetectedMSAdminPortals)) -and (!($_.IsMfaCapable)) -and ($_.Cloud_LastSignInDateTime -gt $DaysLastSignInCheck) ) ) }

        write-host ""
        write-host "Check 3: Active account, MFA missing, MFA not capable, cloud sign-ins during last 90 days, no sign-in events against MS admin portals"
        
        If ($MissingMFA_ActiveAccount_RecentSignIns_MfaNotCapable)
            {
                write-host ""
                Write-host "Users ($(($MissingMFA_ActiveAccount_RecentSignIns_MfaNotCapable | measure-object).count)) that MAY be impacted by MFA enforcement if account may do interactive login against MS admin Portals:" -ForegroundColor Yellow

                $MissingMFA_ActiveAccount_RecentSignIns_MfaNotCapable | Select-object DisplayName, UserPrincipalName | Out-Default
            }
        Else
            {
                write-host "No issues found !" -ForegroundColor Green
                write-host ""
            }


#####################################################################
# Step 8: Export to Excel
#####################################################################

    If (Test-Path $File_Overview)
        {
            Remove-Item $File_Overview -Force
        }

    Write-host ""
    Write-host ""
    Write-host "Step 8/8: Exporting Overview, Observations & Events .... Please Wait !"
    write-host ""

    #-----------------------------------
    Write-host "  Exporting Overview to file ($($File_Overview))"

    $Target = "Users_Scoped"
    $UserInfoArray_Scoped | Export-Excel -Path $File_Overview -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle medium9

    $Target = "Check1_Impact_MFA_Enforcement"
    $Impact_MFA_Enforcement | Export-Excel -Path $File_Overview -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle medium9

    $Target = "Check2_Missing_MFA"
    $MissingMFA_ActiveAccount_RecentSignIns | Export-Excel -Path $File_Overview -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle medium9

    $Target = "Check3_Missing_MFA_Not_Capable"
    $MissingMFA_ActiveAccount_RecentSignIns_MfaNotCapable | Export-Excel -Path $File_Overview -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle medium9

    #-----------------------------------

    If (Test-Path $File_Events)
        {
            Remove-Item $File_Events -Force
        }

    write-host ""
    Write-host "  Exporting Sign-In events to file ($($File_Events))"
    write-host ""

    $Target = "Events"
    $LogEvents | Export-Excel -Path $File_Events -WorksheetName $Target -AutoFilter -AutoSize -BoldTopRow -tablename $Target -tablestyle medium9
