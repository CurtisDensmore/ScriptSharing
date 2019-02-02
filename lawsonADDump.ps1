<#
    This script supplements lawsonADChanges.psq and is used to take full export of all active employees from HR and checking each user, property by property, to make sure Active Directory matches what HR has.

    This script is only necessary because HR's system can't export to a CSV for every different type of record update (such as writing to a CSV on given name updates, whereas they are able to give me a CSV for a job code or department change)
#>

$logPath = "\\chsads5\LawsonDumps\ErrorLogs"
$inFileCSV = "\\chsads5\LawsonDumps\ActiveDirectoryUpdate.txt"
$includeCSV = "\\chsads5\LawsonDumps\Exclusions\names.csv"
$includeName = Import-Csv $includeCSV 
$dump = Import-Csv $inFileCSV
$smtpServer = 'smtp.intra.chs-mi.com'
$timestamp = Get-Date -Format 'yyyy-MM-dd HH-mm-ss-ms'
$LawsonEmailOut = '\\chsads5\LawsonDumps\LawsonEmailImport\LawsonEmailDump.csv'
$sendEmails = $true

Start-Transcript "\\chsads5\lawsondumps\ErrorLogs\Transcript-$(Get-Date -Format 'yyyyMMddHHmm').log"

#remove this before you ever create it, to avoid duplicates in output
Remove-Item -Path $LawsonEmailOut -Force

<#
.Synopsis
   Writes to a log file
.DESCRIPTION
   Appends to a log file, what has changed and for whom
.EXAMPLE
   Write-Log -samAccountName e100922t -propertyName facsimileTelephoneNumber -propertyValue 989-548-3893
#>
function Write-Log
{
    [CmdletBinding()]
    Param
    (
        # Account that was changed
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $samAccountName,

        # The property that was changed
        [string]$propertyName,

        # The properties new value
        [string]$propertyValue,
        
        # Old value
        [string]$oldValue
    )

    #test if logpath exists, if not create it
    if (-not (Test-Path -Path $logPath))
    {
        New-Item -ItemType directory -path $logPath
    }

    #write property with timestamp to file
    $outLine = (Get-Date -Format 'yyyy-MM-dd : HH:mm:ss:ms') + " : $samAccountName changed property $propertyName to `'$propertyValue`' from `'$oldValue`'"
    $outLine >> "$logPath\DUMP-$timestamp.log"
}

<#
.Synopsis
   Writes to an error log
.EXAMPLE
   Write-ErrorLog -name samAccountName -value 'e100922'
#>
function Write-ErrorLog
{
    [CmdletBinding()]
    Param
    (
        # Name of property
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $name,

        # Value of property
        $value
    )

    #test if logpath exists, if not create it
    if (-not (Test-Path -Path $logPath))
    {
        New-Item -ItemType directory -path $logPath
    }

    #write property with timestamp to file
    $outLine = (Get-Date -Format 'yyyy-MM-dd : HH:mm:ss:ms') + " : $name has no value of $value"
    $outLine >> "$logPath\error-DUMP-$timestamp.log"
}

<#
.Synopsis
   Makes the changes for each AD property
.DESCRIPTION
   Simplifies the code to make changes and sets new AD user property values. Then writes changes to a logfile.
.INPUTS
    name - LDAP name of property to be changed
    value - new value of property
.EXAMPLE
   Make-Change -name givenname -value $dump.'First Name'
#>
function Make-Change
{
    [CmdletBinding()]
    Param
    (
        # name of property to be changed
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$name,

        # new value for $name
        $value,

        # User to make change to
        $userName
    )
    #only swap values if they exist
    if ($value.Length -ge 1)
    {
        #replace current value with new value
        #use -cne to compare case-sensitive values
        if ($user.$name -cne $value)
        {
            Write-Verbose -Message '---------------------------------------'
            Write-Verbose -Message "Property e-ID : $userName"
            Write-Verbose -Message "Property Name : $name"
            Write-Verbose -Message "Property Value: $value"
            Write-Verbose -Message '---------------------------------------'
        
            #make the change
            if ($name -eq 'mail')
            {
                #Email
				$mailContents = @{
					To = 'cdensmore@chs-mi.com';
					Subject = "Email Field Update: $value";
					From = 'do_not_reply_lawsonADDump@chs-mi.com';
					BodyAsHtml = "$name for $userName has changed to $value.";
					SmtpServer = 'smtp.intra.chs-mi.com';
				}
                if ($sendEmails -eq $true){
                    Send-MailMessage @mailContents
                }
            }
            elseif($name -eq 'sn')
            {
                #Update user's last name
                Set-ADUser -Identity $userName -Replace @{$name=$value}

                #Generate new email
                $user = Get-ADUser -Identity $userName -Properties givenname,sn,mail
                $email = "$($user.givenname).$($user.sn)@chs-mi.com"
                $mailNick = $email -replace "@",'.'
                $targetaddress = "SMTP:$email"

                #region email validity check
                $query = Get-ADUser -Properties samAccountName,mail,ProxyAddresses -LDAPFilter "(&(objectCategory=person)(objectClass=user)(|(proxyAddresses=*:$email)(mail=$email)))"
                if (-not($query))
                {
                    Write-Verbose "$email doesn't exist"

                    #User Principal Name
                    Set-ADUser -Identity $userName -UserPrincipalName $email -ErrorAction SilentlyContinue
                    #Email Address
                    if ($user.mail -ne $null)
                    {
                        Set-ADUser -Identity $userName -Replace @{mail=$email} -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        Set-ADUser -Identity $userName -Add @{mail=$email} -ErrorAction SilentlyContinue
                    }
                    #Mail Nick Name
                    if ($user.mailNickName -ne $null)
                    {
                        Set-ADUser -Identity $userName -Replace @{mailNickName=$mailNick} -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        Set-ADUser -Identity $userName -Add @{mailNickName=$mailNick} -ErrorAction SilentlyContinue
                    }
                    #Target Address
                    if ($user.targetAddress -ne $null)
                    {
                        Set-ADUser -Identity $userName -Replace @{targetAddress=$targetaddress} -ErrorAction SilentlyContinue
                    }
                    else
                    {
                        Set-ADUser -Identity $userName -Add @{targetAddress=$targetaddress} -ErrorAction SilentlyContinue
                    }

                    #get all proxy addresses for user who owns $email
                    try
                    {
                        [array]$proxyAddresses = (Get-ADUser -Identity $userName -Properties ProxyAddresses -ErrorAction SilentlyContinue).ProxyAddresses
                    }
                    catch
                    {
                        #user doesn't exist
                        Write-Verbose "$userName doesn't exist, can't pull their proxy information. Continue Normally."
                        Write-Log "$userName doesn't exist, can't pull their proxy information. Continue Normally."
                    }
        
                    #only update if there are proxyAddresses to update
                    if($proxyAddresses -ne $null)
                    {
                        #new primary proxy address is SMTP:$email
                        $newprimary = "SMTP:$email"
                        $cnt=0
                        #loop through proxy addresses
                        foreach ($proxy in $proxyAddresses)
                        {
                            $cnt+=1
                            Write-Debug $proxy
                            #if current record starts with capital 'SMTP:' it is the primary proxy address
                            if ($proxy -cmatch 'SMTP:.{0,}')
                            {
                                $primaryCNT=$cnt
                                Write-Verbose $proxy
                                Write-Log $proxy
                                #strip "SMTP:' from primary address, save "smtp:$email" to make it a secondary address
                                $secondary = 'smtp:' + $proxy.substring(5)
                                Write-Verbose "Previous primary is now: $secondary"
                                Write-Log "Previous primary is now: $secondary"
                            }#end if
                        }#end foreach
                        
                        #swap out previous primary, making it a secondary proxy address
                        $proxyAddresses[$primaryCNT -1] = $secondary
                        #add the new address as the primary proxy address
                        $proxyAddresses += $newprimary

                        Write-Verbose "Setting new primary SMTP proxy address to $newprimary"
                        Write-Log "Setting new primary SMTP proxy address to $newprimary"
                        Set-ADUser -Identity $userName -Replace @{ProxyAddresses=@($proxyAddresses)}
                    }#end check for proxyaddresses
                    Set-ADUser -Identity $userName -Replace @{ProxyAddresses=@($proxyAddresses)} -ErrorAction SilentlyContinue
                    
                    #Garbage Collection
                    Remove-Variable -Name cnt
                    Remove-Variable -Name secondary
                    Remove-Variable -Name primaryCNT
                    Remove-Variable -Name proxyAddresses
                    Remove-Variable -Name newprimary
                    Remove-Variable -Name email
                    Remove-Variable -Name query
                    Remove-Variable -Name user
                    Remove-Variable -Name targetAddress
                    Remove-Variable -Name mailNick
                    Remove-Variable -Name proxy
                }
                else
                {
                    Write-Verbose "$($query.samAccountName) has already taken email $email"

                    #if equal, do nothing, else email HRIS
                    if (-not ($userName -eq $query.SamAccountName))
                    {
                        Write-Verbose "Email account exists. Sending email to HRIS"
                        Write-Log -logString "$userName | Email | $emailToHR | email already exists $email"
						$mailContents = @{
							To = $emailToHR;
							CC = $emailCC;
							Subject = "Email taken: $email";
							From = $emailFrom;
							BodyAsHtml = "Please contact IT for a different email address for $userName.<br><br>Lawson will need to be updated with the new email address.";
							SmtpServer = $smtpServer;
						}
                        if ($sendEmails -eq $true){
                            Send-MailMessage @mailContents
                        }
                    }
                }
                #endregion
            }
            elseif($name -eq 'displayname')
            {
                Set-ADUser -Identity $userName -Replace @{$name=$value}
                
                #Update Name for Object. Rename-ADObject wants the whole ADObject, not just the samAccountname
                try 
                {
                    Rename-ADObject -Identity $user -NewName $value
                }
                catch
                {
                    Write-Debug "Tried to change $userName display name to $value, but failed"
                    Rename-ADObject -Identity $user -NewName "$($user.GivenName) X. $($user.Surname)"
                }

            }
            else
            {
                Set-ADUser -Identity $userName -Replace @{$name=$value}
            }
            Write-Log -samAccountName $userName -propertyName $name -propertyValue $value -oldValue $user.$name
        }
    }
    else
    {
        #remove Null properties
        #Set-ADUser -Identity $samAccountName -Clear $name
    }
}

<#
.Synopsis
   Parses phone numbers into correct formatting
.DESCRIPTION
   Takes phone numbers from 5, 7, 10, and 11 digits and parses them into a standard 10 or 11 format such as the folloing
   (989) 583-4281
.EXAMPLE
   Parse-PhoneNumber '999-999-9999'
.INPUTS
    Any unformatted telephonenumber of numerical length 10/11/7/5
        e.g. '999-999-9999' '3-4281' '1(989)5836014'
    [System.String]
    [System.Int32]
.OUTPUTS
    A string in the format of #-(###)###-####
#>
function Parse-Number
{
    [CmdletBinding()]
    Param
    (
        # phone number as string/integer
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $phone
    )

    #replace any non-numeric characters with a blank space
    [regex]$r="[^0-9]"
    $phone = $r.Replace($phone,"")
    [bool]($num -as [int] -is [int])
    [int]$len = $phone.length
    #Format Number to correct form, cast from string to int64
    #10-digit number
    if ($len -eq 10)
    {
        $strPhone = "{0:(###) ###-####}" -f [int64]$phone
    }
    #country and area code
    elseif ($len -eq 11)
    {
        $strPhone = "{0:#-(###) ###-####}" -f [int64]$phone
    }
    #without area code
    elseif ($len -eq 7)
    {
        $strPhone = "{0:(989) ###-####}" -f [int64]$phone
    }
    #5-digit extension
    elseif ($len -eq 5)
    {
        $strPhone = "{0:(989) 58#-####}" -f [int64]$phone
    }
    #Write-Verbose "PhoneNumber = `"$strPhone`""
    #returns a two-element array, you'll want element 1, not 0
    return $strPhone
}

#############################
#intro to script begins here
#############################
<#
#Import AD cmdlets
$ADcmdletHost = 'chsads5'
$ADcmdletsession = New-PSSession -ComputerName $ADcmdletHost
Import-Module -Name ActiveDirectory -PSSession $ADcmdletsession
#>

#dump the corresponding CSV into an array and loop through it
ForEach ($record in $dump)
{
    #zero-out variables
    $first = $null
    $middle = $null
    $last = $null
    $samAccountName = $null
    $user = $null
    $displayName = $null
    $workTelephone = $null
    $workFax = $null
    $index = $null
    $campus = $null
    $prefix = $null
    $suffix = $null
    $oldLast = $null
    $empNo = $null

    #set variables
    $samAccountName = ($record.'Employment #').toLower()
    $UserEmail = ($record.'Email Address').tolower()
    $UPNUser = Get-ADUser -Properties samAccountName,mail,ProxyAddresses -LDAPFilter "(&(objectCategory=person)(objectClass=user)(|(proxyAddresses=*:$UserEmail)(mail=$UserEmail)))"

    #verbosity
    $VerbosePreference = 'Continue'

    #check to see if e-id exists in AD
    if ((Get-ADUser -Filter {sAMAccountName -eq $samAccountName} -ErrorAction SilentlyContinue) -ne $null)
    {
        # get user properties
        $user = Get-ADUser -Identity $samAccountName -Properties *
        $empNo = $record.empNo

        #region Names  
        #Set first and Last name from CSV        
        $first = $record.'First Name'
        $middle = $record.Middle.substring(0,1)
        $last = $record.'Last Name'

        #parse names into correct case
        $first = (Get-Culture).TextInfo.ToTitleCase($first.ToLower())
        $last = (Get-Culture).TextInfo.ToTitleCase($last.ToLower())
        $middle = (Get-Culture).TextInfo.ToTitleCase($middle.ToLower())
        $campus = (Get-Culture).TextInfo.ToTitleCase(($record.Location).ToLower())
        
        #check to see if excluded
        if (-not ((($includeName.samAccountName).toLower()) -match "^$samAccountName$" ))
        {
            Write-Verbose "$samAccountName is not included"
            #if middle inital not existent
            $displayName = "{0} {1}" -f $first, $last
        }
        else
        {
            Write-Verbose "$samAccountName is included"
            #if middle initial not null
            $displayName = "{0} {1}. {2}" -f $first,$middle, $last
        }#end exclusion-if
        $displayName = (Get-Culture).TextInfo.ToTitleCase($displayName.ToLower())
        #endregion
 
        #parse phone and fax numbers first, then throw them into AD
        $workTelephone = Parse-Number -phone $record.'Work Telephone'
        $workFax = Parse-Number -phone $record.Fax
        
        #region AD Changes
        Make-Change -userName $samAccountName -name givenname -value $first
        Make-Change -userName $samAccountName -name sn -value $last
        Make-Change -userName $samAccountName -name initials -value $middle
        Make-Change -userName $samAccountName -name physicalDeliveryOfficeName -value $campus
        Make-Change -userName $samAccountName -name title -value $record.'Job Title'
        Make-Change -userName $samAccountName -name manager -value (Get-ADUser -Identity $record.'Manager ID').distinguishedName
        Make-Change -userName $samAccountName -name department -value $record.'Department Description'
        Make-Change -userName $samAccountName -name telephoneNumber -value $workTelephone[1]
        Make-Change -userName $samAccountName -name displayname -value $displayName
        Make-Change -userName $samAccountName -name employeeID -value $empNo

        #Send Gentle reminder about updating your phone number in Lawson
        if (($workTelephone[1] -eq $null) -and ((Get-Date).DayOfWeek -eq 'Monday'))
        {
			$mailContents = @{
				To = @($user.mail);
				Bcc = @('cdensmore@chs-mi.com');
				From = 'itcommunication@chs-mi.com';
				Subject = "Your Contact Information is not set in Lawson";
				BodyAsHtml = "$first,<br><br>You do not have a current Work Phone set in Lawson. Please follow <a href=`"https://chsconfluence.intra.chs-mi.com/download/attachments/45973725/Employee%20Space%20-%20Add-Update%20Work%20Phone%20-Quick%20Reference%20Guide.pdf?version=2&modificationDate=1473936164793&api=v2`">these instructions to update your work phone number</a><br>Alternatively, you can go the Intranet > Human Resources > Self-Service Portals Employee Space Instruction Manual > Employee Space Quick Reference - Add/Update Work Phone <br>The information from Lawson propagates to Outlook, making it easier for others to contact you.<br>Please call the help desk with any questions at x36014.<br><br>We will continue sending a reminder once a week until you update your phone number.<br><br>-Covenant Information Technology Team";
				Attachments = "\\chsnas1\shared\Human Resources\Talent Acquisition Employee Space\Employee Space - Add-Update Work Phone -Quick Reference Guide.pdf";
				SmtpServer = $smtpServer;
			}
            if ($sendEmails -eq $true){
                Send-MailMessage @mailContents
            }
        }
        #endregion

        #check existing emails
        if ($UserEmail.toupper().Trim() -ne $UPNUser.mail.ToUpper().trim())
        {
            Write-Output 'Testing users email against a regex. Determines whether or not we should output to HR'
            if ($((Get-ADuser -Identity $samAccountName).userprincipalname) -match '.+@chs-mi\.com')
            {
                Write-Verbose "$UserEmail doens't match $($UPNUser.mail)"
                New-Object psobject -Property @{'EmployeeID'=$samAccountName;'LawsonEmail'=$($UserEmail); 'ADEmail'=$((Get-ADuser -Identity $samAccountName).userprincipalname)} | Export-Csv -NoTypeInformation -Path $LawsonEmailOut -Append
            }
        }
    }
    elseif ($UPNUser)
    {
        Write-Output "Found a user matching $UserEmail to be $samAccountName. Assuming samAccountName has changed from $($UPNUser.samaccountname) to $samAccountName"
        Write-ErrorLog -name 'SamAccountName' -value $samAccountName
    }
    else
    {
        Write-Error 'doesnt exist!'
        Write-ErrorLog -name 'SamAccountName' -value $samAccountName
    }#end AD check if user exists
}#END Dump


#email HRIS the changes to email that were implemented today
$mailContents = @{
    'To' = 'HRIS@chs-mi.com';
    'BCC' = 'cdensmore@chs-mi.com';
    'From' = 'LawsonDumps-no-reply@chs-mi.com';
    'Subject' = "Email Updates for $(Get-Date -Format 'yyyyMMdd')";
    'BodyAsHtml' = $true;
    'Body' = 'Please review these changes and import into Lawson.';
    'Attachments' = $LawsonEmailOut;
    'SMTPServer' = $smtpServer
}
if ($sendEmails -eq $true){
    Send-MailMessage @mailContents
}

Stop-Transcript