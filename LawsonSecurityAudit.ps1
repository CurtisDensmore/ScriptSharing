#Lawson Req Center Security Audit
Clear-Host
$inCSV = Import-Csv -Path '\\chsnas1\home\e100922\projects\Lawson Security Audit\LawsonRQCusers.csv'
$outRecord = @()
$smtpServer = 'smtp.intra.chs-mi.com'

#Loop through each employee in listing, aggregating by manager
#Email managers a list of their employees and their security template
$inCSV | ForEach-Object {
    #clear variables
    $manager = $null
    $usrAD = $null

    #set variables
    $usrAD = Get-ADUser -Identity $_.'user id' -Properties *
    $manager = (Get-ADUser -Identity $usrAD.manager -Properties mail)

    #add to array, if no manager found, add "null"
    if($manager -ne $null){
        $outRecord += New-Object PSObject -Property ([ordered]@{'User ID'=$_.'user id';'Name'=$usrAD.name;'Manager'=$manager.samaccountname;'Manager Email'=$manager.mail})
    }else{
        $outRecord += New-Object PSObject -Property ([ordered]@{'User ID'=$_.'user id';'Name'=$usrAD.name;'Manager'='NULL';'Manager Email'='NULL'})
    }
}
Clear-Host
#$outRecord | Sort-Object -Property Manager | Format-Table * -AutoSize
$outRecord = $outRecord | Sort-Object -Property 'Manager Email'

#Loop through each unique manager, sending CSVs of their employees
foreach ($mgr in ($outRecord.manager | select -Unique )){
    $emailString = $null
    $mgrEmail=$null
    $emailString = "Hi,<br>The following employees have been identified as reporting to you. Yearly, IT must complete a security audit for access to our Lawson system. The employees listed have access to <b>Lawson Requisition Center.</b> Please review the following table and respond with either:<br>'Yes, these employees access are all correct.'<br> or <br>'No, the following changes must be made: {Listing any changes that must be made, and forwarding these changes to Bdecker@chs-mi.com}<br><br>"
    $emailString += $outRecord | Where-Object{$_.manager -like "*$mgr*"} | ConvertTo-Html
    $mgrEmail = $outRecord | Where-Object{$_.manager -like "*$mgr*"}
    
    #Send Brenda the failures
    if ($mgrEmail -eq 'NULL'){
        $mgrEmail[0].'Manager Email'='bdecker@chs-mi.com'
    }
    <#
    #Testing emails
    Send-MailMessage -To 'cdensmore@chs-mi.com' `
                    -Subject 'Lawson Security Audit for Managers' `
                    -From 'bdecker@chs-mi.com' `
                    -BodyAsHtml $emailString `
                    -SmtpServer $smtpServer
    #>
    Send-MailMessage -To $mgrEmail[0].'manager email' `
                    -Bcc @('cdensmore@chs-mi.com','bdecker@chs-mi.com')`
                    -Subject 'Lawson Security Audit for Managers' `
                    -From 'bdecker@chs-mi.com' `
                    -BodyAsHtml $emailString `
                    -SmtpServer $smtpServer
    $mgr
    $mgrEmail[0].'manager email'
}