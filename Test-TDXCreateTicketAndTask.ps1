#region login with api key
$TenantName = 'CovenantHealthcare'
$appID = 28
$requesterUID = "c28a3d4a-b271-e711-a94e-000d3a10474f"
$endpointURL = "https://$TenantName.teamdynamix.com/TDWebApi/api/auth/loginadmin"
$loginBody = @{
    "BEID"           = <# REDACTED - Provided by TeamDynamix #>;
    "WebServicesKey" = <# REDACTED - Privided by TeamDynamix #>;
}
$bearerToken = Invoke-RestMethod -Uri $endpointURL -Body (ConvertTo-Json $loginBody) -Method Post -Headers @{'Content-Type'='application/json'; 'charset'='utf-8'}
$bearerToken
#endregion

#region Create Ticket
$endpointURL = "https://$TenantName.teamdynamix.com/TDWebApi/api/$appID/tickets?EnableNotifyReviewer=true&NotifyRequestor=true&NotifyResponsible=true&AllowRequestorCreation=true"
$ticketBody = @{
    "TypeID"         = 3;
    "Title"          = "[Test]Title of the Ticket";
    "AccountID"      = 201;
    "StatusID"       = 0;
    "PriorityID"     = 0;
    "ResponsibleUid" = $requesterUID;
    "RequestorUid"   = $requesterUID;
}
$ticketResponse = Invoke-RestMethod -Uri $endpointURL -Body $ticketBody -Method Post -Headers @{'Authorization'="Bearer $bearerToken"}
$ticketResponse
#endregion

#region Create Tasks
$endpointURL = "https://$TenantName.teamdynamix.com/TDWebApi/api/$appID/tickets/$($ticketResponse.ID)/tasks"
$taskBody = @{
    'Title'              = 'Testing Ticket Task Creation';
    'EstimatedMinutes'   = 60;
    'Description'        = 'Device is either turned off or otherwise not communicable. If device has been removed delete/close the task and let Curtis Densmore know.';
    'ResponsibleGroupID' = '33';
}
$taskResponse = Invoke-RestMethod -Uri $endpointURL -Body $taskBody -Method Post -Headers @{'Authorization'="Bearer $bearerToken"}
$taskResponse
#endregion

<#
####
  The following section is not necessarily needed, but was used to find information for the above
####

#gets all groups
$endpointURL = "https://$TenantName.teamdynamix.com/TDWebApi/api/groups/search"
$groupBody = @{
    'IsActive' = $true;
}
$response = Invoke-RestMethod -Uri $endpointURL -Body $groupBody -Method Post -Headers @{'Authorization'="Bearer $bearerToken"}
$response | ?{$_.name -like '*desktop*'} | ft *
# Desktop Physical is 33
# SysAdmins is 36


#Get information on a given ticket
$ticketID = 29876
$endpointURL = "https://$TenantName.teamdynamix.com/TDWebApi/api/$appID/tickets/$ticketID"
$ticketResponse = Invoke-RestMethod -Uri $endpointURL -Method Get -Headers @{'Authorization'="Bearer $bearerToken"}
$ticketResponse

#>