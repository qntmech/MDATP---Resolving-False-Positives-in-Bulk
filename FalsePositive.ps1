$tenantId = '<tenant ID>' ### Paste your own tenant ID here
$appId = '<app ID>' ### Paste your own app ID here
$appSecret = '<app Secret>' ### Paste your own app keys here
$resourceAppIdUri = 'https://api.securitycenter.windows.com'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"

$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}

$gett=Invoke-WebRequest -Uri https://login.windows.net/$tenantId/oauth2/token -Method POST -Body $authBody
$gett=($gett.Content | ConvertFrom-Json)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$contentType = "application/json"
$token=$gett.access_token
$header = @{"Authorization"="Bearer $token"}

$splitFiles = Get-ChildItem "C:\temp\Pemex\SplitFiles"
	for($counter=0; $counter -lt $splitFiles.Count;$counter++)
		{
			$alertList = Get-Content $splitFiles[$counter].FullName #######  Paste in the location of a list of machines
			$json = @{'comment' = 'Offboard'
				  'status' = "Resolved"
				  'assignedTo' = "email@domain.com"
                                  'classification' = "FalsePositive"
                                  'determination' = "Malware"
                                  'comment' = "No Comment"
		} | ConvertTo-Json

				foreach($alert in $alertList)
					{
    						$alert    
    						$answer = Invoke-RestMethod -Headers $header -Uri  https://api-us.securitycenter.windows.com/api/alerts/$alert -Method POST -Body $json -ContentType $contentType
					}
		Start-Sleep -Second 60
		}

