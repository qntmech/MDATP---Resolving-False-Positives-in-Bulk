$tenantId = '' ### Paste your own tenant ID here
$appId = '' ### Paste your own app ID here
$appSecret = '' ### Paste your own app keys here
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

$splitFiles = Get-ChildItem "C:\Users\wkam\PycharmProjects\Pemex\split"
	for($counter=0; $counter -lt $splitFiles.Count;$counter++)
		{
			$alertList = Get-Content $splitFiles[$counter].FullName #######  Paste in the location of a list of machines
			$json = @{'comment' = 'Offboard'
				  'status' = "Resolved"
				  'assignedTo' = "jose.noel@pemex.com"
                  'classification' = "FalsePositive"
                  'determination' = "Malware"        
		} | ConvertTo-Json

				foreach($alert in $alertList)
					{
    						$alert    
    						$answer = Invoke-RestMethod -Headers $header -Uri  https://api-us.securitycenter.windows.com/api/alerts/$alert -Method PATCH -Body $json -ContentType $contentType
					}
		Start-Sleep -Second 60
		}

