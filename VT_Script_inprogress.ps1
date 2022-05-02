do {
    $key=read-host -prompt "enter your key"
    $hash=read-host -prompt "enter the hash"
    $link='https://www.virustotal.com/api/v3/files/' + $hash
    $headers=@{}
    $headers.Add("Accept","application/json")
    $headers.Add("x-apikey", "$key")
    Function Validate-API {
	    try{
		    $validation=Invoke-Webrequest -URI $link -Method GET -Headers $headers -UseBasicParsing -EA Stop
	    return 1}
	    catch {
	    return 0}
    }
    while (Validate-API -ne 1){
	    Write-Output "Either the API key or the Hash value were invalid."
	    $key=Read-Host -Prompt "Enter your Virus Total API Key"
	    $hash=Read-host -Prompt "Enter the MD5 or SHA256 hash of the file in question"
    }
    Function Validate-Report{
	    try{
		    $response=Invoke-WebRequest -URI $link -Method GET -Headers $headers -EA Stop | Select-Object -ExpandProperty Content
		    $count=$response -split [system.environment]::NewLine | Select-String -Pattern ".count.:\s(.)"
		    $count.Matches[0].Groups[1].Value{
        return $count
	    }
        }
	    catch{
	    return $null}
    }
    while (Validate-Report -eq $null){
	    Write-Output "Virus Total has no reports for the file associated with this hash. Enter a different hash to continue."
	    $hash=Read-Host -Prompt "Enter the MD5 or SHA256 hash of the file in question."
    }
    $real=Invoke-WebRequest -URI $link -Method GET -Headers $headers | Select-Object -ExpandProperty Content
    $reports=$real -split [system.environment]::NewLine | Select-String -Pattern ".count.:\s(.)"
    $total=$reports.Matches[0].Groups[1].Value
    if($total -ge 5){
        write-output("Malicious")
        }elseif(($total -gt 0) -and ($total -lt 5)){
        write-output("Potentially Malicious")
        }elseif($total -eq 0){
        write-output("Not Malicious")
    }
    $continue=Read-Host -Prompt "Report complete. Search another file? (Y/N)"
} while ($continue -eq 'Y')
