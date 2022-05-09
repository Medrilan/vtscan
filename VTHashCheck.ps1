##This script allows a user to receive the number of malicious reports on a file from AntiVirus companies. It does so by taking an MD5 or SHA256 hash, and calling the Virus Total API to retreive the results.# 
#If the API key is invalid or the file hash entered is unkown to VirusTotal, the script will loop back and allow re-entry of a key and hash value.# 

Write-Host "To request a report on a file hash, you will need a Virus Total API key. If you do not have a key, please visit https://www.virustotal.com/gui/my-apikey and sign up for a free account."
#The script is wrapped in a do-while loop that allows continues restarts at the end of a hash check.#
do{
    #The nested do-while loop contains the validation process.#
    do{
    #Declaring variables including those requiring user input. These are in the loop to more easily re-check values after an invalid input.#
        $key=read-host -prompt "Please enter your VirusTotal API Key:"
        $hash=read-host -prompt "Please enter the SHA256 or MD5 hash value of the file to validate:"
        $link='https://www.virustotal.com/api/v3/files/' + $hash
        $headers=@{}
        $headers.Add("Accept","application/json")
        $headers.Add("x-apikey", "$key")
        #To make the end user experience more streamlines, I make an API call with the given key to the location of the file hash.#
            try{
            ($response=Invoke-WebRequest -URI $link -Method GET -Headers $headers | Select-Object -ExpandProperty Content -ErrorAction Stop).BaseResponse
            Write-Host $response.StatusCode
            $status = 'success'
            } catch [System.Net.WebException] {
                Write-Verbose "error $($_.Exception.Message)"
                $status=$_.Exception.Response.StatusCode
            }
        #Here I'm using the response from out validation API call to provide feedback on errors or successful calls.#
        If ($status -eq "NotFound"){Write-Output "File not found. Either the hash is invalid, or VirusTotal has not seen this file before. (404)"}
        ElseIf ($status -eq "Unauthorized"){Write-Output "Invalid API key. Please try again. (401)"}
        Else {Write-Output "Valid API key and hash value. Generating report..."}
    #If the site returns a 401 (invalid api key) or 404 (file not found) then we loop back to request reentry#
    } while (($status -eq "Unauthorized") -or ($status -eq "NotFound"))
    #Here we run the API call specifying the count of reports from the requested hash value. More specifically, were filtering the returned data to just the numerical value in the count field#
    $real=Invoke-WebRequest -URI $link -Method GET -Headers $headers | Select-Object -ExpandProperty Content
    $reports=$real -split [system.environment]::NewLine | Select-String -Pattern ".count.:\s(.)"
    $total=$reports.Matches[0].Groups[1].Value
    #Using an if/elseif statement to classify a file based on report counts. The output will be in black text with green/yellow/red highlights so results stand out more.#
    if($total -ge 5){
    write-Host "This file is malicious. $total vendors have reported it as such." -ForegroundColor Black -BackgroundColor Red
    }elseif(($total -gt 0) -and ($total -lt 5)){
    write-Host "This file is potentially malicious. $total vendors have reported it as such." -ForegroundColor Black -BackgroundColor Yellow
    }elseif($total -eq 0){
    write-Host "This file is not malicious. 0 vendors have reported it as such." -ForegroundColor Black -BackgroundColor Green
    }
    #After the file is checked and the response is issued, we allow the user to restart the search for a new file.#
    $continue=Read-Host -Prompt "Report complete. Search another file? (Y/N)"
} while ($continue -eq 'Y')
