#This script allows a user to input the SHA256 or MD5 hash value of a file, then returns a report from VirusTotal
#The script performs an API call, selects the count of malicious reports, and classifies the file as Malicious, Potentially Malicious, or Clean
Write-Output "The use of this script requires an API key from Virus Total. If you do not have a key, visit https://virustotal.com/gui/join-us"
do {
    $key=read-host -prompt "Enter your Virus Total API Key:"
    $hash=read-host -prompt "Enter the MD5 or SHA256 hash value of the file you would like to have verified:"
    $link='https://www.virustotal.com/api/v3/files/' + $hash
    $headers=@{}
    $headers.Add("Accept","application/json")
    $headers.Add("x-apikey", "$key")
    try{
        $real=Invoke-WebRequest -URI $link -Method GET -Headers $headers | Select-Object -ExpandProperty Content
        $reports=$real -split [system.environment]::NewLine | Select-String -Pattern ".count.:\s(.)"
        $total=$reports.Matches[0].Groups[1].Value
        if($total -ge 5){
        write-output("WARNING: Malicious file. $total vendors have reported this file as malicious.")
        }elseif(($total -gt 0) -and ($total -lt 5)){
        write-output("WARNING: Potentially malicious file. $total vendors have reported this file as malicious.")
        }elseif($total -eq 0){
        write-output("Not known to Virus Total to be malicious. 0 vendors have reported this file as malicious.")
    }
    }
    catch{
    write-host "Error: Either the API key entered was invalid, or Virus Total has not seen this file hash before."}
    $continue=Read-Host -Prompt "Search complete. Search again?(Y/N)"
} until ($continue -ne 'Y')