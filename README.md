# vtscan
Simple powershell script to call the Virus Total API and check a file hash for reported malicious behavior. 

Use of this script requires an API Key from Virus Total. 
If you do not have a key, please go to https://www.virustotal.com/gui/join-us. Create a free account, then go to https://www.virustotal.com/gui/my-apikey to locate your key.

This script will take a users API key, and an MD5 or SHA256 hash value to make an API call on Virus Total. After verifying the validity of the key and hash value, the script will return the total number of malicious reports. 

The script is contained in a do-while loop allowing users to check multiple hash values. 
