# Solid Pancake

Collect Microsoft Defender Quarantined samples at scale.

Tested on:
  - Windows 10 x64
  - Windows 11 x64
 
 The Agent will:
  - listen for Windows Events (ID 1117 for now)
  - Finds the quarantined file inside Windows Defender data files 
  - Decrypts the file and grabs the original file (thanks to [this](https://reversingfun.com/posts/how-to-extract-quarantine-files-from-windows-defender/) awesome post)
  - re-encrypt the file using a provided GPG key
  - uploads the artifact to a webdav endpoint or an Azure blob storage
  - logs everything to stderr, log file, Splunk HEC or Microsoft Sentinel
  
 
