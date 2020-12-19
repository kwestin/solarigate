# Solorigate

[SolarWinds 8-K](https://github.com/kwestin/solarigate/blob/main/solarwinds8k.pdf) describing the issue stated that around 18,000 customers were affected. They indicated that it was Microsoft Office 365 as the initial attack vector. SolarWinds, in collaboration with Microsoft,has taken remediation steps to address the compromise and is investigating whether further remediation steps are required, over what period of time this compromise existed and whether this compromise is associated with the **attack on its Orion software build system**. SolarWinds also is investigating in collaboration with Microsoft as to whether any customer, personnel or other data was exfiltrated as a result of this compromise but has uncovered no evidence at this time of any such exfiltration.

* SolarWinds Security Advisory \
https://www.solarwinds.com/securityadvisory 
* Microsoft labeled the attack "Solorigate" \
https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Behavior:Win32/Solorigate.C!dha&ThreatID=2147771132 \
https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/ \
* FireEye refers to the backdoor as SUNBURST. The campaign is tracked as UNC2452\
https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html\
* DHS Emergency Directive \
https://cyber.dhs.gov/ed/21-01/
* Important steps for customers to protect themselves from recent nation-state cyberattacks \
https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/
* CISA Alert (AA20-352A)
Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations \
https://us-cert.cisa.gov/ncas/alerts/aa20-352a


# Detection Resources #

* Elastic Security provides free and open protections for SUNBURST  \
https://www.elastic.co/blog/elastic-security-provides-free-and-open-protections-for-sunburst

* Finding SUNBURST backdoor with Zeek logs & Corelight \
https://corelight.blog/2020/12/15/finding-sunburst-backdoor-with-zeek-logs-and-corelight/

* Using Splunk to Detect Sunburst Backdoor \
https://www.splunk.com/en_us/blog/security/sunburst-backdoor-detections-in-splunk.html

* DGA domain names \
https://github.com/bambenek/research/blob/main/sunburst/uniq-hostnames.txt




# Known Victims  #

* US Treasury
* US Department of Energy
* US Homeland Security
* US NTIA
* National Nuclear Security Administration
* National Institutes of Health
* 
* FireEye
https://www.zdnet.com/article/microsoft-fireeye-confirm-solarwinds-supply-chain-attack/ 

# Command and Control #
avsvmcloud.com 


# DLL IoCs #

Sha256: 32519685c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77\
Sha1: 76640508b1e7759e548771a5359eaed353bfleec \
File Size: 1011032 bytes \
File Version: 2019.4.5200.9083 \
Date first seen: March 2020 

Sha256: dab758bf98d9b36fa057a66cd0284737abf89857b73ca89280267ee7caf62f3b \
Sha 1: 1acf3108bf1e376c8848fbb25dc87424f2c2a39c \
File Size: 1028072 bytes\
File Version: 2020.2.100.12219 \
Date first seen: March 2020 

Sha256: eb6fab5a2964c5817fb239a7a5079cabca0a00464fb3e07155f28b0a57a2c0ed \
Sha 1t: e257236206e99f5a5c62035c9c59c57206728b28 \
File Size: 1026024 bytes \
File Version: 2020.2.100.11831 \
Date first seen: March 2020 

Sha256: c09040d35630d75dfef0f804f320f8b3d16a481071076918e9b236a321c1ea77 \
Sha 1: bcb5a4dcbc60d26a5f619518f2cfcl b4bb4e4387 \
File Size: 1026024 bytes\
File Version: not available \
Date first seen: March 2020 

Sha256: ac1b2b89e60707a20e9eb1ca480bc3410ead40643b386d624c5d21b47c02917c \
Sha1: 6fdd82b7ca1c1f0ec67c05b36d14c9517065353b \
File Size: 1029096 bytes \
File Version: 2020.4.100.478 \
Date first seen: April 2020 

Sha256: 019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134 \
Sha1: 2f1a5a7411d015d01aaee4535835400191645023 \
File Size: 1028072 bytes \
File Version: 2020.2.5200.12394 \
Date first seen: April 2020 

Sha1: d130bd75645c2433f88ac03e73395fba172ef676 \
Sha256: ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0bOaa8211fe858d6 \
Sha1: d130bd75645c2433f88ac03e73395fba172ef676 \
File Size: 1028072 bytes \
File Version: 2020.2.5300.12432\
Date first seen: May 2020 

** Older DLLs used **

Sha256: a25cadd48d70f6ea0c4a241d99c5241269e6faccb4054e62d16784640f8e53bc \
Sha1: 5e643654179e8b4cfe1d3c1906a90a4c8d611cea \
File Size: 934232 bytes \
File Version: 2019.4.5200.8890 \
Date first seen: October 2019 
 
Sha256: d3c6785e18fba3749fb785bc313cf8346182f532c59172b69adfb31b96a5d0af \
Sha1: ebe711516d0f5cd8126f4d53e375c90b7b95e8f2 \
File Size: 940304 bytes\
File Version: 2019.4.5200.8890 \
Date first seen: October 2019 

# From Microsoft Regarding Code Singing Cert #

The attackers compromised signed libraries that used the target companies' own digital certificates, attempting to evade application control technologies. Microsoft already removed these certificates from its trusted list. The certificate details with the signer hash are shown below: 
 
"Signer": "Solarwinds Worldwide, LLC", \
"SignerHash": "47d92d49e6f7f296260dalaf355f941eb25360c4"
 
The DLL then loads from the installation folder of the SolarWinds application. Afterwards, the main implant installs as a Windows service and as a DLL file in the following path using a folder with different names. \
• installation folder , for example, '&lt;drive letter&gt;':\Program Files(x86))SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll \
• the NET Assembly cache folder (when compiled) 
C:\Windows1System32\configlsystemprofile\AppData\Local\assembly\tmp)&lt;random-named folder&gt; SolarWinds.Orion.Core.BusinessLayer.dll 
 
While Microsoft researcher observed malicious code from the attacker activated only when running under SolarWinds.BusinessLayerHost.exe process context, for the DLL samples currently analyzed, Microsoft Researchers have also seen different SolarWinds processes potentially loading the malicious library. The following list is again non-exhaustive as the situation is still developing at this point. We recommend monitoring the history and network or process activity of this SolarWinds process closely, especially activity coming from SolarWinds.BusinessLayerHost.exe: 
 
• ConfigurationWizard.exe \
• NetflowDatabaseMaintenance.exe \
• NetFlowService.exe \
• SolarWinds.Administration.exe \
• SolarWinds.BusinessLayerHost.exe \
• SolarWinds.Collector.Service.exe \
• SolarwindsDiagnostics.exe 
 
