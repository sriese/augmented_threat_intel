# augmented_threat_intel
A proof of concept for using AI to generate relevant Courses of Action (CoA) from AlienVault OTX TAXII feeds
Developed for Norwich University CYBR382: Defensive Information Warfare

# Intro
>This project represents the proof of concept for an innovative approach in cybersecurity, combining the advanced analytical capabilities of Artificial Intelligence (AI) with threat intelligence analysis. The objective is to demonstrate the feasibility and effectiveness of a system that employs AI models, particularly through the integration of the LangChain library and OpenAI, to further process and interpret cyber threat data. By leveraging STIX-formatted intelligence from TAXII feeds, the system aims to dynamically generate actionable and relevant Courses of Action (COAs) for an organization. This proof of concept highlights the potential of AI-enhanced threat intelligence to provide comprehensive and actionable, near real-time defense against evolving cyber threats

# Conclusion
>The proof of concept could be significantly enhanced through additional prompt engineering and leveraging additional AI strategies such as Retrieval Augmented Generation (RAG) to leverage more specific organizational documentation and knowledge. These enhancements would allow the AI to fetch relevant information from an organization's own documents aligning the generated Courses of Action (COAs) more closely with the organization's unique policies, infrastructure, and risk profile offering a more tailored and context-aware analysis. Refining the AI prompts, including fine tuning and zero-shot prompting to elicit more precise and actionable insights would substantially enhance the consistency of the threat intelligence analysis. Combining fine-tuned prompt engineering with organization-specific data retrieval would create a powerful tool, adept at providing highly relevant and actionable organizational intelligence.

# Sample Outputs

In response to a Threat Intel https://otx.alienvault.com/otxapi/pulses/657b710c1b313b8547fa4145 related to malicious Python Packages:

## Threat Description
Python packages in the official Python package repository (PyPI) have been compromised with more than 100 malicious packages being discovered by researchers. Over the past year, 80 victims are downloading these packages daily, which include malware, with indicators pointing to 'blazywound.ignorelist.com' and the IP '204.152.203.78'. This threat is relevant to our Azure infrastructure if we have python packages installed or running Python-based workloads.

## Immediate Courses of Action

1. Temporarily halt all downloads and installations of Python packages from PyPI until a thorough review is conducted.
2. Perform scans of our Azure resources to identify any of the malicious indicators mentioned.
3. Investigate and analyze network logs to identify abnormal connections to the suspicious hostname and IP address.
4. Confirm and update all Python-based applications to use only verified packages.

## Defense in Depth

1. Implement stricter validation and control of third-party dependencies, particularly originating from PyPI.
2. Regularly validate and update all dependencies for Python applications.
3. Implement advanced threat protection capabilities in Azure to detect anomalous activities.

## System Analysis and Threat Hunting Queries

1. Azure Resources communicating with suspicious hostname and IP:
   ```KQL  
   AzureDiagnostics
   | where TimeGenerated >= ago(7d)
   | where ResourceType == "PUBLICIPADDRESSES"
   | where Properties_d contains "blazywound.ignorelist.com" or Properties_d contains "204.152.203.78"
   ```
2. Azure Resources with malicious hash values:
   ```KQL   
   SecurityEvent 
   | where TimeGenerated >= ago(7d)
   | where Hashes has "686f6d2fb8dd540052f2c698e8aff662" or Hashes has "104a5192cf032cee44b732d33458a27909cef45d7391e092b9c13acd5779bb39"
   ```
3. Azure Resources running malicious processes:
   ```KQL   
   SecurityEvent 
   | where TimeGenerated >= ago(7d)
   | where CommandLine has "python" 
   | extend Indicator = extractjson("$[0].Indicator", Indicators, typeof(string))
   | where Indicator in ('686f6d2fb8dd540052f2c698e8aff662', '104a5192cf032cee44b732d33458a27909cef45d7391e092b9c13acd5779bb39')
   ```

## Threat Description
This threat intelligence report indicates that Russia's foreign intelligence service (SVR) is exploiting a vulnerability in JetBrains TeamCity servers, as reported by the Cybersecurity and Infrastructure Security Agency (CISA). The threat actors are using various techniques to gain access to the vulnerable systems, such as OS credential dumping, automated exfiltration, obfuscated files, masquerading, and command and script interpreter. 

## Immediate Courses of Action
1. Patch and upgrade TeamCity servers to the latest version to ensure the vulnerability is not exploited.
2. Identify and block any network communication associated with the Russian SVR.
3. Use Azure Security Center to audit and identify potential vulnerable systems for the CVE.
4. Put in place network segmentation and access control lists to reduce the attack surface. 
5. Enable strong authentication and authorization measures on the TeamCity environment. 

## Defense in Depth
1. Use Azure Active Directory for user and identity management to ensure only authorized personnel have access to the TeamCity environment. 
2. Enable multi-factor authentication (MFA) for all TeamCity accounts.
3. Implement role-based access control (RBAC) to limit access to the TeamCity environment only to the necessary personnel. 
4. Enforce secure protocols, such as TLS 1.2, over the TeamCity environment for all communications. 
5. Configure Azure Network Security Groups to restrict inbound traffic to only necessary ports and services for the TeamCity environment. 

## System Analysis and Threat Hunting Queries
1. Azure Resource Graph KQL query to identify all affected systems with the vulnerable version of TeamCity: 
```KQL  
Type=Resource | where type == "microsoft.teamcity/servers" and properties.version !~ "latest"
```
2. Azure Sentinel KQL query to identify any processes associated with the Russian SVR IP addresses: 
```KQL
ProcessCreationEvents | where RemoteIP in (list_of_SVR_IP_addresses)
```
3. Azure Sentinel KQL query to identify any malicious file hashes that have been used in the TeamCity attacks: 
```KQL
FileHash=* | where FileHash in (list_of_malicious_hashes)
```