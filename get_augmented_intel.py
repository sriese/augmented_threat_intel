import os
import requests
from langchain.llms import OpenAI

# Function to fetch and parse threat intelligence data
def get_threat_intelligence():
    # API endpoint
    #url = 'https://otx.alienvault.com/api/v1/pulses/subscribed/?limit=10&page=1'
    #url = 'https://otx.alienvault.com/otxapi/pulses/657b710c1b313b8547fa4145' # A pernicious potpourri of Python packages in PyPI
    #url = 'https://otx.alienvault.com/otxapi/pulses/657a4a3e99c3fd110dd0f5f8' # Operation Blacksmith: Lazarus Targets Organizations Worldwide Using Novel Telegram-Based Malware Written in DLang
    url = 'https://otx.alienvault.com/otxapi/pulses/657a2c924ea0e3e9e95e9433' # Russian Foreign Intelligence Service (SVR) Exploiting JetBrains TeamCity CVE Globally | CISA
    headers = {
        'X-OTX-API-KEY': os.environ.get('OTX_API_KEY') # API key
    }
    # Make the GET request
    response = requests.get(url, headers=headers)
    data = response.json()
    return data

# Further trim the STIX data to a minimum set of data to save on tokens
def get_trimmed_intel(data):
    # Initialize an empty list to store the custom dictionaries
    # trimmed_intel = []

    # Get base details
    item_id = data.get('id', '')
    name = data.get('name', '')
    description = data.get('description', '')

    # Get the specific indicators of compromise
    indicators = []
    for indicator in data.get('indicators', []):
        indicators.append({
            'type': indicator.get('type', ''),
            'indicator': indicator.get('indicator', '')
        })

    # Get a list of the specific MITRE Attack IDs
    attack_ids = data.get('attack_ids', [])

    # Create the trimmed object
    trimmed_intel = {
        'id': item_id,
        'name': name,
        'description': description,
        'indicators': indicators,
        'attack_ids': attack_ids
    }

    return trimmed_intel

# bare minimum langchain/OAI usage
def generate_ai_intel(threat_data):
    prompt_template = """You are a Threat Intelligence Analyst. You will be given STIX data from a Threat Intelligence Feed. Your job is to analyze the latest data from our threat intelligence feed and generate a list of actionable Courses of Action (COAs). Focus on identifying key threats and vulnerabilities, and propose specific, targeted strategies to mitigate these risks. Ensure that the COAs are practical, specific to our current Azure security infrastructure, and prioritize them based on the severity and likelihood of the threats. Also, include any recommendations for immediate actions and longer-term security enhancements. Where applicable, such as for hunting IOC's or for identifying potentially vulnerable inventory of systems, generate specific Azure Resource Graph KQL queries. 
    Format sections as follows:
    # Threat Description - provide a succent and brief description of the threat intelligence and its relevance towards our infrastructure
    # Immediate Courses of Action - a short list of the most immediate actions to take for mitigation and threat prevention
    # Defense in Depth - a short list of critical defense in depth controls that need to be implemented
    # System Analysis and Threat Hunting Queries - a list of Azure Sentinel, Azure Graph, or Azure Diagnostic KQL queries to hunt for threats or identify at risk or vulnerable systems. Be very succent and concise in your response.
    Threat Data: {0}""".format(threat_data)
    
    llm = OpenAI(temperature=0.9, max_tokens=2000)
    return llm.invoke(prompt_template)

threat_data = get_trimmed_intel(get_threat_intelligence())
resp = generate_ai_intel(threat_data)
print(resp)