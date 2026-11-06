# MITRE ATT&CK Mapping Notes

These mappings describe defensive hypotheses represented in the lab detections. They are not attribution claims.

| Detection | ATT&CK technique | Why the mapping is relevant | Validation caveat |
|---|---|---|---|
| Repeated authentication failures / many accounts from one source | T1110.001 Password Guessing; T1110.003 Password Spraying | Repeated failed logons or attempts against multiple accounts can be consistent with credential-guessing behavior | A burst can also be caused by a misconfigured service, user error, vulnerability scanner or shared egress IP |
| Repeated script-oriented web egress | T1071.001 Web Protocols | HTTP/S and web protocols can be used for command-and-control communication | User-agent strings and non-standard ports are not proof of C2; establish process, destination, traffic pattern and context |

## References

- T1110 Brute Force: https://attack.mitre.org/techniques/T1110/
- T1110.001 Password Guessing: https://attack.mitre.org/techniques/T1110/001/
- T1110.003 Password Spraying: https://attack.mitre.org/techniques/T1110/003/
- T1071.001 Web Protocols: https://attack.mitre.org/techniques/T1071/001/
