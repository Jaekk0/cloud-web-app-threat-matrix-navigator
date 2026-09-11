# License Scope and Third-Party Notices

## Original Contributions

Original mapping analysis, explanations, and publication documentation are licensed under Creative Commons Attribution 4.0 International (CC BY 4.0), to the extent rights exist and the contributor has authority to license them. Original mapping contributor: [jaekk0](https://github.com/jaekk0).

License: https://creativecommons.org/licenses/by/4.0/

Legal text: [LICENSE](LICENSE)

This license statement does not replace the terms applicable to third-party material below. No trademark rights or endorsement are granted.

## Microsoft Cloud Web Applications Threat Matrix

Source creator: Microsoft Corporation.

Source: https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/

Pinned source revision: https://github.com/microsoft/Threat-Matrix-for-Cloud-Web-Applications/tree/26e5feefc312b99586243343daeea616a9ed2d33

Source license: https://github.com/microsoft/Threat-Matrix-for-Cloud-Web-Applications/blob/26e5feefc312b99586243343daeea616a9ed2d33/LICENSE

The matrix content is licensed under CC BY 4.0. It is supplied subject to the disclaimer of warranties and limitation of liability in Section 5 of that license. Retain this attribution, source and license references, and modification notice when redistributing adapted material as required by the license.

Modifications: extracted the matrix into a mapping inventory; retained all 35 source placements; selected and qualified Enterprise ATT&CK mappings; added eleven researcher-selected mappings, confidence assessments, alternatives, and custom-entry explanations; updated a revoked logging reference; and converted the results into Navigator annotations using official tactic membership. The added Application exploit (RCE) mapping uses T1190 with Medium confidence for public-facing initial access and explicitly notes that the web service can also be private, which is outside that mapping's scope. Exposed/misconfigured admin interfaces uses T1133 with Medium confidence for external administrative access, excluding mere exposure and private-only interfaces. Serverless trigger injection uses T1648 with Medium confidence for arbitrary code or command execution in serverless workloads, excluding legitimate processing and data-only outcomes without such execution. Development slots is partially mapped: its Defense Evasion placement uses T1578 with Medium confidence for managed compute deployment configuration changes to evade defenses; its Execution placement remains custom. This is a researcher interpretation, not an explicit MITRE slot example or change to official scope. Connector reuse uses T1021.007 with Medium confidence for connector-mediated lateral access to a cloud service, excluding non-cloud targets. The source does not establish ATT&CK's synchronized or federated identity context; this is a researcher interpretation, not an explicit MITRE connector example. Data theft uses T1530 with Medium confidence for the cloud-storage retrieval subset, not all cloud-hosted application data or a specified exfiltration channel; its original Impact placement is retained while Navigator uses Collection. Denial of wallet uses T1496.004 with Medium confidence for resource-intensive abuse of a compromised cloud service or SaaS application that incurs costs or consumes quotas. Availability loss and attacker financial gain are not required; request flooding and cloud-function invocations without established SaaS compromise do not qualify merely because billing increases. Publication preparation adds notices and replaces references to private build files with upstream references.

The Microsoft Security Blog is cited as explanatory context, not republished:
https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/

No Microsoft website software, themes, images, or blog HTML are distributed in this outcomes-only package.

## MITRE ATT&CK

Source: https://attack.mitre.org/matrices/enterprise/

Version: Enterprise ATT&CK 19.2.

Pinned data: https://github.com/mitre-attack/attack-stix-data/blob/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack-19.2.json

Pinned license: https://github.com/mitre-attack/attack-stix-data/blob/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/LICENSE.txt

The MITRE license and disclaimers are reproduced below. They also accompany each standalone JSON artifact.

License
-------
The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research,
development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce
MITRE's copyright designation and this license in any such copy.

"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

Disclaimers
-----------
MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part
of its adversary model and framework of techniques. Using the information contained within ATT&CK to address or cover
full categories of techniques will not guarantee full defensive coverage as there may be undisclosed techniques or
variations on existing techniques not documented by ATT&CK.

ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE
ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS,
AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT
THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR
FITNESS FOR A PARTICULAR PURPOSE.


MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation. This independent mapping is not endorsed by MITRE. The license permission statement above does not imply endorsement of the mappings.