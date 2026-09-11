# Microsoft Cloud Web Applications Threat Matrix

Extraction date: 2026-09-11. Target: Enterprise ATT&CK 19.2; Navigator 5.3.2, layer format 4.5.

Contributor: [jaekk0](https://github.com/jaekk0). See [third-party notices](THIRD-PARTY-NOTICES.md).

## Scope and method

Reviewed the complete matrix, all 31 technique pages (including mitigations), all 11 tactic pages, the About page, and the Microsoft blog. Matrix and tactic pages agree on 35 placements. The blog is explanatory, not a complete inventory: it omits SSRF and several repeated placements. Source revision: [Microsoft matrix](https://github.com/microsoft/Threat-Matrix-for-Cloud-Web-Applications/tree/26e5feefc312b99586243343daeea616a9ed2d33). ATT&CK data revision: [Enterprise 19.2](https://github.com/mitre-attack/attack-stix-data/blob/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack-19.2.json). Source snapshots and build tools are not part of this outcomes-only publication.

Results: 34 mapped placements, 1 custom placements; 31 mapped technique names, 1 custom names; 26 Navigator annotations using 24 distinct active ATT&CK IDs.

Technique-name counts can overlap when placements differ. Development slots is partially mapped: Defense Evasion maps to T1578 at Medium confidence, while Execution remains custom. It appears in both name counts, but each of its two placements is counted exactly once.

High = explicit Microsoft mapping verified against MITRE, or direct researcher correspondence. Medium = qualified scope or variant-dependent correspondence. Unmapped = custom, without a sufficiently direct unconditional mapping. Source references are not represented as MITRE endorsements of this matrix. Subtechnique IDs are retained where supported.

## A. Summary table

| Tactic | Technique Name | ATT&CK ID | Mapping Confidence |
|---|---|---|---|
| Resource Development | Subdomain takeover | T1584.001 | High |
| Initial Access | Application vulnerability | T1190 | High |
| Initial Access | Code injection in connected repository | T1195.002 | High |
| Initial Access | Compromised image in registry | T1195.002 | High |
| Initial Access | Exposed/misconfigured admin interfaces | T1133 | Medium |
| Initial Access | Serverless trigger injection | T1648 | Medium |
| Initial Access | Using deployment credentials | T1078 | High |
| Initial Access | Valid cloud accounts | T1078.004 | High |
| Execution | Application exploit (RCE) | T1190 | Medium |
| Execution | Cloud native terminal | T1059 | High |
| Execution | Development slots | custom | Unmapped |
| Execution | Site extensions | T1195.001 | High |
| Persistence | Cron jobs | T1053 | High |
| Persistence | Source code modification | T1195.002 | Medium |
| Persistence | Valid cloud accounts | T1078.004 | High |
| Privilege Escalation | Access cloud resources | T1078.004 | High |
| Privilege Escalation | Access workload identity credentials | T1552.005 | High |
| Defense Evasion | Development slots | T1578 | Medium |
| Defense Evasion | Disable cloud logging | T1685.002 | High |
| Credential Access | Access workload identity credentials | T1552.005 | High |
| Credential Access | Brute force | T1110 | High |
| Credential Access | Cloud credentials in runtime environment | T1552 | High |
| Discovery | Access to connected cloud storage | T1530 | High |
| Discovery | Cloud service discovery | T1526 | High |
| Discovery | Instance metadata API | T1526 | Medium |
| Lateral Movement | Access cloud resources | T1078.004 | High |
| Lateral Movement | Connector reuse | T1021.007 | Medium |
| Lateral Movement | Server side request forgery (SSRF) | T1210 | Medium |
| Collection | Access application database | T1213 | High |
| Collection | Event data capture | T1213 | High |
| Impact | Data destruction | T1485 | High |
| Impact | Data theft | T1530 | Medium |
| Impact | Defacement | T1491 | High |
| Impact | Denial of wallet | T1496.004 | Medium |
| Impact | Resource hijacking | T1496 | High |

## B. Navigator layer

[Importable JSON layer](microsoft-cloud-web-applications.navigator.json). Open Existing Layer > Upload from local in ATT&CK Navigator. ATT&CK version 19 in the Navigator field selects the v19 release family; all IDs and memberships are checked against the pinned 19.2 bundle.

Navigator cannot reproduce arbitrary source tactic assignments or render custom technique cells in the standard Enterprise domain. No invalid technique/tactic pairs are inserted. All 11 source tactics remain represented in layer metadata, including custom-only placements. Identical official ID/tactic annotations are merged without losing any original placement in their comments. Unscored background cells are not claims of mapped coverage.

### Tactic differences

| Original tactic | Original technique | Official ID | Navigator tactic |
|---|---|---|---|
| Initial Access | Serverless trigger injection | T1648 | execution |
| Execution | Application exploit (RCE) | T1190 | initial-access |
| Execution | Site extensions | T1195.001 | initial-access |
| Persistence | Source code modification | T1195.002 | initial-access |
| Privilege Escalation | Access workload identity credentials | T1552.005 | credential-access |
| Defense Evasion | Development slots | T1578 | defense-impairment |
| Defense Evasion | Disable cloud logging | T1685.002 | defense-impairment |
| Discovery | Access to connected cloud storage | T1530 | collection |
| Lateral Movement | Access cloud resources | T1078.004 | privilege-escalation |
| Impact | Data theft | T1530 | collection |

## Mapping rationale and alternatives

### Subdomain takeover

Selected [T1584.001: Domains](https://attack.mitre.org/techniques/T1584/001); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Subdomain%20takeover/).

Mapped original tactics: Resource Development.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Application vulnerability

Selected [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Application%20vulnerability/).

Mapped original tactics: Initial Access.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Code injection in connected repository

Selected [T1195.002: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Code%20injection%20in%20connected%20repository/).

Mapped original tactics: Initial Access.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Compromised image in registry

Selected [T1195.002: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Compromised%20image%20in%20registry/).

Mapped original tactics: Initial Access.

Microsoft lists T1195.002 and T1525. Select T1195.002 for malicious images entering the application's deployment supply chain, consistent with its Initial Access placement and public/private registry scope. T1525 is the more specific alternative for implanting an internal image for persistence, not every described registry scenario.

### Exposed/misconfigured admin interfaces

Selected [T1133: External Remote Services](https://attack.mitre.org/techniques/T1133); Medium confidence; Researcher mapping; conditional external-access scope. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Exposed%20misconfigured%20admin%20interfaces/).

Mapped original tactics: Initial Access.

Maps to T1133 where an externally reachable administrative interface is used to gain access to the application environment, including authenticated management access or exposed services without authentication. Mere exposure is not itself adversary behavior. Private-only interfaces and misconfigurations that do not provide external remote access are outside this mapping's scope. T1078 may additionally describe valid-credential abuse; T1190 may apply when a public-facing weakness is exploited. Medium confidence reflects the source's broader exposed-or-misconfigured category. Preserve Microsoft's original Initial Access tactic.

### Serverless trigger injection

Selected [T1648: Serverless Execution](https://attack.mitre.org/techniques/T1648); Medium confidence; Researcher mapping; conditional arbitrary-execution scope. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Serverless%20trigger%20injection/).

Mapped original tactics: Initial Access.

Maps to T1648 when attacker-controlled event inputs cause arbitrary code or commands to execute in a serverless workload. The function may already exist; creating a malicious function is not required. Merely triggering legitimate processing, or causing data access without attacker-controlled code or command execution, is outside this mapping's scope. T1190 may additionally apply where exploitation of a public-facing application provides initial access. T1059.009 concerns cloud-provider API abuse, not every application API request or upload. Medium confidence reflects the source's broader range of outcomes; T1648 captures the execution behavior, not the input-injection mechanism itself. Microsoft's original Initial Access tactic is preserved in comments; Navigator places T1648 under Execution.

### Using deployment credentials

Selected [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078); High confidence; Researcher mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Using%20deployment%20credentials/).

Mapped original tactics: Initial Access.

Abusing legitimate deployment credentials for authenticated management access directly matches Valid Accounts. Use the parent rather than T1078.004 because publishing/SCM credentials are not necessarily cloud user or service identities. Credential acquisition and subsequent command execution are separate behaviors.

### Valid cloud accounts

Selected [T1078.004: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Valid%20cloud%20accounts/).

Mapped original tactics: Initial Access, Persistence.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Application exploit (RCE)

Selected [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190); Medium confidence; Researcher mapping; conditional public-facing scope. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Application%20exploit%20(RCE)/).

Mapped original tactics: Execution.

Select T1190 for exploitation of an internet-facing cloud web application to gain initial access through remote code execution. The web service can also be private; that private-service scenario is not covered by T1190 merely because RCE occurs. T1210 may apply when an internal remote service is exploited for lateral movement after an initial foothold, but that context is not established here. T1203 concerns client applications, not generic server-side RCE. Medium confidence reflects the source's unspecified exposure and access context. Preserve Microsoft's original Execution tactic in comments; Navigator places T1190 under Initial Access.

### Cloud native terminal

Selected [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Cloud%20native%20terminal/).

Mapped original tactics: Execution.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Site extensions

Selected [T1195.001: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001); High confidence; Researcher mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Site%20extensions/).

Mapped original tactics: Execution.

A malicious or compromised third-party NuGet extension installed as a trusted dependency matches Compromise Software Dependencies and Development Tools, including package-name confusion. Prefer T1195.001 over the broader T1195.002. T1176 can cover malicious extension persistence, but persistence is not established here. ATT&CK places the selected mechanism in Initial Access; Microsoft places its execution outcome in Execution.

### Cron jobs

Selected [T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Cron%20jobs/).

Mapped original tactics: Persistence.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Source code modification

Selected [T1195.002: Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002); Medium confidence; Researcher mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Source%20code%20modification/).

Mapped original tactics: Persistence.

Modifying canonical source or deployment artifacts before automated production consumption matches Compromise Software Supply Chain, consistent with Microsoft's connected-repository mapping. T1525 is a specific alternative for the internal container-image variant. The selection captures the common deployment mechanism, not every possible runtime edit. Microsoft's Persistence placement describes repeated redeployment; ATT&CK assigns the selected technique to Initial Access.

### Access cloud resources

Selected [T1078.004: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Access%20cloud%20resources/).

Mapped original tactics: Privilege Escalation, Lateral Movement.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Access workload identity credentials

Selected [T1552.005: Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Access%20workload%20identity%20credentials/).

Mapped original tactics: Privilege Escalation, Credential Access.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Development slots

Selected [T1578: Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578); Medium confidence; Researcher mapping; conditional managed-infrastructure interpretation. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Development%20slots/).

Mapped original tactics: Defense Evasion.

Maps to T1578 when an adversary creates or modifies a cloud application deployment slot or comparable managed compute deployment configuration to evade defenses, for example by placing malicious activity in a staging deployment outside production-focused monitoring or by changing deployment routing to bypass defensive checks. This is a researcher interpretation of the parent technique's broad infrastructure-modification definition, not an explicit MITRE deployment-slot example or a change to official ATT&CK scope. Editing application code alone, invoking an unchanged staging endpoint, or promoting a deployment without an established defense-evasion purpose is outside this mapping's scope. Prefer the parent T1578 over T1578.005, which focuses on settings affecting compute size, location, and available resources; T1535 concerns geographic regions. Microsoft's original Defense Evasion tactic is retained; Navigator places T1578 under Defense Impairment. The separate Execution placement remains custom.

### Disable cloud logging

Selected [T1685.002: Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002); High confidence; Microsoft mapping updated by MITRE revoked-by relationship. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Disable%20cloud%20logging/).

Mapped original tactics: Defense Evasion.

Microsoft references T1562.008. ATT&CK 19.2 revokes it in favor of T1685.002 (Disable or Modify Cloud Log), verified by relationship--8f018f26-24ff-4ad1-9583-a5c92bda350b. The replacement belongs to Defense Impairment, while Microsoft's original tactic is Defense Evasion. The mapping covers disabling/modifying logging; other log-deletion behaviors may need additional analysis.

### Brute force

Selected [T1110: Brute Force](https://attack.mitre.org/techniques/T1110); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Brute%20force/).

Mapped original tactics: Credential Access.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Cloud credentials in runtime environment

Selected [T1552: Unsecured Credentials](https://attack.mitre.org/techniques/T1552); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Cloud%20credentials%20in%20runtime%20environment/).

Mapped original tactics: Credential Access.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Access to connected cloud storage

Selected [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530); High confidence; Researcher mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Access%20to%20connected%20cloud%20storage/).

Mapped original tactics: Discovery.

Reading source code and configuration from cloud object storage directly matches Data from Cloud Storage. T1619 concerns object enumeration rather than reading contents. The Microsoft Discovery placement is preserved in annotations; ATT&CK places this behavior in Collection.

### Cloud service discovery

Selected [T1526: Cloud Service Discovery](https://attack.mitre.org/techniques/T1526); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Cloud%20service%20discovery/).

Mapped original tactics: Discovery.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Instance metadata API

Selected [T1526: Cloud Service Discovery](https://attack.mitre.org/techniques/T1526); Medium confidence; Microsoft explicit mapping; qualified scope. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Instance%20metadata%20API/).

Mapped original tactics: Discovery.

Retain Microsoft's explicit T1526 mapping for cloud-service discovery. The description also covers VM and network information, so this is not an exact mapping of every metadata query. T1552.005 applies specifically to credential retrieval and is separately represented by Access workload identity credentials.

### Connector reuse

Selected [T1021.007: Cloud Services](https://attack.mitre.org/techniques/T1021/007); Medium confidence; Researcher mapping; conditional connector-mediated cloud-access interpretation. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Connector%20reuse/).

Mapped original tactics: Lateral Movement.

Maps to T1021.007 where an adversary abuses an existing managed connector to access a connected cloud service using the connector's stored authenticated identity. The connector may perform authentication and remote actions on the adversary's behalf without exposing its credentials. This is a researcher interpretation of connector-mediated lateral access, not an explicit MITRE connector-reuse example. The Microsoft source does not establish the synchronized or federated identity context described by ATT&CK, which limits confidence. Connections to non-cloud targets and actions that do not establish access to a connected cloud service are outside this mapping's scope. Microsoft's original Lateral Movement tactic is retained. T1550.001 may apply when application-token compromise and use are established; T1671 may apply to OAuth integration persistence, which is not required or established by this mapping.

### Server side request forgery (SSRF)

Selected [T1210: Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210); Medium confidence; Microsoft explicit mapping; qualified scope. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Server%20side%20request%20forgery%20(SSRF)/).

Mapped original tactics: Lateral Movement.

Retain Microsoft's explicit T1210 mapping for exploitation of internal remote services through SSRF. Merely redirecting an HTTP request is broader than remote-service exploitation; the mapping applies to the exploitation/lateral-movement case, not every SSRF request. T1190 instead describes initial exploitation of the public-facing application.

### Access application database

Selected [T1213: Data from Information Repositories](https://attack.mitre.org/techniques/T1213); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Access%20application%20database/).

Mapped original tactics: Collection.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Event data capture

Selected [T1213: Data from Information Repositories](https://attack.mitre.org/techniques/T1213); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Event%20data%20capture/).

Mapped original tactics: Collection.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Data destruction

Selected [T1485: Data Destruction](https://attack.mitre.org/techniques/T1485); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Data%20destruction/).

Mapped original tactics: Impact.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Data theft

Selected [T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530); Medium confidence; Researcher mapping; conditional cloud-storage collection. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Data%20theft/).

Mapped original tactics: Impact.

Maps to T1530 where an adversary retrieves application content, user information, configuration files, or proprietary content from cloud storage used by the application or its connected resources. Microsoft explicitly includes storage and connected cloud resources, supporting this researcher-selected alignment. The source also describes broader application-data retrieval without specifying the storage type or access method, which limits confidence. Collection from local files, process memory, or information repositories is not covered by this mapping merely because the application is cloud-hosted. This mapping represents collection from cloud storage, not a specified exfiltration channel. Microsoft's original Impact tactic is retained; Navigator places the annotation under Collection.

### Defacement

Selected [T1491: Defacement](https://attack.mitre.org/techniques/T1491); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Defacement/).

Mapped original tactics: Impact.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

### Denial of wallet

Selected [T1496.004: Cloud Service Hijacking](https://attack.mitre.org/techniques/T1496/004); Medium confidence; Researcher mapping; conditional cloud-service hijacking. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Denial%20of%20wallet/).

Mapped original tactics: Impact.

Maps to T1496.004 where an adversary abuses a compromised cloud service or SaaS application to perform resource-intensive operations that incur costs or consume service quotas for the victim. ATT&CK explicitly recognizes these financial consequences; service unavailability and attacker financial gain are not required. This is a researcher-selected alignment with Microsoft's cloud-service abuse and cost-inflation behavior, not an unconditional equivalence. Microsoft also describes request flooding and cloud-function invocations without establishing compromise of a SaaS application, so those cases are not covered merely because they increase billing. Microsoft's original Impact tactic is retained.

### Resource hijacking

Selected [T1496: Resource Hijacking](https://attack.mitre.org/techniques/T1496); High confidence; Microsoft explicit mapping. [Microsoft source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Resource%20hijacking/).

Mapped original tactics: Impact.

Retain the active ATT&CK reference explicitly published by Microsoft. Preserve the referenced parent/subtechnique specificity rather than infer a narrower mechanism.

## C. Custom / unmapped techniques

### Development slots

Status: custom. Original tactics: Execution. Source identifier: MS-TA7011 (Microsoft identifier, not an ATT&CK ID). [Source](https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/techniques/Development%20slots/).

The Execution placement remains custom. Running code in a development slot has no single direct mapping across all described platforms. T1648 may cover arbitrary execution in a serverless variant, but is not selected for this placement. T1578 describes infrastructure modification to evade defenses, not generic execution, and is selected only for the separate Defense Evasion placement. T1535 concerns geographic regions, not slots.

## Validation

The revised outcome passed matrix/tactic-page consistency, source coverage, active Enterprise 19.2 IDs, official tactic membership, JSON, and Navigator 4.5 emitted-field checks. These are scoped checks, not certification by MITRE.

This package preserves all mappings and technique annotations from the revised outcome while adding attribution and licensing notices and replacing private build references. Local export checks verify those invariants. This exact layer file was imported into Navigator 5.3.2 on 2026-09-11, with all 26 expected highlighted cells rendered. All technique/tactic pairs, score values, and full tooltip comment hashes matched the prepared file; merged source placements and the custom Development slots Execution metadata were retained. Contributor attribution and licensing notices were inspected in layer settings. The browser selected the ATT&CK 19 release family; exact 19.2 mapping validation used the pinned STIX bundle. Browser-validated layer SHA256: D456F2AD031E21EC815D13E064CBFF3E286F8067C993ED6CBBD0235B79180D04. The private build tools and validation logs are not included.

Original contribution license: CC BY 4.0. Original mapping contributor: [jaekk0](https://github.com/jaekk0). Third-party material retains its applicable terms. See [LICENSE](LICENSE) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for attribution, modification notices, and the reproduced MITRE license. This is an independent project, not affiliated with or endorsed by Microsoft or MITRE.

Microsoft IDs are provenance only. ATT&CK 19 replaces the former Defense Evasion taxonomy with Stealth and Defense Impairment; the source logging reference T1562.008 is revoked and migrated to T1685.002 via the official revoked-by relationship.

## Sources

- https://microsoft.github.io/Threat-Matrix-for-Cloud-Web-Applications/
- https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/
- https://attack.mitre.org/matrices/enterprise/
- https://mitre-attack.github.io/attack-navigator/
- https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
