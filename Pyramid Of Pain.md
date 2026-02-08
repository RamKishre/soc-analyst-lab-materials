# Pyramid of Pain – Defensive Security Analysis

> The Pyramid of Pain is a defensive security framework that explains how different types of indicators affect an attacker’s ability to continue an operation.
> Lower-level indicators are easier for attackers to change while higher-level indicators cause significant disruption and force attackers to modify their tools, techniques and behavior.

# Pyramid of Pain – Level 1 :

 * Indicator Level: Hash Values
 * Pyramid Difficulty: Very Low
 * Indicator Color: Green
   
 * Why it is weak: Hash-based indicators are weak because attackers can easily change the hash of a malicious file by recompiling, 
   packing, or making minor modifications to the file. Even a small change in the file results in a completely different hash, 
   allowing the attacker to bypass hash-based detection.
   
 * Detection sources: Antivirus , Endpoint Detection and Response (EDR) , File integrity monitoring systems
 * Validation Source: VirusTotal , ANY.RUN , Malware sandboxes.
 * Common interview question:
   Q. Why is hash-based detection ineffective against new malware?
      Ans: Hash-based detection is signature-based and primarily useful for identifying known malware, not new or modified threats.


 # Pyramid of Pain – Level 2 :

* Indicator Level: IP Address
* Pyramid Difficulty: Low
* Indicator Color: Green
  
* Why it is weak: IP-based indicators are weak because attackers can easily rotate IP addresses using fast-flux techniques, proxies, 
  VPNs or botnets. Blocking a single IP address causes minimal disruption as attackers can quickly switch to new infrastructure,
  making IP-based detection short-lived and prone to false positives.
  
* Detection Sources: SIEM, Firewall logs, IDS/IPS, Network monitoring tools
* Validation Sources: ANY.RUN, VirusTotal, Threat intelligence platforms
* Common Interview Question:
  Q: Why are IP addresses considered weak indicators in the Pyramid of Pain?
     Ans: IP addresses are weak indicators because attackers can rapidly change or rotate them using fast-flux, proxies, or botnets,
          making IP-based detection easy to evade and short-lived.


# Pyramid of Pain – Level 3 :

* Indicator Level: Domain Name (DNS)
* Pyramid Difficulty: Low–Medium
* Indicator Color: Teal
  
* Why it is weak: Domain-based indicators are stronger than IPs but still relatively weak because attackers can register new domains quickly
  or abuse legitimate services such as URL shorteners and compromised domains. Techniques like domain generation algorithms (DGAs) and IDN homograph
  (punycode) attacks allow attackers to evade domain-based detection, making it short-lived.

* Detection Sources: SIEM (DNS logs, proxy logs, email gateway logs), Secure Web Gateway (SWG)
* Validation sources :VirusTotal, ANY.RUN, WHOIS, Passive DNS
* Common Interview Question:
  Q: Why are domain names considered stronger than IP addresses but still weak indicators in the Pyramid of Pain?
     Ans: Domain names require more effort to change than IPs, but attackers can still easily register new domains 
          or abuse URL shorteners and punycode attacks, making domain-based detection limited in long-term effectiveness.


# Pyramid of Pain – Level 4 :

* Indicator Level: Host / Network Artifacts
* Pyramid Difficulty: Medium
* Indicator Color: Yellow
  
* Why it is strong: At this level, detection focuses on attacker behavior and activity patterns rather than simple indicators.Host and network artifacts 
  include items such as unusual process execution, command-line arguments, user-agent strings,registry changes, or abnormal network traffic patterns.
  To evade detection at this level attackers must modify their tools, infrastructure usage or execution methods, which requires more time, effort and  
  resources, causing noticeable disruption to their operations.

* Detection Sources: SIEM, EDR, IDS/IPS, Firewall logs, DNS logs etc..
* Validation Sources: ANY.RUN, Sandboxes, EDR telemetry, Threat intelligence feeds, Process analysis tools
* Common Interview Question:
  Q: Why are host and network artifacts considered stronger indicators than IPs or domains in the Pyramid of Pain?
     Ans: Host and network artifacts are stronger indicators because they focus on attacker behavior and activity patterns, forcing attackers to modify tools
     or execution methods, which requires more effort and causes greater disruption.




# Pyramid of Pain – Level 5 :

* Indicator Level: Tools
* Pyramid Difficulty: High
* Indicator Color: Orange

* Why it is strong:
At this level, defenders focus on detecting the tools used by attackers rather than simple indicators. Tools include malware builders, backdoors, C2 frameworks,
malicious macro generators, password crackers, and custom executables or DLLs. If a SOC successfully detects tools, attackers must either heavily modify existing tools,
develop new ones, or acquire alternative tooling, which requires significant time, expertise, and financial resources. This causes major disruption to attacker operations
and often forces them to abandon or delay campaigns.

* Detection Sources: Antivirus signatures, EDR detection rules, YARA rules, SIEM correlations, endpoint telemetry

* Validation Sources: MalwareBazaar, MalShare, Sandboxes, Threat intelligence feeds, YARA repositories

* Common Interview Question:
  Q: Why does detecting attacker tools cause more pain than detecting IPs or domains?
     Ans: Detecting attacker tools forces adversaries to rebuild, replace, or significantly modify their tooling, which requires time, 
     resources, and expertise, making evasion costly and disruptive.



# Pyramid of Pain – Level 6 :

* Indicator Level: TTPs (Tactics, Techniques, and Procedures)
* Pyramid Difficulty: Very High
* Indicator Color: Red

* Why it is strong:
  TTP-based detection focuses on attacker behavior rather than specific indicators or tools. It identifies how an attacker operates across the entire attack lifecycle,
  such as lateral movement techniques,persistence mechanisms, privilege escalation methods, and command-and-control behaviors. To evade detection at this level, 
  attackers must fundamentally change how they conduct attacks, retrain operators, redesign playbooks, and adopt new operational strategies. This is extremely costly,
  time-consuming, and often impractical, making TTP-based detection the most effective and resilient form of defense.

* Detection Sources:
SIEM (behavioral correlation rules), EDR (behavioral analytics), UEBA, IDS/IPS, Endpoint telemetry, Network traffic analysis

* Validation Sources: MITRE ATT&CK framework, Threat intelligence reports, Incident response case studies, Threat hunting platforms

* Common Interview Question:
  Q: Why do TTP-based detections cause the most pain to attackers in the Pyramid of Pain?
     Ans: TTP-based detections target attacker behavior and operational patterns, forcing adversaries to change how they conduct attacks 
          rather than just modifying indicators or tools, which is costly and difficult to sustain.














