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
** Why it is weak: **IP-based indicators are weak because attackers can easily rotate IP addresses using fast-flux techniques, proxies, 
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














