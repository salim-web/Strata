import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("strata.gemini_analyst")

# MITRE ATT&CK reference mapping for the 6 threat classes
MITRE_MAPPINGS = {
    "VOLUMETRIC_DDOS": {
        "tactic": "Impact",
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "primary_vector": "High-velocity SYN flood / distributed bandwidth exhaustion"
    },
    "BOTNET_C2": {
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols Beaconing",
        "primary_vector": "Low-jitter periodic heartbeat to external C2 controller"
    },
    "DGA_DNS_TUNNEL": {
        "tactic": "Command and Control / Exfiltration",
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS Tunnelling / DGA",
        "primary_vector": "High-entropy domain name query strings & TXT payload encoding"
    },
    "ENCRYPTED_MALWARE": {
        "tactic": "Command and Control / Defense Evasion",
        "technique_id": "T1573.002",
        "technique_name": "Encrypted Channel: Asymmetric Cryptography (JA3/JA4 Fingerprint)",
        "primary_vector": "Malware-specific TLS ClientHello fingerprint without payload decryption"
    },
    "RECON_SCAN": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595.001",
        "technique_name": "Active Scanning: Scanning IP Blocks / Ports",
        "primary_vector": "Rapid fan-out cardinality across target subnets and service ports"
    },
    "DATA_EXFIL": {
        "tactic": "Exfiltration",
        "technique_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol: Asymmetric Upload",
        "primary_vector": "Abnormal directional byte asymmetry ratio (>8x outbound)"
    }
}


def _generate_deterministic_assessment(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    High-fidelity deterministic Cyber Threat Intelligence generator used when
    running in air-gapped environments or when GEMINI_API_KEY is not configured.
    Strictly derives all observations from passive metadata evidence.
    """
    threat_class = alert_data.get("threat_class", "VOLUMETRIC_DDOS")
    flow_id = alert_data.get("flow_id", "0.0.0.0:0->0.0.0.0:0:TCP")
    confidence = alert_data.get("confidence_score", 0.85)
    severity = alert_data.get("severity", "HIGH")
    evidence = alert_data.get("evidence", {})

    mitre = MITRE_MAPPINGS.get(threat_class, {
        "tactic": "Suspicious Activity",
        "technique_id": "T1000",
        "technique_name": "Unclassified Network Anomaly",
        "primary_vector": "Metadata deviation"
    })

    if threat_class == "VOLUMETRIC_DDOS":
        rate = evidence.get("flow_rate_rps", "elevated")
        syn_ack = evidence.get("syn_to_ack_ratio", "abnormal")
        entropy = evidence.get("src_ip_entropy", "high")
        hypothesis = (
            f"Passive optical tap observed high-velocity flow burst ({rate}) with heavily asymmetric "
            f"SYN/ACK ratio ({syn_ack}) and source IP Shannon entropy ({entropy}). This indicates a distributed "
            f"packet flood intended to saturate state tables or ingress pipeline capacity."
        )
        recommendations = [
            "Observe upstream BGP community signaling to divert volumetric transit to blackhole scrubbers.",
            "Monitor core border router interfaces for link saturation without altering diode read-only state.",
            "Log source IP distribution clusters for post-incident threat intelligence attribution."
        ]
    elif threat_class == "BOTNET_C2":
        periodicity = evidence.get("periodicity_score", "high")
        iat_var = evidence.get("iat_variance", "low")
        hypothesis = (
            f"Flow timing analysis revealed recurring inter-arrival times with {periodicity} periodicity "
            f"and ultra-low variance ({iat_var}). The pattern matches an automated botnet agent heartbeat "
            f"maintaining persistence with an external C2 node over standard port protocols."
        )
        recommendations = [
            "Cross-reference destination IP against passive global threat intelligence feeds and sinkholes.",
            "Isolate the internal host on the endpoint detection plane (EDR) out-of-band.",
            "Audit passive DNS logs for domain names associated with this destination IP."
        ]
    elif threat_class == "DGA_DNS_TUNNEL":
        char_entropy = evidence.get("query_char_entropy", "high")
        query = evidence.get("dns_query", "suspicious.domain")
        vowel_ratio = evidence.get("vowel_ratio", "skewed")
        hypothesis = (
            f"DNS telemetry captured query '{query}' exhibiting abnormal character entropy ({char_entropy}) "
            f"and anomalous vowel-to-consonant distribution ({vowel_ratio}). The pattern strongly aligns with "
            f"Domain Generation Algorithms (DGA) or TXT-encoded covert data tunneling."
        )
        recommendations = [
            "Monitor authoritative name server responses for NXDOMAIN burst cascades.",
            "Record subsequent query sequences to identify the DGA seed or tunneling protocol format.",
            "Update internal resolver sinkhole lists via out-of-band threat feed distribution."
        ]
    elif threat_class == "ENCRYPTED_MALWARE":
        ja3 = evidence.get("ja3_hash", "known_malware")
        matched = evidence.get("matched_threat", "Malware C2")
        hypothesis = (
            f"Passive TLS ClientHello metadata matches threat profile '{matched}' with signature JA3: {ja3}. "
            f"Analysis performed strictly on handshake metadata and cipher suites with zero payload decryption. "
            f"The connection represents an encrypted C2 or loader session."
        )
        recommendations = [
            "Inspect passive JA4 client/server fingerprint combinations for exact campaign tracking.",
            "Verify whether internal client certificate or process owner can be identified via endpoint telemetry.",
            "Retain initial packet size arrays for behavioral malware family classification."
        ]
    elif threat_class == "RECON_SCAN":
        fanout = evidence.get("fanout_cardinality", "high")
        scan_type = evidence.get("scan_type", "Port Sweep")
        hypothesis = (
            f"Rolling 10-second window detected fan-out cardinality of {fanout} originating from the source host. "
            f"The observed traffic profile represents {scan_type}, typically executed during pre-exploitation "
            f"enumeration to discover vulnerable service listeners."
        )
        recommendations = [
            "Track scan trajectory across internal subnets to determine boundary exposure.",
            "Correlate source IP with authenticated VPN or DHCP leases to identify origin host.",
            "Ensure edge honeynets passively record probe payloads for threat actor fingerprinting."
        ]
    elif threat_class == "DATA_EXFIL":
        byte_ratio = evidence.get("byte_asymmetry_ratio", "extreme")
        outbound = evidence.get("outbound_bytes", "large")
        hypothesis = (
            f"Flow exhibits extreme directional asymmetry with outbound-to-inbound ratio of {byte_ratio} "
            f"and total transfer of {outbound}. In standard client browsing, inbound downloads exceed uploads; "
            f"this reverse pattern strongly indicates unauthorized bulk data exfiltration."
        )
        recommendations = [
            "Verify internal host data classification and sensitive repository access permissions.",
            "Audit NetFlow archives for historical transfer baselines between these endpoints.",
            "Notify security operations to inspect host-level DLP logs out-of-band."
        ]
    else:
        hypothesis = f"Anomalous passive metadata vector flagged with confidence {confidence}."
        recommendations = ["Continue passive monitoring and correlate with SIEM alerts."]

    return {
        "model_used": "Air-Gapped Enclave Intelligence Engine (Deterministic)",
        "threat_classification": threat_class,
        "flow_id": flow_id,
        "severity": severity,
        "confidence_score": confidence,
        "mitre_attack_mapping": mitre,
        "threat_hypothesis": hypothesis,
        "passive_evidence_analysis": (
            f"Evidence extracted non-intrusively via unidirectional diode tap: "
            + ", ".join(f"{k} = {v}" for k, v in evidence.items())
        ),
        "observation_summary": (
            f"Enclave detected {severity} severity {threat_class} on flow {flow_id}. "
            f"Zero return-path packets were generated in accordance with passive diode security constraints."
        ),
        "passive_monitoring_recommendations": recommendations
    }


async def generate_threat_intelligence_assessment(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an intelligence assessment using Google Gemini (via google-genai)
    with seamless fallback to deterministic local analysis if GEMINI_API_KEY is not set.
    """
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass

    gemini_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_key:
        try:
            from backend.config import settings
            gemini_key = getattr(settings, "GEMINI_API_KEY", None)
        except Exception:
            pass

    if not gemini_key:
        logger.info("GEMINI_API_KEY not set in environment or .env. Using air-gapped deterministic intelligence engine.")
        return _generate_deterministic_assessment(alert_data)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=gemini_key)

        prompt = f"""
You are an expert Cyber Threat Intelligence Analyst monitoring a unidirectional air-gapped data diode enclave.
You must analyze the following passive network metadata alert. Decryption of payloads is strictly forbidden;
your assessment must be grounded strictly in the passive evidence attributes provided.

Alert Metadata:
- Flow ID: {alert_data.get('flow_id')}
- Threat Class: {alert_data.get('threat_class')}
- Confidence: {alert_data.get('confidence_score')}
- Severity: {alert_data.get('severity')}
- Passive Evidence Metrics: {json.dumps(alert_data.get('evidence', {}), indent=2)}

Respond with a JSON object with these exact keys:
{{
  "threat_classification": "{alert_data.get('threat_class')}",
  "mitre_attack_mapping": {{
    "tactic": "<MITRE Tactic Name>",
    "technique_id": "<e.g. T1071.001>",
    "technique_name": "<Technique Name>"
  }},
  "threat_hypothesis": "<2-3 sentences explaining what the threat actor is attempting based on the passive evidence>",
  "passive_evidence_analysis": "<Detailed breakdown explaining why the evidence values deviate from normal baselines>",
  "observation_summary": "<Executive summary for SOC analysts>",
  "passive_monitoring_recommendations": [
    "<Recommendation 1 (passive out-of-band monitoring or SIEM correlation, strictly NO firewall pushback)>",
    "<Recommendation 2>",
    "<Recommendation 3>"
  ]
}}
Only return the valid JSON object.
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2
            )
        )

        result_text = response.text
        parsed = json.loads(result_text)
        parsed["model_used"] = "Google Gemini 2.5 Flash"
        parsed["flow_id"] = alert_data.get("flow_id")
        parsed["severity"] = alert_data.get("severity")
        parsed["confidence_score"] = alert_data.get("confidence_score")
        return parsed

    except Exception as e:
        logger.warning(f"Error invoking Google Gemini API ({e}). Falling back to deterministic analyst engine.")
        fallback = _generate_deterministic_assessment(alert_data)
        fallback["model_used"] = f"Air-Gapped Fallback (Gemini Error: {type(e).__name__})"
        return fallback
