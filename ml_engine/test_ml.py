import os
import sys

# Ensure ml_engine directory is in Python path for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from train_model import train_and_save_model
from inference import detect_anomaly
from ai_reporter import generate_threat_report

def run_tests():
    print("=" * 60)
    print("🧪 Running ML Engine & Interface Contract Tests")
    print("=" * 60)

    # 1. Test Anomaly Detection Engine (detect_anomaly)
    print("\n1️⃣ Testing Anomaly Detection Function Signature & Logic...")
    
    # Test Normal Case
    normal_payload = "username=john_doe&action=view_profile"
    normal_rate = 12
    normal_result = detect_anomaly(normal_payload, normal_rate)
    print(f"Normal Request Output: {normal_result} (Type: {type(normal_result).__name__})")
    assert isinstance(normal_result, bool), "detect_anomaly must return a boolean!"
    assert normal_result is False, "Normal payload must return False!"

    # Test Clean Login Case
    clean_login = "username=admin&password=secret123"
    clean_result = detect_anomaly(clean_login, 5)
    print(f"Clean Login Request Output: {clean_result} (Type: {type(clean_result).__name__})")
    assert clean_result is False, "Clean login payload must return False!"


    # Test SQLi Case
    sqli_payload = "username=' OR '1'='1'-- &password=admin"
    sqli_rate = 15
    sqli_result = detect_anomaly(sqli_payload, sqli_rate)
    print(f"SQLi Request Output: {sqli_result} (Type: {type(sqli_result).__name__})")
    assert isinstance(sqli_result, bool), "detect_anomaly must return a boolean!"
    assert sqli_result is True, "SQLi payload should return True!"

    # Test DDoS Rate Spike
    ddos_payload = "ping=true"
    ddos_rate = 250
    ddos_result = detect_anomaly(ddos_payload, ddos_rate)
    print(f"DDoS Spike Output: {ddos_result} (Type: {type(ddos_result).__name__})")
    assert isinstance(ddos_result, bool), "detect_anomaly must return a boolean!"
    assert ddos_result is True, "High request rate should return True!"

    # 2. Test AI Security Incident Reporter (generate_threat_report)
    print("\n2️⃣ Testing AI Threat Reporter Function Signature & Logic...")
    ip = "192.168.1.150"
    attack_type = "SQL_INJECTION"
    raw_payload = sqli_payload

    report = generate_threat_report(ip, attack_type, raw_payload)
    print(f"Report Output:\n\"{report}\"\n(Type: {type(report).__name__})")
    assert isinstance(report, str), "generate_threat_report must return a string!"
    assert len(report) > 0, "Report output must not be empty!"

    print("\n" + "=" * 60)
    print("🎉 ALL ML ENGINE INTERFACE CONTRACT TESTS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
