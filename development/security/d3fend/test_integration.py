#!/usr/bin/env python3
"""
D3FEND Integration Test Suite
Quick validation of D3FEND integration functionality
"""

import asyncio
from datetime import datetime


def test_technique_mapping():
    """Test 1: Verify technique mapping works"""
    print("\n" + "="*70)
    print("TEST 1: D3FEND Technique Mapping")
    print("="*70)

    from technique_mapping import TechniqueMapper

    mapper = TechniqueMapper()

    # Test component mapping
    mapping = mapper.get_techniques_for_component("webhook_monitoring.py")
    assert mapping is not None, "[FAIL] Webhook monitoring mapping not found!"
    print(f"[OK] Webhook Monitoring mapped to {len(mapping.d3fend_techniques)} techniques")
    print(f"   Techniques: {', '.join(mapping.technique_ids)}")

    # Test coverage report
    report = mapper.generate_coverage_report()
    assert report['techniques_implemented'] > 0, "[FAIL] No techniques implemented!"
    print(f"[OK] Coverage: {report['coverage_percentage']:.1f}%")
    print(f"   Implemented: {report['techniques_implemented']}/{report['total_techniques_available']}")

    # Test recommendations
    recommendations = mapper.recommend_next_techniques(limit=3)
    print(f"[OK] Generated {len(recommendations)} recommendations")

    return True


def test_ontology_export():
    """Test 2: Verify ontology export works"""
    print("\n" + "="*70)
    print("TEST 2: Ontology Export (JSON-LD, RDF, Turtle)")
    print("="*70)

    from ontology_export import D3FENDOntologyExporter

    exporter = D3FENDOntologyExporter()

    # Create test event
    test_event = {
        "event_id": "test_123",
        "timestamp": datetime.now().timestamp(),
        "event_type": "test.webhook.event",
        "endpoint": "https://test.example.com/webhook",
        "duration": 0.123,
        "status": "success"
    }

    # Test JSON-LD export
    jsonld = exporter.export_webhook_event_jsonld(test_event)
    assert "@context" in jsonld, "[FAIL] JSON-LD missing @context!"
    assert "@type" in jsonld, "[FAIL] JSON-LD missing @type!"
    print("[OK] JSON-LD export successful")
    print(f"   Types: {jsonld['@type']}")
    print(f"   Techniques: {len(jsonld.get('d3f:defendsTechnique', []))} D3FEND techniques")

    # Test RDF/XML export
    rdf_xml = exporter.export_to_rdf_xml(jsonld)
    assert 'rdf:RDF' in rdf_xml, "[FAIL] RDF/XML export failed!"
    print(f"[OK] RDF/XML export successful ({len(rdf_xml)} bytes)")

    # Test Turtle export
    turtle = exporter.export_to_turtle(jsonld)
    assert '@prefix d3f:' in turtle, "[FAIL] Turtle export failed!"
    print(f"[OK] Turtle export successful ({len(turtle)} bytes)")

    return True


def test_compliance_mapping():
    """Test 3: Verify compliance mapping works"""
    print("\n" + "="*70)
    print("TEST 3: Compliance Control Mapping")
    print("="*70)

    from compliance_d3fend_mapping import ComplianceD3FENDMapper

    mapper = ComplianceD3FENDMapper()

    # Test SOC2 mapping
    soc2_mapping = mapper.get_d3fend_for_control("SOC2", "CC6.7")
    assert soc2_mapping is not None, "[FAIL] SOC2 CC6.7 mapping not found!"
    print("[OK] SOC2 CC6.7 (Encryption)")
    print(f"   D3FEND Techniques: {[t.value for t in soc2_mapping.d3fend_techniques]}")

    # Test ISO27001 mapping
    iso_mapping = mapper.get_d3fend_for_control("ISO27001", "A.9.1.2")
    assert iso_mapping is not None, "[FAIL] ISO27001 A.9.1.2 mapping not found!"
    print("[OK] ISO27001 A.9.1.2 (Network Access)")
    print(f"   D3FEND Techniques: {[t.value for t in iso_mapping.d3fend_techniques]}")

    # Test NIST mapping
    nist_mapping = mapper.get_d3fend_for_control("NIST", "SI-4")
    assert nist_mapping is not None, "[FAIL] NIST SI-4 mapping not found!"
    print("[OK] NIST SI-4 (System Monitoring)")
    print(f"   D3FEND Techniques: {[t.value for t in nist_mapping.d3fend_techniques]}")

    # Test coverage
    soc2_coverage = mapper.get_framework_coverage("SOC2")
    print("[OK] SOC2 Framework Coverage:")
    print(f"   Controls: {soc2_coverage['total_controls']}")
    print(f"   D3FEND Techniques: {soc2_coverage['d3fend_techniques_covered']}")

    return True


async def test_api_client():
    """Test 4: Verify API client works (with offline fallback)"""
    print("\n" + "="*70)
    print("TEST 4: D3FEND API Client (Offline Fallback)")
    print("="*70)

    from api_client import D3FENDAPIClient, D3FENDOfflineData

    client = D3FENDAPIClient()

    # Test offline data (always works)
    offline_data = D3FENDOfflineData.get_technique("D3-NTA")
    assert offline_data is not None, "[FAIL] Offline data not available!"
    print("[OK] Offline data available for D3-NTA")
    print(f"   Name: {offline_data['name']}")
    print(f"   Category: {offline_data['category']}")

    offline_data_iv = D3FENDOfflineData.get_technique("D3-IV")
    assert offline_data_iv is not None, "[FAIL] Offline data for D3-IV not available!"
    print("[OK] Offline data available for D3-IV")
    print(f"   Name: {offline_data_iv['name']}")

    # Test API client (may fail if no network, but shouldn't crash)
    try:
        technique = await client.get_technique("D3-NTA")
        if technique:
            print("[OK] API client connected successfully")
            print(f"   Retrieved: {technique.name}")
        else:
            print("[WARN]  API unavailable (using offline fallback)")
    except Exception as e:
        print(f"[WARN]  API error (expected): {type(e).__name__}")
        print("   Offline fallback will be used in production")

    return True


def test_technique_coverage():
    """Test 5: Verify technique coverage meets minimum"""
    print("\n" + "="*70)
    print("TEST 5: D3FEND Coverage Requirements")
    print("="*70)

    from technique_mapping import TechniqueMapper

    mapper = TechniqueMapper()
    coverage = mapper.get_category_coverage()

    # Check each category
    for category, cov in coverage.items():
        status = "[OK]" if cov >= 80 else "[WARN]" if cov >= 50 else "[FAIL]"
        print(f"{status} {category.value.upper()}: {cov:.1f}%")

    # Check minimum overall coverage
    report = mapper.generate_coverage_report()
    overall = report['coverage_percentage']

    if overall >= 60:
        print(f"\n[OK] Overall Coverage: {overall:.1f}% (PASS - Target: 60%)")
    else:
        print(f"\n[FAIL] Overall Coverage: {overall:.1f}% (FAIL - Target: 60%)")

    # Check implemented categories
    implemented_categories = [cat for cat, cov in coverage.items() if cov > 0]
    print(f"[OK] Categories Implemented: {len(implemented_categories)}/7")

    missing_categories = mapper.get_missing_categories()
    if missing_categories:
        print(f"[WARN]  Missing Categories: {', '.join([c.value for c in missing_categories])}")

    return overall >= 60


def test_export_formats():
    """Test 6: Verify all export formats work"""
    print("\n" + "="*70)
    print("TEST 6: Export Format Validation")
    print("="*70)

    from ontology_export import D3FENDOntologyExporter

    exporter = D3FENDOntologyExporter()

    test_event = {
        "event_id": "format_test",
        "timestamp": 1234567890.0,
        "event_type": "format.test",
        "endpoint": "https://test.com",
        "duration": 0.1,
        "status": "success"
    }

    jsonld = exporter.export_webhook_event_jsonld(test_event)

    # Validate JSON-LD structure
    required_keys = ["@context", "@id", "@type", "d3f:defendsTechnique"]
    for key in required_keys:
        assert key in jsonld, f"[FAIL] JSON-LD missing required key: {key}"
    print("[OK] JSON-LD structure valid (all required keys present)")

    # Validate RDF/XML
    rdf = exporter.export_to_rdf_xml(jsonld)
    assert '<?xml version' in rdf, "[FAIL] RDF/XML missing XML declaration"
    assert 'rdf:RDF' in rdf, "[FAIL] RDF/XML missing RDF root"
    assert 'd3f:defendsTechnique' in rdf, "[FAIL] RDF/XML missing D3FEND technique"
    print("[OK] RDF/XML structure valid")

    # Validate Turtle
    turtle = exporter.export_to_turtle(jsonld)
    assert '@prefix d3f:' in turtle, "[FAIL] Turtle missing d3f prefix"
    assert '@prefix rdf:' in turtle, "[FAIL] Turtle missing rdf prefix"
    assert 'd3f:defendsTechnique' in turtle, "[FAIL] Turtle missing D3FEND technique"
    print("[OK] Turtle structure valid")

    return True


async def run_all_tests():
    """Run all integration tests"""
    print("\n" + "="*70)
    print("D3FEND INTEGRATION TEST SUITE")
    print("="*70)

    tests = [
        ("Technique Mapping", test_technique_mapping),
        ("Ontology Export", test_ontology_export),
        ("Compliance Mapping", test_compliance_mapping),
        ("API Client", test_api_client),
        ("Coverage Requirements", test_technique_coverage),
        ("Export Formats", test_export_formats),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            results.append((test_name, result, None))
        except Exception as e:
            results.append((test_name, False, str(e)))
            print(f"\n[FAIL] {test_name} FAILED: {e}")

    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    passed = sum(1 for _, result, _ in results if result)
    total = len(results)

    for test_name, result, error in results:
        status = "[OK] PASS" if result else "[FAIL] FAIL"
        print(f"{status}: {test_name}")
        if error:
            print(f"       Error: {error}")

    print("\n" + "="*70)
    print(f"TOTAL: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("="*70)

    if passed == total:
        print("\n[SUCCESS] ALL TESTS PASSED! D3FEND integration is working correctly.")
        print("\nNext steps:")
        print("1. Review: development/security/d3fend/README.md")
        print("2. Integrate: Follow development/security/d3fend/INTEGRATION_GUIDE.md")
        print("3. Deploy: Run the 15-minute quick start")
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed. Please review errors above.")

    return passed == total


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    exit(0 if success else 1)
