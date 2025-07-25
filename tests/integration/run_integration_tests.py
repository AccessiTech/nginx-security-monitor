#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration Test Runner for NGINX Security Monitor

Executes all integration tests in a structured manner according to the phases
defined in the integration test plan.
"""

import unittest
import os
import sys
import time
import argparse
from datetime import datetime


def run_test_phase(phase_name, test_modules, verbosity=2):
    """Run a specific phase of integration tests."""
    print(f"\n{'='*80}")
    print(f"🚀 Running Integration Test Phase: {phase_name}")
    print(f"{'='*80}")
    
    start_time = time.time()
    results = []
    
    for module_name in test_modules:
        print(f"\n{'-'*80}")
        print(f"📋 Running test module: {module_name}")
        print(f"{'-'*80}")
        
        test_module = __import__(module_name, fromlist=['*'])
        
        # Create a test suite from the module
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(test_module)
        
        # Run the tests
        result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
        results.append((module_name, result))
        
        print(f"{'-'*80}")
        print(f"✅ Completed test module: {module_name}")
        print(f"📊 Results: {result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors")
    
    # Calculate and display summary for this phase
    total_tests = sum(result.testsRun for _, result in results)
    total_failures = sum(len(result.failures) for _, result in results)
    total_errors = sum(len(result.errors) for _, result in results)
    
    elapsed = time.time() - start_time
    
    print(f"\n{'='*80}")
    print(f"📊 Phase Summary: {phase_name}")
    print(f"{'='*80}")
    print(f"⏱️  Duration: {elapsed:.2f} seconds")
    print(f"🔢 Total Tests: {total_tests}")
    print(f"❌ Failures: {total_failures}")
    print(f"⚠️  Errors: {total_errors}")
    
    return results


def generate_report(all_results):
    """Generate a comprehensive test report."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"integration_test_report_{timestamp}.txt"
    
    with open(report_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("NGINX Security Monitor - Integration Test Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*80 + "\n\n")
        
        # Overall summary
        total_phases = len(all_results)
        total_modules = sum(len(phase_results) for phase_results in all_results.values())
        total_tests = sum(sum(result.testsRun for _, result in phase_results) 
                        for phase_results in all_results.values())
        total_failures = sum(sum(len(result.failures) for _, result in phase_results) 
                           for phase_results in all_results.values())
        total_errors = sum(sum(len(result.errors) for _, result in phase_results) 
                         for phase_results in all_results.values())
        
        f.write("📊 Overall Summary\n")
        f.write("-"*80 + "\n")
        f.write(f"Phases: {total_phases}\n")
        f.write(f"Test Modules: {total_modules}\n")
        f.write(f"Total Tests: {total_tests}\n")
        f.write(f"Failures: {total_failures}\n")
        f.write(f"Errors: {total_errors}\n")
        
        # Avoid division by zero
        if total_tests > 0:
            success_rate = ((total_tests - total_failures - total_errors) / total_tests * 100)
            f.write(f"Success Rate: {success_rate:.2f}%\n\n")
        else:
            f.write("Success Rate: N/A (no tests run)\n\n")
        
        # Phase-by-phase details
        for phase_name, phase_results in all_results.items():
            f.write(f"Phase: {phase_name}\n")
            f.write("-"*80 + "\n")
            
            for module_name, result in phase_results:
                f.write(f"Module: {module_name}\n")
                f.write(f"Tests: {result.testsRun}\n")
                f.write(f"Failures: {len(result.failures)}\n")
                f.write(f"Errors: {len(result.errors)}\n")
                
                # Detailed failure information
                if result.failures:
                    f.write("\nFailures:\n")
                    for i, (test, traceback) in enumerate(result.failures, 1):
                        f.write(f"  {i}. {test}\n")
                        f.write(f"     {traceback.split('Traceback')[0].strip()}\n")
                
                # Detailed error information
                if result.errors:
                    f.write("\nErrors:\n")
                    for i, (test, traceback) in enumerate(result.errors, 1):
                        f.write(f"  {i}. {test}\n")
                        f.write(f"     {traceback.split('Traceback')[0].strip()}\n")
                
                f.write("\n")
            
            f.write("\n")
    
    print(f"\n📝 Detailed report saved to: {report_file}")
    return report_file


def main():
    """Main function to run all integration tests."""
    parser = argparse.ArgumentParser(description='Run NGINX Security Monitor Integration Tests')
    parser.add_argument('--phase', type=str, help='Run only a specific phase (phase1, phase2, phase3)')
    parser.add_argument('--verbose', '-v', action='count', default=2, help='Increase verbosity')
    args = parser.parse_args()
    
    # Define test phases and their modules
    test_phases = {
        "phase1": {
            "name": "Phase 1: Core Component Integration",
            "modules": [
                "tests.integration.test_phase1_core",
                "tests.integration.test_phase1_config",
                "tests.integration.test_phase1_alerts"
            ]
        },
        "phase2": {
            "name": "Phase 2: Security Response Integration",
            "modules": [
                "tests.integration.test_phase2_threat_response",
                "tests.integration.test_phase2_security_integrations",
                "tests.integration.test_phase2_service_protection"
            ]
        },
        "phase3": {
            "name": "Phase 3: Advanced Integration Scenarios",
            "modules": [
                "tests.integration.test_phase3_plugin_system",
                "tests.integration.test_phase3_network_security",
                "tests.integration.test_phase3_crypto"
            ]
        }
    }
    
    print("\n🧪 NGINX Security Monitor - Integration Test Suite")
    print(f"🕒 Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    overall_start = time.time()
    all_results = {}
    
    if args.phase:
        # Run only the specified phase
        if args.phase in test_phases:
            phase_info = test_phases[args.phase]
            results = run_test_phase(phase_info["name"], phase_info["modules"], args.verbose)
            all_results[args.phase] = results
        else:
            print(f"❌ Unknown phase: {args.phase}")
            print(f"Available phases: {', '.join(test_phases.keys())}")
            return 1
    else:
        # Run all phases in order
        for phase_id, phase_info in test_phases.items():
            results = run_test_phase(phase_info["name"], phase_info["modules"], args.verbose)
            all_results[phase_id] = results
    
    overall_elapsed = time.time() - overall_start
    
    print("\n" + "="*80)
    print("📊 Integration Test Execution Complete")
    print("="*80)
    print(f"⏱️  Total Duration: {overall_elapsed:.2f} seconds")
    
    # Generate detailed report
    report_file = generate_report(all_results)
    
    # Return non-zero exit code if any tests failed
    total_failures = sum(sum(len(result.failures) + len(result.errors) for _, result in phase_results) 
                       for phase_results in all_results.values())
    
    return 1 if total_failures > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
