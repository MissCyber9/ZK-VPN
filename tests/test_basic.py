"""
Tests de base pour ZK-VPN
"""

import sys
import os

# Ajouter le package au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))

def test_import_package():
    """Test l'importation du package"""
    try:
        import zkvpn
        assert hasattr(zkvpn, '__version__')
        assert zkvpn.__version__ == "0.1.0"
        return True
    except ImportError:
        return False

def test_circuits_module():
    """Test le module circuits"""
    try:
        from zkvpn.circuits import no_logging
        circuit = no_logging.NoLoggingCircuit()
        assert circuit.circuit_id == "no_logging_v1"
        return True
    except ImportError:
        return False

def test_cli_structure():
    """Test la structure CLI"""
    try:
        from zkvpn.cli import main
        assert hasattr(main, 'cli')
        return True
    except ImportError:
        return False

def run_all_tests():
    """Exécute tous les tests et affiche les résultats"""
    print("🧪 TESTS ZK-VPN v0.1.0")
    print("=" * 40)
    
    tests = [
        ("Import package", test_import_package),
        ("Module circuits", test_circuits_module),
        ("Structure CLI", test_cli_structure)
    ]
    
    passed = 0
    total = len(tests)
    
    for name, test_func in tests:
        try:
            if test_func():
                print(f"✅ {name}")
                passed += 1
            else:
                print(f"❌ {name}")
        except Exception as e:
            print(f"❌ {name} (erreur: {e})")
    
    print("=" * 40)
    print(f"Score: {passed}/{total} tests passés")
    
    return passed == total

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
