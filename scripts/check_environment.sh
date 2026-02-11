#!/bin/bash
# Vérification complète environnement ZK-VPN

echo "🔍 VÉRIFICATION ENVIRONNEMENT ZK-VPN"
echo "========================================"

# Fonction de logging
log() {
    echo "[$(date +'%H:%M:%S')] $1"
}

# Variables
ERRORS=0
WARNINGS=0
PROJECT_ROOT="$HOME/projects/ZK-VPN"

# 1. Vérifier structure
log "1. 📁 Vérification structure..."
required_dirs=("agents" "prototype" "prototype/src" "prototype/tests")
for dir in "${required_dirs[@]}"; do
    if [ -d "$PROJECT_ROOT/$dir" ]; then
        echo "   ✅ $dir"
    else
        echo "   ❌ $dir manquant"
        ((ERRORS++))
    fi
done

# 2. Vérifier Python
log "2. 🐍 Vérification Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo "   ✅ Python $PYTHON_VERSION"
    
    # Vérifier venv
    if [ -d "$PROJECT_ROOT/.venv" ]; then
        echo "   ✅ Environnement virtuel présent"
    else
        echo "   ⚠️  Pas d'environnement virtuel (exécuter: python -m venv .venv)"
        ((WARNINGS++))
    fi
else
    echo "   ❌ Python3 non installé"
    ((ERRORS++))
fi

# 3. Vérifier Git
log "3. 📦 Vérification Git..."
if command -v git &> /dev/null; then
    echo "   ✅ Git $(git --version | awk '{print $3}')"
    
    # Vérifier configuration
    GIT_USER=$(git config --global user.name)
    GIT_EMAIL=$(git config --global user.email)
    
    if [ -n "$GIT_USER" ] && [ -n "$GIT_EMAIL" ]; then
        echo "   ✅ Git config: $GIT_USER <$GIT_EMAIL>"
    else
        echo "   ⚠️  Git non configuré (git config --global user.name 'Votre Nom')"
        ((WARNINGS++))
    fi
else
    echo "   ❌ Git non installé"
    ((ERRORS++))
fi

# 4. Vérifier WireGuard
log "4. 🛡️ Vérification WireGuard..."
if command -v wg &> /dev/null; then
    echo "   ✅ WireGuard $(wg --version | awk '{print $2}')"
else
    echo "   ⚠️  WireGuard non installé (sudo apt install wireguard)"
    ((WARNINGS++))
fi

# 5. Vérifier GitHub
log "5. 🐙 Vérification GitHub..."
cd "$PROJECT_ROOT"
if git remote -v | grep -q "github.com/MissCyber9/ZK-VPN"; then
    echo "   ✅ Remote GitHub configuré"
    
    # Tester la connexion
    if git ls-remote --exit-code origin &> /dev/null; then
        echo "   ✅ Connexion GitHub OK"
    else
        echo "   ⚠️  Impossible de contacter GitHub (vérifier SSH/HTTPS)"
        ((WARNINGS++))
    fi
else
    echo "   ❌ Remote GitHub non configuré"
    ((ERRORS++))
fi

# 6. Vérifier les agents
log "6. 🤖 Vérification agents..."
AGENTS=("orchestrator.py" "cryptographer_agent.py" "network_agent.py" 
        "contracts_agent.py" "security_agent.py" "documentation_agent.py")

for agent in "${AGENTS[@]}"; do
    if [ -f "$PROJECT_ROOT/agents/$agent" ]; then
        echo "   ✅ $agent"
    else
        echo "   ❌ $agent manquant"
        ((ERRORS++))
    fi
done

# 7. Vérifier les dépendances
log "7. 📦 Vérification dépendances..."
if [ -f "$PROJECT_ROOT/prototype/requirements.txt" ]; then
    echo "   ✅ requirements.txt présent"
    
    # Compter les dépendances
    DEPS_COUNT=$(wc -l < "$PROJECT_ROOT/prototype/requirements.txt")
    echo "   📊 $DEPS_COUNT dépendances listées"
else
    echo "   ❌ requirements.txt manquant"
    ((ERRORS++))
fi

# Résumé
echo ""
echo "========================================"
echo "📊 RÉSUMÉ DE VÉRIFICATION"
echo "----------------------------------------"
echo "✅ Succès : $((${#required_dirs[@]} + 6 - ERRORS - WARNINGS))"
echo "⚠️  Avertissements : $WARNINGS"
echo "❌ Erreurs : $ERRORS"
echo "----------------------------------------"

if [ $ERRORS -eq 0 ]; then
    if [ $WARNINGS -eq 0 ]; then
        echo "🎉 ENVIRONNEMENT PRÊT POUR LE DÉVELOPPEMENT !"
        echo ""
        echo "Prochaines étapes :"
        echo "1. Activer l'environnement : source .venv/bin/activate"
        echo "2. Lancer les agents : ./agents/start_agents.sh"
        echo "3. Suivre la traçabilité : cat TRACABILITY.md"
    else
        echo "⚠️  ENVIRONNEMENT PRESQUE PRÊT - $WARNINGS avertissement(s)"
        echo ""
        echo "Recommandations :"
        [ $WARNINGS -gt 0 ] && echo "- Installer WireGuard : sudo apt install wireguard"
        [ ! -d ".venv" ] && echo "- Créer venv : python -m venv .venv"
    fi
else
    echo "❌ ENVIRONNEMENT INCOMPLET - $ERRORS erreur(s) à corriger"
    exit 1
fi

echo "========================================"
