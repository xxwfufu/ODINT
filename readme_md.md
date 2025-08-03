# xxwfufu OSINT Tool 🔍

**Créateur**: xxwfufu  
**Version**: 1.0  
**Compatibilité**: Windows 10/11  

Un outil complet d'Open Source Intelligence (OSINT) développé en Python pour rechercher des informations approfondies sur des personnes, domaines, adresses IP et plus encore.

## 📋 Fonctionnalités

### ✅ Fonctionnalités principales
- ✅ **Recherche par nom complet** - Trouve des profils sur les réseaux sociaux et annuaires
- ✅ **Recherche par pseudo/username** - Vérifie la présence sur 15+ plateformes
- ✅ **Analyse d'adresse e-mail** - Vérification de fuites, analyse du domaine, MX records
- ✅ **Analyse de numéro de téléphone** - Géolocalisation, opérateur, type de ligne
- ✅ **Analyse d'adresse IP** - Géolocalisation, WHOIS, scan de ports
- ✅ **Analyse d'image** - Extraction EXIF, hash MD5
- ✅ **Recherche WHOIS et DNS** - Informations complètes sur les domaines
- ✅ **Google Dorking automatisé** - 9 types de recherches prédéfinies
- ✅ **Recherche réseaux sociaux** - Détection automatique de profils
- ✅ **Analyse de domaine complète** - WHOIS + DNS + sous-domaines
- ✅ **Générateur de rapport** - Export JSON complet

### 🎯 Plateformes supportées
- GitHub, Twitter, Instagram, Reddit, YouTube
- TikTok, LinkedIn, Facebook, Twitch, Discord
- Telegram, Steam, Spotify, Pinterest, Snapchat

## 🚀 Installation rapide

### Méthode 1: Installation automatique (recommandée)
1. Téléchargez tous les fichiers dans un dossier
2. Double-cliquez sur `install_dependencies.bat`
3. Attendez la fin de l'installation
4. Double-cliquez sur `run_xxwfufu.bat` pour lancer l'outil

### Méthode 2: Installation manuelle
```bash
# Cloner ou télécharger les fichiers
# Installer Python 3.8+ depuis https://python.org

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'outil
python xxwfufu_osint.py
```

## 📁 Structure des fichiers

```
xxwfufu-osint/
├── xxwfufu_osint.py          # Script principal
├── install_dependencies.bat   # Installation automatique (Windows)
├── run_xxwfufu.bat           # Lanceur rapide (Windows)
├── requirements.txt           # Liste des dépendances
└── README.md                 # Cette documentation
```

## 💻 Utilisation

### Mode interactif (recommandé)
```bash
python xxwfufu_osint.py
```
Suivez le menu interactif pour choisir votre type de recherche.

### Mode ligne de commande
```bash
# Analyser un e-mail
python xxwfufu_osint.py --target user@example.com --mode email

# Analyser une IP
python xxwfufu_osint.py --target 8.8.8.8 --mode ip

# Rechercher un username
python xxwfufu_osint.py --target johndoe --mode username

# Analyser un domaine
python xxwfufu_osint.py --target example.com --mode domain

# Analyser un téléphone
python xxwfufu_osint.py --target "+33123456789" --mode phone
```

## 🔧 Configuration

### APIs optionnelles
Pour des fonctionnalités avancées, vous pouvez configurer:

1. **Shodan API** (scan de ports avancé)
   - Obtenez une clé sur https://shodan.io
   - Modifiez la ligne `self.shodan_api = None` dans le code

2. **HaveIBeenPwned API** (vérification de fuites)
   - Nécessite une clé API payante pour l'usage automatisé

## 📊 Exemple de sortie

```
[+] Analyse de l'e-mail: test@example.com
[+] Vérification des fuites de données...
[+] Analyse du domaine example.com...
[+] Domaine analysé avec succès
[+] 2 enregistrements MX trouvés

[+] Recherche du username: johndoe
[+] Vérification sur 15 plateformes...
[+] Trouvé sur GitHub: https://github.com/johndoe
[+] Trouvé sur Twitter: https://twitter.com/johndoe
[+] Username trouvé sur 2 plateformes
```

## 🛡️ Utilisation éthique

⚠️ **IMPORTANT**: Cet outil est destiné à des fins éducatives et de test de sécurité uniquement.

### ✅ Utilisations légales
- Tests de sécurité sur vos propres systèmes
- Recherches académiques et éducatives
- Vérification de votre propre empreinte numérique
- Investigations légitimes avec autorisation

### ❌ Utilisations interdites
- Harcèlement ou stalking
- Violations de vie privée
- Activités illégales
- Utilisation sans consentement

## 🔍 Fonctionnalités détaillées

### 1. Recherche par nom
- Recherche sur LinkedIn, Facebook, Twitter
- Vérification dans les annuaires publics
- Cross-référencement des informations

### 2. Analyse d'e-mail
- Validation du format
- Vérification des fuites de données
- Analyse WHOIS du domaine
- Enregistrements MX et DNS

### 3. Analyse de téléphone
- Validation internationale
- Géolocalisation par préfixe
- Identification de l'opérateur
- Type de ligne (mobile/fixe)

### 4. Analyse d'IP
- Géolocalisation précise
- Informations ISP/ASN
- Scan de ports communs
- Données WHOIS

### 5. Google Dorking
- Recherche