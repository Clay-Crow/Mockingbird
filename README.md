# Projet de Pentest Automatisé  Mockingbird 

## Description

Mockingbird est un outil complet conçu pour les Pentest automatique. Il offre des fonctionnalités pour la numérisation de réseaux, l'évaluation des vulnérabilités et l'énumération de divers services tels que FTP, SSH, SNMP, SMB et plus encore. L'outil intègre plusieurs utilitaires puissants pour automatiser le processus d'identification et de rapport des vulnérabilités de sécurité.

Mockingbird utilise divers outils comme `nmap`, `hydra`, `medusa`, `dirhunt`, `wafw00f`, `dnsrecon`, `sublist3r`, `testssl.sh`, `nikto`, `whatweb`, `amass`, `nuclei`, `wpscan`, `ffuf`, et `GVM (Greenbone Vulnerability Manager)`.

## Fonctionnalités

- **Scan de Réseau** : Utilise Nmap pour des analyses de réseau complètes.
- **Évaluation des Vulnérabilités** : Intègre OpenVAS pour des analyses détaillées des vulnérabilités.
- **Énumération des Services** : Énumère des services comme FTP, SSH, SNMP, SMB, etc.
- **Brute Force des service** : Utilsie Hydra ou Meddusa pour faire du Brut Force sur  les service détecté
- **Attaque automatisé** : Utilisse Metasploit et d'autre outills pour lancer des attaques 
- **Génération de Rapports** : Génère des rapports détaillés de l'évaluation de sécurité.
- **Traitement de mot de passe** : Analyse et géneration de mot de passe fort


## Prérequis

- A executer sur une machine KALI-LINUX
- Python 3.x
- Les packages Python nécessaire sont  listés dans `requirements.txt`
- Installer Openvas au préalable sur votre machine 

## Installation

1. Dans le terminal : 
    ```bash
    apt install -y pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev
   ```  
   

2. Clonez le dépôt :
   ```bash
   git clone sudo git clone https://github.com/Clay-Crow/Mockingbird.git
   cd Mockingbird
   ```
    

3. Installez les dépendances Python :
   ```bash
   pip install -r requirements.txt
   ```



## Utilisation

1. Lancer le script principal :
   ```bash
   python Mockingbird.py
   ```
2. Suivez les instructions à l'écran pour effectuer une analyse de sécurité. le script va demander votre username et password de     openvas veulliez le renseigner correctement 


## Auteurs

- [GUY TCHATAT ](lien_vers_profil)

---

**Note :** Veuillez vous assurer d'avoir les droits nécessaires pour exécuter des analyses de sécurité sur les réseaux cibles. Utilisez cet outil de manière responsable.

---
