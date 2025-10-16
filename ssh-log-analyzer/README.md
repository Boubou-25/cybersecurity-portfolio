SSH Log Analyzer
Analyseur de logs SSH/Fail2Ban en Python

Objectif
Detecter automatiquement les tentatives de connexion SSH suspectes en analysant /var/log/auth.log

Fonctionnalites
Parse les logs systeme (auth.log/secure)

Compte les echecs de connexion par IP

Alerte sur les IPs depassant un seuil (brute-force potentiel)

Regex optimisees pour performance

Utilisation
bash

# Installation (aucune dependance externe)

git clone https://github.com/Boubou-25/ssh-log-analyzer.git
cd ssh-log-analyzer

# Lancement (necessite acces root pour lire logs)

sudo python3 ssh_analyzer.py
Exemple de sortie
text
Demarrage analyse logs SSH...

=== Analyse des logs SSH ===
Seuil d'alerte : 5 tentatives

2 IP(s) suspecte(s) detectee(s) :

[ALERTE] 192.168.1.50 - 23 tentatives echouees
[ALERTE] 10.0.0.15 - 8 tentatives echouees
Evolutions futures
Export JSON des resultats

Integration avec API VirusTotal (verif reputation IP)

Blocage automatique via iptables

Dashboard web Flask

Competences demontrees
Parsing logs systeme Linux

Regex Python

Detection d'intrusion basique

Gestion fichiers/permissions

Contact : benjaminbouhier@proton.me
