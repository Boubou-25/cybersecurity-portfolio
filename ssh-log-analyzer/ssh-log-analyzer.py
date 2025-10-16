#!/usr/bin/env python3
"""
Analyseur de logs SSH/Fail2Ban
Detecte les tentatives de connexion echouees et identifie les IPs suspectes
Auteur : Boubou-25
"""

import re
from collections import Counter
from datetime import datetime

# Chemin du fichier de log (a adapter selon ton systeme)
LOG_FILE = "/var/log/auth.log"  # Debian/Ubuntu
# LOG_FILE = "/var/log/secure"  # CentOS/RHEL

def parse_failed_attempts(log_file):
    """
    Parse le fichier auth.log et extrait les tentatives SSH echouees
    Retourne un dict {ip: nombre_tentatives}
    """
    failed_ips = []
    
    # Regex pour capturer les echecs de connexion SSH
    pattern = r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    ip = match.group(1)
                    failed_ips.append(ip)
    except FileNotFoundError:
        print(f"[ERREUR] Fichier {log_file} introuvable")
        return {}
    except PermissionError:
        print(f"[ERREUR] Permission refusee. Lance avec sudo")
        return {}
    
    return Counter(failed_ips)

def display_results(ip_counter, threshold=5):
    """
    Affiche les IPs suspectes (> threshold tentatives)
    """
    print("\n=== Analyse des logs SSH ===")
    print(f"Seuil d'alerte : {threshold} tentatives\n")
    
    suspicious = {ip: count for ip, count in ip_counter.items() if count >= threshold}
    
    if not suspicious:
        print("Aucune IP suspecte detectee")
        return
    
    print(f"{len(suspicious)} IP(s) suspecte(s) detectee(s) :\n")
    for ip, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
        print(f"[ALERTE] {ip:15} - {count} tentatives echouees")

if __name__ == "__main__":
    print("Demarrage analyse logs SSH...")
    
    # Parse les logs
    ip_stats = parse_failed_attempts(LOG_FILE)
    
    # Affiche resultats (alerte si > 5 tentatives)
    display_results(ip_stats, threshold=5)
