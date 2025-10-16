#!/usr/bin/env python3
"""
Analyseur de logs SSH/Fail2Ban (compatible systemd)
Detecte les tentatives de connexion echouees et identifie les IPs suspectes
Auteur : Boubou-25
"""

import re
import subprocess
from collections import Counter

def parse_failed_attempts_journalctl():
    """
    Parse les logs SSH via journalctl
    Retourne un dict {ip: nombre_tentatives}
    """
    failed_ips = []
    
    # Regex pour capturer les echecs de connexion SSH
    pattern = r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)'
    
    try:
        # Execute journalctl pour recuperer les logs SSH
        result = subprocess.run(
            ['journalctl', '-u', 'ssh', '--no-pager'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Si service ssh n'existe pas, essaie sshd
        if result.returncode != 0:
            result = subprocess.run(
                ['journalctl', '-u', 'sshd', '--no-pager'],
                capture_output=True,
                text=True,
                timeout=10
            )
        
        if result.returncode != 0:
            print("[ERREUR] Impossible de lire les logs SSH")
            print("Essayez : sudo journalctl -u ssh ou sudo journalctl -u sshd")
            return {}
        
        # Parse les logs
        for line in result.stdout.splitlines():
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                failed_ips.append(ip)
                
    except subprocess.TimeoutExpired:
        print("[ERREUR] Timeout lors de la lecture des logs")
        return {}
    except PermissionError:
        print("[ERREUR] Permission refusee. Lance avec sudo")
        return {}
    except FileNotFoundError:
        print("[ERREUR] journalctl introuvable. Systeme non compatible")
        return {}
    
    return Counter(failed_ips)

def display_results(ip_counter, threshold=5):
    """
    Affiche les IPs suspectes (> threshold tentatives)
    """
    print("\n=== Analyse des logs SSH (via journalctl) ===")
    print(f"Seuil d'alerte : {threshold} tentatives\n")
    
    suspicious = {ip: count for ip, count in ip_counter.items() if count >= threshold}
    
    if not suspicious:
        print("Aucune IP suspecte detectee")
        print(f"\nTotal tentatives echouees : {sum(ip_counter.values())}")
        if ip_counter:
            print("\nTop 3 IPs (toutes tentatives) :")
            for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:3]:
                print(f"  - {ip:15} : {count} tentatives")
        return
    
    print(f"{len(suspicious)} IP(s) suspecte(s) detectee(s) :\n")
    for ip, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
        print(f"[ALERTE] {ip:15} - {count} tentatives echouees")

if __name__ == "__main__":
    print("Demarrage analyse logs SSH (systemd)...")
    
    # Parse les logs via journalctl
    ip_stats = parse_failed_attempts_journalctl()
    
    # Affiche resultats (alerte si > 5 tentatives)
    display_results(ip_stats, threshold=5)
