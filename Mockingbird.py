import re
import os
import sys
import time
import nmap
import ldap3
import shutil
import random
import string
import getpass
import datetime
import requests
import subprocess
import pandas as pd
from tqdm import tqdm
from tabulate import tabulate
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
import xml.etree.ElementTree as ET
from gvm.connections import UnixSocketConnection

####################################################################################### PARTIE COMMUN ##############################################################################################################

# # ici  on initialise la liste que que prend en argument opeenvas
adresse_ip_liste = []
# ici  on initialise la liste que que prend en argument opeenvas
website_liste = []
# ici je vais metre la liste des données qu' on  va recuprer pour les nmap
clees = ["Port", "State", "Service", "Product", "Version", "Extra Info", "CPE"]
# ici je vais initialiser la liste des données des scan udp et tcp
data_tcp = True
data_udp = True
os_detected = True
user_pass_openvas = []
user_passwd = []
port_scan_openVAS_ip = "T:21,22,23,80,88,443,135,139,445,389,593,636,U:25,88,465,587,53,123,137,138,139,161,500,5355,5353"
port_scan_openVAS_web = "T:80,443"
file_result_txt = ""


def create_report_directory():
    directory = "RAPPORT"
    if not os.path.exists(directory):
        os.makedirs(directory)
    return directory

def create_unique_file(directory, filename):
    base, ext = os.path.splitext(filename)
    counter = 1
    unique_filename = os.path.join(directory, filename)
    while os.path.exists(unique_filename):
        unique_filename = os.path.join(directory, f"{base}_{counter}{ext}")
        counter += 1
    return unique_filename

def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    # Utilisation des séquences d'échappement ANSI pour colorer en bleu
    sys.stdout.write(f'\r{prefix} [\033[94m{bar}\033[0m] {percent}% {suffix}')
    sys.stdout.flush()

def connect_to_openvasrv():

    try:
        while True:
            username = input("Entrez votre nom d'utilisateur : ")
            password = getpass.getpass("Entrez votre mot de passe : ")
            path = '/run/gvmd/gvmd.sock'
            connection = UnixSocketConnection(path=path)
            
            with Gmp(connection=connection) as gmp:
                response = gmp.authenticate(username, password)
                task_test = gmp.get_tasks()

                if "200" in response and task_test:
                    print("Authentification réussie")
                    user_pass_openvas= [username,password]
                    time.sleep(2)
                    os.system("clear")
                    return user_pass_openvas
                else:
                    print("Identifiant ou mot de passe incorrect...")
                    time.sleep(2)
                    os.system("clear")
    except GvmError as e:
        print('Une erreur est survenue lors de la connexion :', e, file=sys.stderr)

def read_vuln_xml_openvas(filename):

    with open(file_result_txt,"a") as f :
        f.write("SCAN DE VULNERABILITÉ OPENVAS:\n\n")

        try:
            tree = ET.parse(filename)
            root = tree.getroot()

            vuln_info = []

            # Recherche de tous les éléments <result> qui contiennent les informations des NVT
            result_elements = root.findall(".//result")

            if len(result_elements) == 0 :
                print("Aucun resultats trouvé pour se scan")
            else:
                for result_elem in result_elements:
                    nvt_elem = result_elem.find(".//nvt")
                    if nvt_elem is None:
                        continue
                    
                    name_elem = nvt_elem.find(".//name")
                    threat_elem = result_elem.find(".//original_threat")
                    severity_elem = result_elem.find(".//original_severity")
                    solution_elem = result_elem.find(".//solution")
                    cve_elements = nvt_elem.findall(".//ref[@type='cve']")

                    name_text = name_elem.text if name_elem is not None else "Nom non trouvé"
                    threat_text = threat_elem.text if threat_elem is not None else "Information de menace non trouvée"
                    severity_text = severity_elem.text if severity_elem is not None else "Information de gravité non trouvée"
                    solution_text = solution_elem.text if solution_elem is not None else "Solution non trouvée"
                    solution_type = solution_elem.attrib.get('type', 'Type de solution non trouvé') if solution_elem is not None else "Type de solution non trouvé"

                    # Ne pas ajouter si la sévérité est 0
                    if severity_elem is not None and severity_text != "Information de gravité non trouvée":
                        try:
                            severity_value = float(severity_text)
                            if severity_value == 0:
                                continue
                        except ValueError:
                            severity_value = float('-inf')  # Pour gérer les valeurs non numériques

                    cve_ids = [cve_elem.attrib.get('id', 'ID non trouvé') for cve_elem in cve_elements]

                    vuln_info.append((name_text, threat_text, severity_text, severity_value, cve_ids, solution_text, solution_type))

                # Trier les NVT par sévérité de la plus haute à la plus basse
                vuln_info_sorted = sorted(vuln_info, key=lambda x: x[3], reverse=True)

                # Calculer la largeur maximale pour chaque colonne
                max_lengths = {
                    "name": max(len("Nom"), max(len(item[0]) for item in vuln_info_sorted)),
                    "threat": max(len("Threat"), max(len(item[1]) for item in vuln_info_sorted)),
                    "severity": max(len("Severity"), max(len(item[2]) for item in vuln_info_sorted)),
                    "cve": max(len("CVE"), max(len(", ".join(item[4])) for item in vuln_info_sorted)),
                    "solution": max(len("Solution"), max(len(item[5]) for item in vuln_info_sorted)),
                    "solution_type": max(len("Type de Solution"), max(len(item[6]) for item in vuln_info_sorted)),
                }

                # Afficher les informations NVT avec alignement
                for idx, (name, threat, severity, _, cve_ids, solution, solution_type) in enumerate(vuln_info_sorted, start=1):
                    cve_ids_text = ", ".join(cve_ids) if cve_ids else ""
                    print(f"{idx}. Nom:".ljust(20) + f"{name}")
                    print(f"   Threat:".ljust(20) + f"{threat}")
                    print(f"   Severity:".ljust(20) + f"{severity}")
                    print(f"   CVE:".ljust(20) + f"{cve_ids_text}")
                    print(f"   Type de Solution:".ljust(20) + f"{solution_type}\n")
                    print(f"   Solution:".ljust(20) + f"{solution}")
                    print("\n")  # Ajouter un espace après chaque énumération
                    
                    f.write(f"{idx}. Nom:".ljust(20) + f"{name}\n")
                    f.write(f"   Threat:".ljust(20) + f"{threat}\n")
                    f.write(f"   Severity:".ljust(20) + f"{severity}\n")
                    f.write(f"   CVE:".ljust(20) + f"{cve_ids_text}\n")
                    f.write(f"   Type de Solution:".ljust(20) + f"{solution_type}\n")
                    f.write(f"   Solution:".ljust(20) + f"{solution}\n")
                    f.write("\n")  # Ajouter un espace après chaque énumération

                end_time = datetime.datetime.now()
                end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"DATE ET HEURE DE LA FIN DU PENTEST : {end_time_str}\n\n\n")



        except ET.ParseError as e:
            print(f"Erreur lors de l'analyse du fichier XML : {e}")
            return []

def update_install():

    while True:
        try:
            # Update and upgrade the system
            subprocess.run(["apt", "update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            subprocess.run(["apt", "full-upgrade", "-y"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            
            # Install packages
            packages = [
                "nmap", "hydra", "medusa", "nbtscan", "enum4linux", "ldap-utils",
                "whois", "dnsutils", "wafw00f", "dnsrecon", "sublist3r", "testssl.sh",
                "nikto", "whatweb", "amass", "nuclei", "wpscan", "ffuf"
            ]
            subprocess.run(["apt", "install", "-y"] + packages, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            
            # Install pip package
            subprocess.run(["pip", "install", "dirhunt"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            
            # Start GVM
            subprocess.run(["gvm-start"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            
            # Clear the terminal
            subprocess.run(["clear"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        
            print("Installation et mise à jour des outils fait ... ")
            time.sleep(3)
            subprocess.run(["clear"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            break

        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")

#################################################################################################################################################################################################################################################################

###################################################################################### PARTIE ADRESSE IP ################################################################################################################""

def demander_adresse_ip():
    os.system("clear")
    while True:
        valid_ip = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        adresse_ip = input("Entrez l'adresse IP : ")

        if re.match(valid_ip, adresse_ip):
            os.system("clear")
            return adresse_ip
        else:
            print("Adresse IP invalide. Veuillez réessayer.")
            time.sleep(2)
            os.system("clear")

def my_nmap_tcp_ip():
    scanner_tcp = nmap.PortScanner()

    # Scan des ports et des services
    print("Scan des ports TCP...")
    scanner_tcp.scan(adresse_ip, arguments='-sV')
    
    # Collecter les données
    data_tcp = []
    headers_tcp = ["Port", "State", "Service", "Product", "Version", "Extra Info", "CPE"]

    for host in scanner_tcp.all_hosts():
        print(f'Host : {host} ({scanner_tcp[host].hostname()})')
        print(f'State : {scanner_tcp[host].state()}')
        for proto in scanner_tcp[host].all_protocols():
            lport = scanner_tcp[host][proto].keys()
            for port in lport:
                service = scanner_tcp[host][proto][port]
                service_name = service.get('name', 'N/A')
                service_product = service.get('product', 'N/A')
                service_version = service.get('version', 'N/A')
                service_extrainfo = service.get('extrainfo', 'N/A')
                service_cpe = service.get('cpe', 'N/A')
                data_tcp.append([
                    port,
                    service.get('state', 'N/A'),
                    service_name,
                    service_product,
                    service_version,
                    service_extrainfo,
                    service_cpe
                ])

    # Afficher les données sous forme de table
    print(tabulate(data_tcp, headers=headers_tcp, tablefmt="pretty"))
    
    with open(file_result_txt, "a") as f:
        f.write("Scan port TCP :\n")
        f.write(tabulate(data_tcp, headers=headers_tcp, tablefmt="pretty"))
        f.write("\n\n\n")

    return data_tcp

def my_nmap_udp_ip():
    
    scanner_udp = nmap.PortScanner()

    # Scan des ports et des services
    print("Scan des ports UDP ...")
    scanner_udp.scan(adresse_ip, arguments='-sU -p25,88,465,587,53,5355,5353,123,137,138,139,161,500,')
    
    # Collecter les données
    data_udp = []
    headers_udp = ["Port", "State", "Service", "Product", "Version", "Extra Info", "CPE"]

    for host in scanner_udp.all_hosts():
        print(f'Host : {host} ({scanner_udp[host].hostname()})')
        print(f'State : {scanner_udp[host].state()}')
        for proto in scanner_udp[host].all_protocols():
            lport = scanner_udp[host][proto].keys()
            for port in lport:
                service = scanner_udp[host][proto][port]
                service_name = service.get('name', 'N/A')
                service_product = service.get('product', 'N/A')
                service_version = service.get('version', 'N/A')
                service_extrainfo = service.get('extrainfo', 'N/A')
                service_cpe = service.get('cpe', 'N/A')
                data_udp.append([
                    port,
                    service.get('state', 'N/A'),
                    service_name,
                    service_product,
                    service_version,
                    service_extrainfo,
                    service_cpe
                ])

    # Afficher les données sous forme de table
    print(tabulate(data_udp, headers=headers_udp, tablefmt="pretty"))

    with open(file_result_txt, "a") as f:
        f.write("Scan port UDP :\n")
        f.write(tabulate(data_udp, headers=headers_udp, tablefmt="pretty"))
        f.write("\n\n\n")
    return data_udp

def my_nmap_os_ip():
    # Scan pour la détection de l'OS
    print("Détection de l'OS...")
    with open(file_result_txt,"a") as f :

        try:
            nmap_command = f"nmap -O {adresse_ip}"
            result = subprocess.check_output(nmap_command, shell=True, text=True)
            lines = result.split('\n')

            os_detected = None
            for line in lines:
                if "OS details" in line and ':' in line:
                    os_detected = line.split(":")[1].strip()
                    break

            if os_detected:
                print("OS détecté :", os_detected)
                f.write(f"OS détecté : {os_detected}\n\n\n")
            else:
                print("OS non détecté.")
                f.write(f"OS non détecté.\n\n\n")
        except subprocess.CalledProcessError as e:
            print("Erreur lors de la détection de l'OS :", e)

        return os_detected

def snmp_enum():

    #snmp_port = any(data_udp.get("Port") == 161 for data_udp in data_udp)
    snmp_port = any(data_udp[i]["Port"] == 161 and data_udp[i]["State"] == "open" for i in range(len(data_udp)))

    if snmp_port:
        
        print("SNMP ENUMEARATION : \n")
        print("brute force metasploitable des communauté:\n")
        with os.popen(f"msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_login;set RHOSTS {adresse_ip};run;exit'") as stream0:
            output0 = stream0.readlines()

            element_found = [ligne for ligne in output0 if "Login Successful" in ligne]
        
            # Affiche les lignes filtrées
            for elment  in element_found:
                print(elment)
            print("\n")

            with open(file_result_txt, "a") as f:
                f.write("SNMP ENUMEARATION:\n\n")
                f.write("Brute force comunnauté snmp :\n")
                for elment  in element_found:
                    f.write(elment)
                f.write("\n")
        print("differents Script nmap  por snmp:\n")
        with os.popen(f"nmap -sU -p161 --script snmp-win32-users {adresse_ip}") as stream:
            output = stream.read()

            file = "BRUTE_FORCE/common_user.txt"
            # Utilise une expression régulière pour extraire les utilisateurs
            pattern = r"snmp-win32-users:\s*\|([\s\S]*?)MAC Address:"
            matches = re.search(pattern, output)
            
            if matches:
                # Récupère et nettoie la liste des utilisateurs
                output_new = matches.group(1).strip()
                users_sans_barre = [user.strip('|_ ').strip() for user in output_new.split('\n') if user.strip()]
                
                # Affiche les utilisateurs nettoyés
                for user in users_sans_barre:
                    print(user)

                with open(file, 'a') as f:
                    for user in users_sans_barre:
                        f.write(user + '\n')
                        print(user)

                with open(file_result_txt,"a") as f:
                    f.write('Enumeration user WIN avec nmap:\n')
                    for user in users_sans_barre:
                        f.write(user + '\n')
                    f.write("\n")

        with os.popen(f"nmap -sU -p161 --script snmp-win32-shares {adresse_ip}") as stream1:
            output1 = stream1.read()
            pattern = r"snmp-win32-shares:\s*\|([\s\S]*?)MAC Address:"
            matches = re.search(pattern, output1)

            if matches:
                # Récupère et nettoie la liste des utilisateurs
                output_new = matches.group(1).strip()
                element_sans_barre = [element.strip('|_ ').strip() for element in output_new.split('\n') if element.strip()]

                for element in element_sans_barre:
                    print(element)
                
                with open(file_result_txt,"a") as f:
                    f.write('Enumeration shares WIN avec nmap:\n')
                    for element in element_sans_barre:
                        f.write(element + '\n')
                    f.write("\n")

        with os.popen(f"nmap -sU -p161 --script snmp-info {adresse_ip}") as stream2:
            output2 = stream2.read()
            pattern = r"snmp-info:\s*\|([\s\S]*?)MAC Address:"
            matches = re.search(pattern, output2)

            if matches:
                # Récupère et nettoie la liste des utilisateurs
                print("snmp-info:")
                output_new = matches.group(1).strip()
                element_sans_barre = [element.strip('|_ ').strip() for element in output_new.split('\n') if element.strip()]

                for element in element_sans_barre:
                    print(element)
                print("\n")
                
                with open(file_result_txt,"a") as f:
                    f.write('Snmp info avec nmap:\n')
                    for element in element_sans_barre:
                        f.write(element + '\n')
                    f.write("\n")

        with os.popen(f"nmap -sU -p161  --script snmp-sysdescr {adresse_ip}") as stream3:
            output3 = stream3.read()
            #pattern = r"snmp-sysdescr: \s*\|([\s\S]*?)MAC Address:"
            pattern = r"snmp-sysdescr:([\s\S]*?)MAC Address:"
            matches = re.search(pattern, output3)

            if matches:
                print("snmp-sysdescr:")
                # Récupère et nettoie la liste des utilisateurs
                output_new = matches.group(1).strip()
                element_sans_barre = [element.strip('|_ ').strip() for element in output_new.split('\n') if element.strip()]

                for element in element_sans_barre:
                    print(element)
                print("\n")

                with open(file_result_txt,"a") as f:
                    f.write('Snmp sysdescr avec nmap:\n')
                    for element in element_sans_barre:
                        f.write(element + '\n')
                    f.write("\n")

        with os.popen(f"nmap -sU -p161 --script snmp-interfaces {adresse_ip}") as stream4:
            output4 = stream4.read()
            pattern = r"snmp-interfaces:\s*\|([\s\S]*?)MAC Address:"
            matches = re.search(pattern, output4)

            if matches:
                print("snmp-interfaces:")
                # Récupère et nettoie la liste des utilisateurs
                output_new = matches.group(1).strip()
                element_sans_barre = [element.strip('|_ ').strip() for element in output_new.split('\n') if element.strip()]

                for element in element_sans_barre:
                    print(element)
                print("\n")

                with open(file_result_txt,"a") as f:
                    f.write('Snmp interface avec nmap:\n')
                    for element in element_sans_barre:
                        f.write(element + '\n')
                    f.write("\n")

        with os.popen(f"nmap -sU -p161 --script snmp-processes {adresse_ip}") as stream5:
            output5 = stream5.read()
            pattern = r"snmp-processes:\s*\|([\s\S]*?)MAC Address:"
            matches = re.search(pattern, output5)

            if matches:
                print("snmp-processes:")
                # Récupère et nettoie la liste des utilisateurs
                output_new = matches.group(1).strip()
                element_sans_barre = [element.strip('|_ ').strip() for element in output_new.split('\n') if element.strip()]

                for element in element_sans_barre:
                    print(element)
                print("\n\n")

                with open(file_result_txt,"a") as f:
                    f.write('Snmp processes avec nmap:\n')
                    for element in element_sans_barre:
                        f.write(element + '\n')
                    f.write("\n\n\n")
            
    else:
        pass

def ftp_enum():

    ftp_port = any(data_tcp.get("Port") == 21 for data_tcp in data_tcp)

    # Vérifiez si le port FTP (21) est ouvert
    if ftp_port:

        print("FTP ENMUM : \n")
        user_passwd = [] 

        with os.popen(f"nmap -p 21 -sS --script ftp-anon {adresse_ip}") as stream1:
            output1 = stream1.read()
            with open(file_result_txt,"a") as f:
                f.write("FTP ENUMEARATION: \n\n")
                f.write("Anonymous FTP login:\n")
                if "Anonymous FTP login allowed" in output1:
                    anon_ftp = "Anonymous FTP login allowed"
                    print(anon_ftp)
                    f.write(anon_ftp)
                    f.write("\n")

                else:
                    anon_ftp = "Anonymous FTP login not allowed"
                    print(anon_ftp)
                    f.write(anon_ftp)
                    f.write("\n")
        
        with os.popen(f"nmap -p 21 -sS --script ftp-syst {adresse_ip}") as stream2:
            output2 = stream2.read()
            pattern = r"ftp-syst:\s*\|([\s\S]*?)MAC Address:"
            matches = re.search(pattern, output2)
            with open(file_result_txt,"a") as f:
                f.write("ftp-syst :\n")
                if matches:
                    ftp_syst_output = matches.group(1).strip()
                    print("resultat du script ftp-syst:")
                    print(ftp_syst_output)
                    f.write(ftp_syst_output)
                    f.write("\n")
                else:
                    print("Le script ftp-syst n'a pas trouvé de contenu ou le format n'est pas reconnu.")

        with os.popen(f"hydra -L BRUTE_FORCE/common_user.txt -P BRUTE_FORCE/common_pwd.txt {adresse_ip} ftp") as stream3:
            output3 = stream3.read()
            pattern = re.compile(r'\[21\]\[ftp\] host: [0-9.]+   login: (\S+)   password: (\S+)')
            matches = pattern.findall(output3)
            print("BRUT FORCE en cours...")
        
            df = pd.DataFrame(matches, columns=['USER', 'PASSWORD'])
            print(tabulate(df, headers='keys', tablefmt='pretty'))
            print(f"Nombre total d'utilisateurs valides trouvés: {len(matches)}")
            for match in matches:
                    user_passwd.append([match[0], match[1]])
            
            with open(file_result_txt,"a") as f :

                f.write("BRUTE FORCE FTP: \n")
                f.write(tabulate(df, headers='keys', tablefmt='pretty'))
                f.write("\n")
                f.write("\n\n\n")

        return user_passwd

    else:
        pass

def ssh_enum():
    
    ssh_port = any(data_tcp.get("Port") == 22 for data_tcp in data_tcp)

    
    if ssh_port:
        user_passwd = []
        print("Lancement de l'enum ssh:\n\n")
        with open(file_result_txt,"a") as f :
            f.write("SSH ENUMERATION : \n\n")
            f.write("ssh enum algo:\n")       
            with os.popen(f"nmap -p 22 --script ssh2-enum-algos {adresse_ip}") as stream:
                output = stream.read()
                pattern = r"ssh2-enum-algos:\s*\|([\s\S]*?)MAC Address:"
                match = re.search(pattern, output)
                if match:
                    ssh2_enum_algos = match.group(1).strip()
                    print("resultat du script ssh2-enum-algos:")
                    print(ssh2_enum_algos)
                    f.write(ssh2_enum_algos)
                    f.write("\n")
                else:
                    print("Le script ssh2-enum-algos n'a pas trouvé de contenu ou le format n'est pas reconnu.")

            f.write("ssh hostkey :\n")
            with os.popen(f"nmap -p 22 --script ssh-hostkey {adresse_ip}") as stream1:
                output1 = stream1.read()
                pattern = r"ssh-hostkey:\s*\|([\s\S]*?)MAC Address:"
                match = re.search(pattern, output1)
                if match:
                    ssh_hostkey = match.group(1).strip()
                    print("resultat du script ssh-hostkey:")
                    print(ssh_hostkey)
                    f.write(ssh_hostkey)
                    f.write("\n")
                else:
                    print("Le script ssh-hostkey n'a pas trouvé de contenu ou le format n'est pas reconnu.")

            f.write("ssh auth methods:\n")
            with os.popen(f"nmap -p 22 --script ssh-auth-methods {adresse_ip}") as stream2:
                output2 = stream2.read()
                pattern = r"ssh-auth-methods:\s*\|([\s\S]*?)MAC Address:"
                match = re.search(pattern, output2)
                if match:
                    ssh_auth_meth = match.group(1).strip()
                    print("resultat du script ssh-auth-methods:")
                    print(ssh_auth_meth)
                    f.write(ssh_auth_meth)
                    f.write("\n")
                else:
                    print("Le script ssh-auth-methods n'a pas trouvé de contenu ou le format n'est pas reconnu.")

            f.write("ENUM USER SSH METASPLOITE :\n")
            with os.popen(f"msfconsole -q -x 'use scanner/ssh/ssh_enumusers;set RHOSTS {adresse_ip};set USER_FILE BRUTE_FORCE/common_user.txt;run;exit'") as stream3:
                output3 = stream3.read()
                user_pattern = re.compile(r"User '(\w+)' found")
                users = user_pattern.findall(output3)
                if users:
                    print("Voici les utilisateurs valides trouvés :")
                    df = pd.DataFrame(users, columns=['UTILISATEUR',])
                    print(tabulate(df, headers='keys', tablefmt='pretty'))
                    f.write(tabulate(df, headers='keys', tablefmt='pretty'))
                    f.write("\n")

                else:
                    print("Auncun utilisateur valide trouvé")
            
            f.write("BRUTE FORCE SSH MEDUSA :\n")
            with os.popen(f"medusa -U BRUTE_FORCE/common_user.txt -P BRUTE_FORCE/common_pwd.txt -h {adresse_ip} -M ssh -f -t5")  as stream4:
                output4 = stream4.read()
                user_pattern = re.compile(r"ACCOUNT FOUND: \[ssh\] Host: \S+ User: (\S+) Password: (\S+) \[SUCCESS\]")
                matches = user_pattern.findall(output4)
                print("BRUTE FORCE en cours...")
                if matches:
                    print("Voici les utilisateurs valides trouvés :")
                    df = pd.DataFrame(matches, columns=['UTILISATEUR',"MOT DE PASSE"])
                    print(tabulate(df, headers='keys', tablefmt='pretty'))
                    print(f"Nombre total d'utilisateurs valides trouvés: {len(matches)}")
                    for match in matches:
                        user_passwd.append([match[0], match[1]])

                    f.write(tabulate(df, headers='keys', tablefmt='pretty'))
                    f.write("\n\n\n")
                    print("\n")
                else:
                    print("Auncun utilisateur valide trouvé")
        
        return user_passwd

    else:
        pass

def telnet_enum():
    
    telnet_port = any(data_tcp.get("Port") == 23 for data_tcp in data_tcp)

    if telnet_port:
        print("TELNET ENUMERATION:\n\n")
        with open(file_result_txt,"a") as f :
            f.write("TELNET ENUMERATION:\n\n")
            f.write("Telnet encryption:\n")
            with os.popen(f"nmap -n -sV -Pn --script telnet-encryption -p 23 {adresse_ip}") as stream:
                output = stream.read()
                if "Telnet server does not support encryption" in output:
                    telnet_encrypt = "Le serveur Telnet ne prend pas en charge le cryptage"
                    print(telnet_encrypt)
                    f.write(telnet_encrypt)
                    f.write("\n\n\n")
                else:
                    print(output)
                    f.write(output)
                    f.write("\n\n\n")
    else:
        pass

def smtp_enum():

    smtp_port1 = any(data_tcp.get("Port") == 465 for data_tcp in data_tcp)
    smtp_port2 = any(data_tcp.get("Port") == 587 for data_tcp in data_tcp)
    smtp_port3 = any(data_tcp.get("Port") == 25  for data_tcp in data_tcp)
    

    if smtp_port1 or smtp_port2 or smtp_port3:
        print("SMTP ENUMERATION:\n\n")
        with open(file_result_txt,"a") as f :
            f.write("SMTP ENUMERATION:\n\n")
            f.write("Recherche de serveur mail:\n")
            with os.popen(f"dig +short mx {adresse_ip}") as stream:
                output = stream.readlines()
                df = pd.DataFrame(output, columns=['SERVEUR MX',])
                print(tabulate(df, headers='keys', tablefmt='pretty'))
                f.write(tabulate(df, headers='keys', tablefmt='pretty'))
                f.write("\n")

            f.write("smtp open relay:\n")
            with os.popen(f"nmap -p25 --script smtp-open-relay {adresse_ip}") as stream1:
                output1 = stream1.read()
                pattern = r"smtp-open-relay: ([\s\S]*?)\nMAC Address:"
                matches = re.search(pattern,output1)
                if matches:
                    smtp_relay_output = matches.group(1).strip()
                    if "Server doesn't seem to be an open relay, all tests failed" in smtp_relay_output:
                        srv_relay_smtp = "ACUN serveur relai trouvé"
                        print(srv_relay_smtp)
                    else:
                        print(smtp_relay_output)
                        f.write(smtp_relay_output)
                        f.write("\n")
                else:
                    srv_relay_smtp = "Aucun serveur relai trouvé"
                    print(srv_relay_smtp)

            f.write("smtp command:\n")
            with os.popen(f"nmap -p25 --script smtp-commands {adresse_ip}") as stream2:
                output2 = stream2.read()
                pattern = r"smtp-commands: ([\s\S]*?)\nMAC Address:"
                matches = re.search(pattern,output2)
                if matches:
                    smtp_command_output = matches.group(1).strip()
                    print("Voici les commandes SMTP trouvés:")
                    print(smtp_command_output)
                    f.write(smtp_command_output)
                    f.write("\n")
                else:
                    smtp_command_output = "Aucune commande trouvé"
                    print(smtp_command_output)

            f.write("smtp enum user:\n")
            with os.popen(f"nmap -p25 --script smtp-enum-users {adresse_ip}") as stream3:
                output3 = stream3.read()
                pattern = r"smtp-enum-users: ([\s\S]*?)\nMAC Address:"
                matches = re.search(pattern,output3)
                if matches:
                    smtp_enumuser_output = matches.group(1).strip()
                    if "Method RCPT returned a unhandled status code." in smtp_enumuser_output:
                        smtp_enumuser = "Aucun utilisateur trouvé"
                        print(smtp_enumuser)
                    else:
                        print("Voici les users trouvés :")
                        print(smtp_enumuser_output)
                        f.write(smtp_enumuser_output)
                        f.write("\n\n\n")
                else:
                    smtp_enumuser = "Aucun utilisateur trouvé"
                    print(smtp_enumuser)

    else:
        pass

def dns_enum():

    dns_port = any(data_tcp.get("Port") == 53 for data_tcp in data_tcp) or any(data_udp[i]["Port"] == 53 and data_udp[i]["State"] == "open" for i in range(len(data_udp)))

    if dns_port:
        print("DNS ENUMERATION:\n\n")
        with open(file_result_txt,"a") as f :
            f.write("DNS ENUMERATION:\n\n")
            f.write("dns enumeration:\n")
            with os.popen(f" nmap -p53 -n --script '(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport' {adresse_ip}") as stream:
                output = stream.read()
                print(output)
                f.write(output)
                f.write("\n")

            f.write("enum dns METASPLOITE:\n")
            with os.popen(f"msfconsole -q -x 'use auxiliary/gather/enum_dns;set DOMAIN {adresse_ip};run;exit'") as stream1:
                output1 = stream1.read()
                print(output1)
                f.write(output1)
                f.write("\n\n\n")
    else:
        pass

def ntp_enum():
    
    #ntp_port = any(data_udp.get("Port") == 123 for data_udp in data_udp)
    ntp_port = any(data_udp[i]["Port"] == 123 and data_udp[i]["State"] == "open" for i in range(len(data_udp)))

    
    if ntp_port:
        print("NTP ENUMERATION:\n\n")
        with open(file_result_txt,"a") as f :
            f.write("NTP ENUMERATION:\n\n")
            f.write("ntp info :\n")
            print("Lancement de l'enum ntp")
            with os.popen(f"nmap -sU -sV --script ntp-info -p 123 {adresse_ip}") as stream:
                output = stream.read()
                pattern = r"ntp-info:\s*\|([\s\S]*?)MAC Address:"
                matches = re.search(pattern,output)
                if matches:
                    outpu_new = matches.group(1).strip()
                    print(outpu_new)
                    f.write(outpu_new)
                    f.write("\n\n\n")
                else:
                    print("Aucune information trouvé")
    else:
        pass

def netbios_enum():
    
    netbios_port1 = any(data_tcp.get("Port") == 137 for data_tcp in data_tcp)
    netbios_port2 = any(data_tcp.get("Port") == 138 for data_tcp in data_tcp)
    netbios_port3 = any(data_tcp.get("Port") == 139 for data_tcp in data_tcp)

    if netbios_port1 or netbios_port2 or netbios_port3:
        print("NETBIOS ENUM :\n\n")
        with open(file_result_txt,"a") as f :
            f.write("NETBIOS ENUM :\n\n")
            f.write("nbtscan:\n")
            with os.popen(f"nbtscan -v {adresse_ip}") as stream:
                output = stream.readlines()
            
                # Filtrer les lignes vides et enlever les espaces superflus
                filtered_output = [line.strip() for line in output if line.strip()]
                
                # Supprimer les 5 premières lignes et la dernière ligne (comme demandé)
                if len(filtered_output) > 6:
                    del filtered_output[:5]
                    del filtered_output[-2:]
                
                # Préparation des données pour le tableau
                data_netbios = []
                for line in filtered_output:
                    parts = line.split()
                    name = parts[0]
                    service = parts[1]
                    type_netbios = parts[2]
                    data_netbios.append([name, service, type_netbios])
                
                # En-têtes du tableau
                headers = ["Name", "NETBIOS CODE", "Type"]
                
                # Utilisation de tabulate pour afficher le tableau
                table = tabulate(data_netbios, headers=headers, tablefmt="grid")
                print(table)
                f.write(table)
                f.write("\n\n\n")
                return data_netbios
            
    else:
        pass

def msrpc_enum():

    msrpc_port = any(data_tcp.get("Port") == 135 for data_tcp in data_tcp)

    if msrpc_port:
        print("MSRPC ENUMERATION:\n\n") 
        with open(file_result_txt,"a") as f:
            f.write("MSRPC ENUMERATION:\n\n")  
            f.write("IOXIDResolver:\n") 
        #######   abuser de la méthode ServerAlive2 à l'intérieur de l'interface IOXIDResolver
            filename = "IOXIDResolver"
            os.system(f"git clone https://github.com/mubix/IOXIDResolver.git ")

            print("Lancement de l'enum MSRPC ")

            with os.popen(f"python IOXIDResolver/IOXIDResolver.py -t {adresse_ip}") as stream:
                output = stream.readlines()
                time.sleep(5)
                print(output)
                for element in output:
                    f.write(element)
                shutil.rmtree(filename)
                f.write("\n\n\n")
    else:
        pass

def smb_enum():

    smb_port1 = any(data_tcp.get("Port") == 139 for data_tcp in data_tcp)
    smb_port2 = any(data_tcp.get("Port") == 445 for data_tcp in data_tcp)


    if smb_port1 or smb_port2:
        print("SMB ENUMERATION:\n\n")
        user_passwd = [] 
        with open(file_result_txt,"a") as f :
            f.write("SMB ENUMERATION:\n\n")
            f.write("Smb version:\n")
            #VERSION DU SERVEUR SMB
            with os.popen(f"msfconsole -q -x 'use auxiliary/scanner/smb/smb_version;set RHOSTS {adresse_ip};set RPORT 139;run;exit'") as stream00:
                output00 = stream00.read()
                print(output00)
                f.write(output00)
                f.write('\n')

            f.write("Enum4linux anonyme:\n")
            with os.popen(f"enum4linux -a {adresse_ip}") as stream:
                output = stream.read()
                print(output)
                f.write(output)
                f.write("\n")

            f.write("BRUTE FORCE SMB HYDRA:\n")
            with os.popen(f"hydra -L BRUTE_FORCE/common_user.txt -P BRUTE_FORCE/common_pwd.txt {adresse_ip} smb") as stream0:
                output0 = stream0.read()
                pattern = re.compile(r'\[445\]\[smb\] host: [0-9.]+   login: (\S+)   password: (\S+)')
                matches = pattern.findall(output0)
                print("BRUT FORCE en cours...")
                
                for match in matches:
                    user_passwd.append([match[0], match[1]])

                df = pd.DataFrame(matches, columns=['UTILISATEUR', 'MOT_DE_PASSE'])
                print(tabulate(df, headers='keys', tablefmt='pretty'))
                print(f"Nombre total d'utilisateurs valides trouvés: {len(matches)}")
                f.write(tabulate(df, headers='keys', tablefmt='pretty'))
                f.write("\n")

            if not user_passwd:
                pass
            else:
                f.write("Enum4linux with credential:\n")
                with os.popen(f"enum4linux -a -u {user_passwd[0][0]} -p {user_passwd[0][1]} {adresse_ip}") as stream1:
                    output1 = stream1.read()
                    print(output1)
                    f.write(output1)
                    f.write("\n\n\n")
            return user_passwd
    else:
        pass

def enum_ldap_anonyme():
    
    print("LDAP ENUM ANONYME:\n")
    with open(file_result_txt,"a") as f :
        f.write("LDAP ENUM ANONYME:\n")
        while True:
            server = ldap3.Server(adresse_ip, get_info = ldap3.ALL, port =389,)
            connection = ldap3.Connection(server)
            connection.bind()
            connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*')
            print(server.info)
            f.write(f"server.info")
            f.write("\n")
            break

def ldap_enum():
    
    ldap_port = any(data_tcp.get("Port") == 389 for data_tcp in data_tcp)

    if ldap_port:
       
        with open(file_result_txt,"a") as f :
            f.write("LDAP ENUM :\n\n")
            with os.popen(f" nmap -sV -p389 {adresse_ip}") as stream:
                output = stream.read()
                pattern = r"Domain: ([\s\S]*?)\,"
                matches = re.search(pattern,output)
                if matches:
                    domaine = matches.group(1).strip()
                    print(f"Le domaine trouvé est {domaine}")
                    dc_dc = domaine.split(".")
                    f.write(f"Le domaine trouvé est {domaine}")
                    f.write("\n")

            enum_ldap_anonyme()
            if not user_passwd or len(user_passwd[0]) < 2:
                pass
            else:
                print("LDAP ENUM avec credential :\n")
                f.write("Ldapsearch all:\n")
                with os.popen(f"ldapsearch -x -H ldap://{adresse_ip} -D '{dc_dc[0]}\{user_passwd[0][0]}' -w '{user_passwd[0][1]}' -b 'DC={dc_dc[0]},DC={dc_dc[1]}'") as stream0:
                    output0 = stream0.read()
                    print(output0)
                    f.write(output0)
                    f.write("\n\n\n")
    else:
        pass

def scan_vuln_openvas_ip():
    try:
        username = user_pass_openvas[0]
        password = user_pass_openvas[1]
        path = '/run/gvmd/gvmd.sock'
        connection = UnixSocketConnection(path=path)
        with Gmp(connection=connection) as gmp:
            gmp.authenticate(username, password)

            time.sleep(2)
            # Récupérer la liste des listes de ports
            toutes_les_listes_ports = gmp.get_port_lists()
            toutes_les_listes_ports_xml = ET.fromstring(toutes_les_listes_ports)
            toutes_les_listes_ports_existantes = toutes_les_listes_ports_xml.findall('.//port_list')
            nom_liste_ports = "PORTS POUR LE SCAN DE VULN"

            # Vérifier si la liste de ports existe déjà et récupérer l'ID si c'est le cas
            id_liste_ports = None
            for pl in toutes_les_listes_ports_existantes:
                for name in pl.findall('name'):
                    if name.text == nom_liste_ports:
                        id_liste_ports = pl.get('id')
                        print(f"Liste de ports pour {nom_liste_ports} existe déjà avec ID : {id_liste_ports}")
                        time.sleep(2)
                        break
                if id_liste_ports:
                    break

            # Créer la liste de ports si elle n'existe pas
            if not id_liste_ports:
                liste_ports_creer = gmp.create_port_list(
                    name=nom_liste_ports,
                    port_range=port_scan_openVAS_ip
                )
                liste_ports_xml = ET.fromstring(liste_ports_creer)
                id_liste_ports = liste_ports_xml.get('id')
                print(f"Liste de ports pour {nom_liste_ports} créée avec ID : {id_liste_ports}")
                time.sleep(2)

            # Récupérer la liste des cibles
            toutes_les_cibles = gmp.get_targets()
            toutes_les_cibles_xml = ET.fromstring(toutes_les_cibles)
            toutes_les_cibles_existantes = toutes_les_cibles_xml.findall('.//target')
            nom_cible = f"CIBLE {adresse_ip_liste}"

            # Vérifier si la cible existe déjà et récupérer l'ID si c'est le cas
            id_cible = None
            for t in toutes_les_cibles_existantes:
                for name in t.findall('name'):
                    if name.text == nom_cible:
                        id_cible = t.get('id')
                        print(f"{nom_cible} existe déjà avec ID : {id_cible}")
                        time.sleep(2)
                        break
                if id_cible:
                    break

            # Créer la cible si elle n'existe pas
            if not id_cible:
                cible_creer = gmp.create_target(name=nom_cible,
                                                hosts=adresse_ip_liste,
                                                port_list_id=id_liste_ports)
                cible_xml = ET.fromstring(cible_creer)
                id_cible = cible_xml.get("id")
                print(f"{nom_cible} créée avec ID : {id_cible}")
                time.sleep(2)

            # Récupérer la liste des tâches
            toutes_les_taches = gmp.get_tasks()
            toutes_les_taches_xml = ET.fromstring(toutes_les_taches)
            toutes_les_taches_existantes = toutes_les_taches_xml.findall(".//task")
            nom_tache = f"MON SCAN {adresse_ip}"

            # Vérifier si la tâche existe déjà et récupérer l'ID et le statut si c'est le cas
            id_tache = None
            statut_tache = None
            for t in toutes_les_taches_existantes:
                for name in t.findall('name'):
                    if name.text == nom_tache:
                        id_tache = t.get('id')
                        for status in t.findall('.//status'):
                            statut_tache = status.text
                        print(f"La tâche {nom_tache} existe déjà avec ID : {id_tache} et statut : {statut_tache}")
                        time.sleep(2)
                        break
                if id_tache:
                    break

            # Si la tâche a déjà été lancée et est terminée, récupérer le rapport
            if id_tache and statut_tache == 'Done':
                print(f"La tâche {nom_tache} est terminée, récupération du rapport...")
                rapports = gmp.get_reports()
                rapports_xml = ET.fromstring(rapports)
                rapport_id = None
                for rapport in rapports_xml.findall('.//report'):
                    if rapport.find('.//task').get('id') == id_tache:
                        rapport_id = rapport.get('id')
                        break

                if rapport_id:
                    rapport = gmp.get_report(report_id=rapport_id, report_format_id='5057e5cc-b825-11e4-9d0e-28d24461215b',ignore_pagination=True)  # Format xml
                    #save_report(rapport, f"rapport_{nom_tache}.xml")
                    filename = f"rapport_{nom_tache}.xml"
                    with open(filename, 'w') as file:
                        file.write(rapport)
                    read_vuln_xml_openvas(filename=filename)
                    os.remove(filename)
                else:
                    print("Aucun rapport trouvé pour la tâche.")

            # Si la tâche a déjà été lancée mais n'est pas encore terminée
            elif id_tache:
                print(f"La tâche {nom_tache} a déjà été lancée : {statut_tache}")
                time.sleep(2)

            # Créer la tâche si elle n'existe pas
            else:
                tache_creer = gmp.create_task(name=nom_tache,
                                            config_id='daba56c8-73ec-11df-a475-002264764cea',
                                            scanner_id='08b69003-5fc2-4037-a479-93b440211c73',
                                            target_id=id_cible)
                tache_xml = ET.fromstring(tache_creer)
                id_tache = tache_xml.get("id")
                print(f"Tâche {nom_tache} créée avec ID : {id_tache}")
                time.sleep(2)

                # Lancer la tâche
                gmp.start_task(id_tache)
                print(f"Tâche {nom_tache} lancée.")

                # Surveiller l'état de la tâche
                tache_en_cours = True
                while tache_en_cours:
                    # Vérifier si la tâche existe toujours
                    toutes_les_taches = gmp.get_tasks()
                    toutes_les_taches_xml = ET.fromstring(toutes_les_taches)
                    toutes_les_taches_existantes = toutes_les_taches_xml.findall(".//task")

                    id_tache_existe = False
                    for t in toutes_les_taches_existantes:
                        if t.get('id') == id_tache:
                            id_tache_existe = True
                            statut_tache = None
                            for status in t.findall('.//status'):
                                statut_tache = status.text
                            break

                    if not id_tache_existe:
                        print(f"La tâche {nom_tache} a été supprimée.")
                        tache_en_cours = False
                    elif statut_tache == 'Done':
                        tache_en_cours = False
                        print(f"La tâche {nom_tache} est terminée.")
                        # Récupérer le rapport complet
                        rapports = gmp.get_reports()
                        rapports_xml = ET.fromstring(rapports)
                        rapport_id = None
                        for rapport in rapports_xml.findall('.//report'):
                            if rapport.find('.//task').get('id') == id_tache:
                                rapport_id = rapport.get('id')
                                break

                        if rapport_id:
                            rapport = gmp.get_report(report_id=rapport_id,report_format_id='5057e5cc-b825-11e4-9d0e-28d24461215b',ignore_pagination=True)  # Format xml
                            filename = f"rapport_{nom_tache}.xml"
                            with open(filename, 'w') as file:
                                file.write(rapport)
                            read_vuln_xml_openvas(filename=filename)
                            os.remove(filename)
                        else:
                            print("Aucun rapport trouvé pour la tâche.")
                    elif statut_tache in ['Stopped', 'Interrupted', 'Aborted']:
                        tache_en_cours = False
                        print(f"La tâche {nom_tache} a rencontré un problème : {statut_tache}.")
                    else:
                        progress = t.find('.//progress')
                        if progress is not None:
                            progress_value = int(progress.text)
                            print_progress_bar(progress_value, 100, prefix=f"Progression de la tâche {nom_tache} :", suffix=f"Statut : {statut_tache}")
                        else:
                            print(f"En attente de la fin de la tâche {nom_tache}...")
                    time.sleep(5)  # Ajuster le temps d'attente selon votre besoin
    except GvmError as e:
        print('Une erreur est survenue lors de la connexion :', e, file=sys.stderr)

def pentest_ip():
    global adresse_ip, adresse_ip_liste, user_pass_openvas, data_tcp, data_udp, os_detected, user_passwd,file_result_txt

    adresse_ip = demander_adresse_ip()
    adresse_ip_liste = [adresse_ip]

    # Créer le dossier "RAPPORT"
    report_directory = create_report_directory()
    
    # Créer un fichier unique dans le dossier "RAPPORT" avec l'adresse IP dans le nom
    file_result_txt = create_unique_file(report_directory, f"Rapport_pentest_{adresse_ip}.txt")
    
    with open(file_result_txt, "w") as f:
        start_time = datetime.datetime.now()
        start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"DATE ET HEURE DU DEBUT DU PENTEST : {start_time_str}\n\n\n")
        f.write(f"Adresse IP : {adresse_ip}\n\n\n")
        user_pass_openvas = connect_to_openvasrv()
        data_tcp = my_nmap_tcp_ip()
        data_udp = my_nmap_udp_ip()
        data_tcp = [dict(zip(clees, entry)) for entry in data_tcp]
        data_udp = [dict(zip(clees, entry)) for entry in data_udp]
        os_detected = my_nmap_os_ip()
        snmp_enum()

    with open(file_result_txt,"a") as f :
        f.write("Analyse des mots de passe pour FTP : \n\n")
        user_passwd = ftp_enum()
        reuslta_analyse_mdp = analyser_mot_de_passe()
        for e in reuslta_analyse_mdp:
            print(e)
            print("\n")
            f.write(f"{e}")
            f.write("\n")
        f.write("\n\n\n")

    with open(file_result_txt,"a") as f :
        f.write("Analyse des mots de passe pour SSH : \n\n")
        user_passwd = ssh_enum()
        reuslta_analyse_mdp = analyser_mot_de_passe()
        for e in reuslta_analyse_mdp:
            print(e)
            print("\n")
            f.write(f"{e}")
            f.write("\n")
        f.write("\n\n\n")

        telnet_enum()
        smtp_enum()
        dns_enum()
        ntp_enum()
        netbios_enum()
        msrpc_enum()

    with open(file_result_txt,"a") as f :
        f.write("Analyse des mots de passe pour SMB : \n\n")
        user_passwd = smb_enum()
        reuslta_analyse_mdp = analyser_mot_de_passe()
        for e in reuslta_analyse_mdp:
            print(e)
            print("\n")
            f.write(f"{e}")
            f.write("\n")
        f.write("\n\n\n")

        ldap_enum()
        scan_vuln_openvas_ip()

##########################################################################################################################################################################################################################

####################################################### PARTIE POUR LES SERVEUR WEB ####################################################################################################################################################


def demander_website():
    os.system("clear")
    while True:

        valid_website = r'^[\w-]+\.[a-z]{2,3}$'
        website = input("Entrez l'adresse web : ")

        if re.match(valid_website,website):
            os.system("clear")
            return website
        else:
            print("Adresse WEB invalide. Veuillez réessayer.")
            time.sleep(2)
            os.system("clear")

def my_nmap_tcp_website():

    with open(file_result_txt,"a") as f:

        f.write("Scan port TCP :\n")
        scanner_tcp = nmap.PortScanner()

        # Scan des ports et des services
        print("Scan des ports TCP...")
        scanner_tcp.scan(website, arguments='-sV')
        
        # Collecter les données
        data_tcp = []
        headers_tcp = ["Port", "State", "Service", "Product", "Version", "Extra Info", "CPE"]

        for host in scanner_tcp.all_hosts():
            print(f'Host : {host} ({scanner_tcp[host].hostname()})')
            print(f'State : {scanner_tcp[host].state()}')
            for proto in scanner_tcp[host].all_protocols():
                lport = scanner_tcp[host][proto].keys()
                for port in lport:
                    service = scanner_tcp[host][proto][port]
                    service_name = service.get('name', 'N/A')
                    service_product = service.get('product', 'N/A')
                    service_version = service.get('version', 'N/A')
                    service_extrainfo = service.get('extrainfo', 'N/A')
                    service_cpe = service.get('cpe', 'N/A')
                    data_tcp.append([
                        port,
                        service.get('state', 'N/A'),
                        service_name,
                        service_product,
                        service_version,
                        service_extrainfo,
                        service_cpe
                    ])

        # Afficher les données sous forme de table
        print(tabulate(data_tcp, headers=headers_tcp, tablefmt="pretty"))
        f.write(tabulate(data_tcp, headers=headers_tcp, tablefmt="pretty"))
        f.write("\n\n\n")
        
        return data_tcp

def my_nmap_os_website():
    # Scan pour la détection de l'OS
    print("Détection de l'OS...")
    with open(file_result_txt,"a") as f:

        try:
            nmap_command = f"nmap -O {website}"
            result = subprocess.check_output(nmap_command, shell=True, text=True)
            lines = result.split('\n')

            os_detected = None
            for line in lines:
                if "OS details" in line and ':' in line:
                    os_detected = line.split(":")[1].strip()
                    break

            if os_detected:
                print("OS détecté :", os_detected)
                f.write(f"OS détecté : {os_detected}\n\n\n")
            else:
                print("OS non détecté.")
        except subprocess.CalledProcessError as e:
            print("Erreur lors de la détection de l'OS :", e)

        return os_detected

def my_whois():
    
    with open(file_result_txt,"a") as f :
        f.write("WHOIS :\n\n")
        # Lancer la commande whois et capturer la sortie
        print(f"Lancement de la commande whois\n")

        # Utiliser os.popen pour exécuter la commande et lire la sortie
        with os.popen(f"whois {website}") as stream:
            output = stream.read()

        # Définir les en-têtes
        headers = [
            "Domain Name", "Registry Domain ID", "Registrar WHOIS Server", "Registrar URL",
            "Updated Date", "Creation Date", "Registry Expiry Date", "Registrar",
            "Registrar IANA ID", "Registrar Abuse Contact Email", "Registrar Abuse Contact Phone",
            "Domain Status", "Name Server", "DNSSEC", "DNSSEC DS Data",
            "Registry Registrant ID", "Registrant Name", "Registrant Organization",
            "Registrant Street", "Registrant City", "Registrant State/Province",
            "Registrant Postal Code", "Registrant Country", "Registrant Phone",
            "Registrant Phone Ext", "Registrant Fax", "Registrant Fax Ext", "Registrant Email",
            "Registry Admin ID", "Admin Name", "Admin Organization", "Admin Street",
            "Admin City", "Admin State/Province", "Admin Postal Code", "Admin Country",
            "Admin Phone", "Admin Phone Ext", "Admin Fax", "Admin Fax Ext", "Admin Email",
            "Registry Tech ID", "Tech Name", "Tech Organization", "Tech Street",
            "Tech City", "Tech State/Province", "Tech Postal Code", "Tech Country",
            "Tech Phone", "Tech Phone Ext", "Tech Fax", "Tech Fax Ext", "Tech Email"
        ]

        # Initialiser le dictionnaire whois_info avec des listes vides pour chaque en-tête
        whois_info = {header: [] for header in headers}

        # Générer dynamiquement les regex patterns pour chaque en-tête
        patterns = {header: re.compile(rf"{header}:\s*(.+)", re.IGNORECASE) for header in headers}

        # Extraire les informations de la sortie whois
        for line in output.splitlines():
            for header, pattern in patterns.items():
                match = pattern.match(line)
                if match:
                    whois_info[header].append(match.group(1))

        # Préparer les tableaux pour chaque en-tête et ses données
        tables = []
        for header in headers:
            data = [[entry] for entry in whois_info[header]]
            if data:  # Afficher uniquement si des données sont disponibles
                tables.append((header, tabulate(data, headers=[header], tablefmt="grid")))

        # Afficher chaque tableau séparément
        for header, table in tables:
            print(f"\n{header}:\n{table}")
            print("\n\n")

            f.write(f"\n{header}:\n{table}")
            print("\n\n\n")

def my_nslookup():
    with open(file_result_txt,"a") as f :

        f.write("NSLOOKUP :\n\n")
        print(f"Lancement de la commande nslookup {website} \n")

        with os.popen(f"nslookup {website}") as stream:
            output = stream.read()

        headers = [
            "Non-authoritative answer",
            "Réponse ne faisant pas autorité",
            "Name",
            "Nom",
            "Address",
            "Addresses"
        ]

        nslookup_info = {header: [] for header in headers}

        patterns = {
            "Non-authoritative answer": re.compile(r"Non-authoritative answer", re.IGNORECASE),
            "Réponse ne faisant pas autorité": re.compile(r"Réponse ne faisant pas autorité", re.IGNORECASE),
            "Name": re.compile(r"Name:\s*(.+)", re.IGNORECASE),
            "Nom": re.compile(r"Nom\s*:\s*(.+)", re.IGNORECASE),
            "Address": re.compile(r"Address:\s*(.+)", re.IGNORECASE),
            "Addresses": re.compile(r"Addresses:\s*(.+)", re.IGNORECASE)
        }

        current_header = None
        for line in output.splitlines():
            for header, pattern in patterns.items():
                if header in ["Non-authoritative answer", "Réponse ne faisant pas autorité"]:
                    if pattern.match(line):
                        current_header = header
                        break
                else:
                    match = pattern.match(line)
                    if match:
                        nslookup_info[header].append(match.group(1))
                        current_header = header
                        break
            else:
                if current_header in ["Addresses"] and re.match(r"\s+(\d+\.\d+\.\d+\.\d+)", line):
                    nslookup_info[current_header].append(line.strip())

        if nslookup_info["Address"]:
            nslookup_info["Address"] = nslookup_info["Address"][1:]
        elif nslookup_info["Addresses"]:
            nslookup_info["Addresses"] = nslookup_info["Addresses"][1:]

        tables = []
        for header in headers:
            if nslookup_info[header]:
                data = [[entry] for entry in nslookup_info[header]]
                tables.append((header, tabulate(data, headers=[header], tablefmt="grid")))

        for header, table in tables:
            print(f"\n{header}:\n{table}")
            print("\n\n")

            f.write(f"\n{header}:\n{table}")
            f.write("\n\n\n")

def my_wafwoof():
    with open(file_result_txt,"a") as f :
        f.write("WAFWOOF:\n\n")
        print(f"Lancement de la commande wafw00f \n")
        
        with os.popen(f"wafw00f {website} -v") as stream:
            output = stream.read()
        
        # Rechercher la ligne contenant le nom du WAF
        waf_match = re.search(r'\[\+\] The site .* is behind (.*) WAF\.', output)
        
        if waf_match:
            waf_name = waf_match.group(1)
            print(f"WAF détecté : {waf_name}")
            f.write(f"WAF détecté : {waf_name}")
            f.write("\n\n\n")
        else:
            print("Aucun WAF détecté")
            f.write("Aucun WAF détecté")
            f.write("\n\n\n")

def my_dnsrecon():

    with open(file_result_txt,"a") as f :
        f.write("DNSRECON:\n\n")
        print(f"Lancement de la commande dnsrecon \n")

        with os.popen(f"dnsrecon -d {website}") as stream1:
            output1 = stream1.read()


        # Catégoriser les résultats
        results1 = {
            "General Enumeration": [],
            "DNSSEC Configuration": [],
            "DNSKEYs": [],
            "SOA Record": [],
            "NS Records": [],
            "Bind Version": [],
            "MX Records": [],
            "A Records": [],
            "AAAA Records": [],
            "TXT Records": [],
            "SRV Records": []
        }

        lines = output1.splitlines()
        current_category = None

        for line in lines:
            if "Performing General Enumeration" in line:
                current_category = "General Enumeration"
            elif "DNSSEC is configured" in line:
                current_category = "DNSSEC Configuration"
            elif "DNSKEYs" in line:
                current_category = "DNSKEYs"
            elif "SOA" in line:
                current_category = "SOA Record"
            elif "NS" in line:
                current_category = "NS Records"
            elif "Bind Version" in line:
                current_category = "Bind Version"
            elif "MX" in line:
                current_category = "MX Records"
            elif "A " in line:
                current_category = "A Records"
            elif "AAAA" in line:
                current_category = "AAAA Records"
            elif "TXT" in line:
                current_category = "TXT Records"
            elif "Enumerating SRV Records" in line:
                current_category = "SRV Records"
            
            if current_category:
                results1[current_category].append(line)

        # Affichage des résultats bien rangés
        for category, lines in results1.items():
            print(f"=== {category} ===")
            f.write(f"=== {category} ===")
            for line in lines:
                print(line)
                f.write(line)
                f.write("\n")
            print()


        
        with os.popen(f"dnsrecon -d {website} -t axfr") as stream2:
            output2 = stream2.read()


        results2 = {
            "Zone Transfer Check": [],
            "SOA Record": [],
            "NS Records": [],
            "NS Servers": [],
            "Duplicate NS Removal": [],
            "NS Server Check": [],
            "Zone Transfer Results": []
        }

        lines = output2.splitlines()
        current_category = None

        for line in lines:
            if "Checking for Zone Transfer" in line:
                current_category = "Zone Transfer Check"
            elif "Resolving SOA Record" in line:
                current_category = "SOA Record"
            elif "Resolving NS Records" in line:
                current_category = "NS Records"
            elif "NS Servers found" in line:
                current_category = "NS Servers"
            elif "Removing any duplicate NS server IP Addresses" in line:
                current_category = "Duplicate NS Removal"
            elif "Trying NS server" in line:
                current_category = "NS Server Check"
            elif "Zone Transfer Failed" in line or "Zone Transfer Successful" in line:
                current_category = "Zone Transfer Results"
            
            if current_category:
                results2[current_category].append(line)

        # Affichage des résultats bien rangés
        for category, lines in results2.items():
            print(f"=== {category} ===")
            f.write(f"=== {category} ===")
            for line in lines:
                print(line)
                f.write(line)
                f.write("\n\n\n")
            print()

def my_sublist3r():

    with open(file_result_txt,"a") as f :
        f.write("SUBLIST3R:\n\n")

        print(f"Lancement de la commande sublist3r\n")

        # Run the command and capture the output
        with os.popen(f"sublist3r -d {website}") as stream:
            output = stream.read()

        # Initialize an empty list to store subdomains
        subdomains = []

        # Find the index of the line containing "Total Unique Subdomains Found"
        index = output.find("Total Unique Subdomains Found")
        if index != -1:
            # Extract lines after the line containing the total count
            subdomain_lines = output[index:].split('\n')[1:]
            for line in subdomain_lines:
                line = line.strip()
                if line:  # Skip empty lines
                    subdomains.append([line])

        # Print the table of subdomains
        print("Sous domaines  touvé:")
        print(tabulate(subdomains, headers=["Subdomains"]))
        f.write("Sous domaines  touvé:\n")
        f.write(tabulate(subdomains, headers=["Subdomains"]))
        f.write("\n\n\n")

def my_testssl():

    with open(file_result_txt,"a") as f :
        f.write("TESTSSL:\n\n")
        print("lancement de la commande testssl\n")

        with os.popen(f"testssl {website}:443") as stream:
            output = stream.read()
            pattern = r"<<--.*?([\s\S]*?)Done"
            matches = re.search(pattern,output)
            if matches:
                output_new = matches.group(1).strip()
                print(output_new)
                f.write(output_new)
                f.write("\n\n\n")
            else:
                print("Pas de correspondance...")
                f.write("pas de correspondance ...")
                f.write("\n\n\n")

def recon_web_serveur():
    
    while True:
        my_whois()
        my_nslookup()
        my_wafwoof()
        my_dnsrecon()
        my_sublist3r()
        my_testssl()
        break

def my_nikto():
    with open(file_result_txt,"a") as f :
        f.write("NIKTO:\n\n")
        print("Lanccement de la commande nikto\n")

        with os.popen(f"nikto -host {website}") as stream:
            output = stream.read()
            #pattern = r"- Nikto v2\.5\.0([\s\S]*?)\+ 1 host\(s\) tested"
            pattern = r"Nikto v\d+\.\d+\.\d+([\s\S]*?)\+ 1 host\(s\) tested"
            matches = re.search(pattern,output)
            if matches:
                output_new = matches.group(1).strip()
                print(output_new)
                f.write(output_new)
                f.write("\n\n\n")
            else:
                print("Aucun resultat trouvé pour nikto")

def my_what_web():
    with open(file_result_txt,"a") as f:
        f.write("WHATWEB:\n\n")
        print("lancement de la commande whatweb\n")
        with os.popen(f"whatweb -a 3 {website}") as stream:
            output = stream.read()
            print(output)
            f.write(output)
            f.write("\n\n\n")

def my_nuclei():
    with open(file_result_txt,"a") as f :
        f.write("NUCLEI:\n\n")
        print("lancement de la commande NUCLEI\n")
        with os.popen(f"nuclei -target {website}") as stream:
            output = stream.read()
            print(output)
            f.write(output)
            f.write("\n\n\n")

def my_wpscan():

    with open(file_result_txt,"a") as f :
        f.write("WPSCAN:\n\n")
        print("Lancement de la commande wpscan")

        with os.popen(f"wpscan --force update -e  --url {website}")as stream:
            output = stream.read()
            if "Scan Aborted" in output:
                print("Impossible de scanner ou pas detecter de woodpresse ..")
            else:
                pattern = r"Interesting Finding\(s\):([\s\S]*)"
                matches = re.search(pattern,output)
                if matches:
                    output_new = matches.group(1).strip()
                    print(output_new)
                    f.write(output_new)
                    f.write("\n\n\n")

def scan_auto_web():
    
    while True:

        my_nikto()
        my_what_web()
        my_nuclei()
        my_wpscan()
        break

def verif_common_site_fichier():
    with open(file_result_txt,"a") as f :
        f.write("verification de fichier:\n\n")
        print("verification de fichiers sur le site web:\n")

        resources = [
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/.well-known'
        ]
        results = {}
        
        for resource in resources:
            url = f"https://{website}" + resource
            response = requests.get(url)
            if response.status_code == 200:
                results[resource] = True
            else:
                results[resource] = False

        # Affichage des résultats
        for resource, found in results.items():
            if found:
                print(f"{resource} trouvé sur {website}")
                f.write(f"{resource} trouvé sur {website}")
            else:
                print(f"{resource} non trouvé sur {website}")
                f.write(f"{resource} non trouvé sur {website}")

            f.write("\n\n\n")

        return results

def my_dirhunt():

    with open(file_result_txt,"a") as f :
        f.write("DIRHUNT:\n\n")
        print("lancement de dirhunt")

        with os.popen(f"dirhunt https://{website}") as stream:
            output = stream.read()
            print(output)
            f.write(output)
            f.write("\n\n\n")

def my_brute_force_reportoir():
    with open(file_result_txt,"a") as f:
        f.write("FUFF BRUTE FORCE:\n\n")
        print("Lancement du BRUTE FORCE de répertoire")
        with os.popen(f"ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://{website}") as stream:
            output = stream.read()
            print(output)
            f.write(output)
            f.write("\n\n\n")

def scan_vuln_openvas_web():
    try:
        username = user_pass_openvas[0]
        password = user_pass_openvas[1]
        path = '/run/gvmd/gvmd.sock'
        connection = UnixSocketConnection(path=path)
        with Gmp(connection=connection) as gmp:
            gmp.authenticate(username, password)

            time.sleep(2)
            # Récupérer la liste des listes de ports
            toutes_les_listes_ports = gmp.get_port_lists()
            toutes_les_listes_ports_xml = ET.fromstring(toutes_les_listes_ports)
            toutes_les_listes_ports_existantes = toutes_les_listes_ports_xml.findall('.//port_list')
            nom_liste_ports = "PORTS POUR LE SCAN DE VULN WEB"

            # Vérifier si la liste de ports existe déjà et récupérer l'ID si c'est le cas
            id_liste_ports = None
            for pl in toutes_les_listes_ports_existantes:
                for name in pl.findall('name'):
                    if name.text == nom_liste_ports:
                        id_liste_ports = pl.get('id')
                        print(f"Liste de ports pour {nom_liste_ports} existe déjà avec ID : {id_liste_ports}")
                        time.sleep(2)
                        break
                if id_liste_ports:
                    break

            # Créer la liste de ports si elle n'existe pas
            if not id_liste_ports:
                liste_ports_creer = gmp.create_port_list(
                    name=nom_liste_ports,
                    port_range=port_scan_openVAS_web
                )
                liste_ports_xml = ET.fromstring(liste_ports_creer)
                id_liste_ports = liste_ports_xml.get('id')
                print(f"Liste de ports pour {nom_liste_ports} créée avec ID : {id_liste_ports}")
                time.sleep(2)

            # Récupérer la liste des cibles
            toutes_les_cibles = gmp.get_targets()
            toutes_les_cibles_xml = ET.fromstring(toutes_les_cibles)
            toutes_les_cibles_existantes = toutes_les_cibles_xml.findall('.//target')
            nom_cible = f"CIBLE {website_liste}"

            # Vérifier si la cible existe déjà et récupérer l'ID si c'est le cas
            id_cible = None
            for t in toutes_les_cibles_existantes:
                for name in t.findall('name'):
                    if name.text == nom_cible:
                        id_cible = t.get('id')
                        print(f"{nom_cible} existe déjà avec ID : {id_cible}")
                        time.sleep(2)

                        break
                if id_cible:
                    break

            # Créer la cible si elle n'existe pas
            if not id_cible:
                cible_creer = gmp.create_target(name=nom_cible,
                                                hosts=website_liste,
                                                port_list_id=id_liste_ports)
                cible_xml = ET.fromstring(cible_creer)
                id_cible = cible_xml.get("id")
                print(f"{nom_cible} créée avec ID : {id_cible}")
                time.sleep(2)
                

            # Récupérer la liste des tâches
            toutes_les_taches = gmp.get_tasks()
            toutes_les_taches_xml = ET.fromstring(toutes_les_taches)
            toutes_les_taches_existantes = toutes_les_taches_xml.findall(".//task")
            nom_tache = f"MON SCAN {website}"

            # Vérifier si la tâche existe déjà et récupérer l'ID et le statut si c'est le cas
            id_tache = None
            statut_tache = None
            for t in toutes_les_taches_existantes:
                for name in t.findall('name'):
                    if name.text == nom_tache:
                        id_tache = t.get('id')
                        for status in t.findall('.//status'):
                            statut_tache = status.text
                        print(f"La tâche {nom_tache} existe déjà avec ID : {id_tache} et statut : {statut_tache}")
                        time.sleep(2)
                        break
                if id_tache:
                    break

            # Si la tâche a déjà été lancée et est terminée, récupérer le rapport
            if id_tache and statut_tache == 'Done':
                print(f"La tâche {nom_tache} est terminée, récupération du rapport...")
                rapports = gmp.get_reports()
                rapports_xml = ET.fromstring(rapports)
                rapport_id = None
                for rapport in rapports_xml.findall('.//report'):
                    if rapport.find('.//task').get('id') == id_tache:
                        rapport_id = rapport.get('id')
                        break

                if rapport_id:
                    rapport = gmp.get_report(report_id=rapport_id, report_format_id='5057e5cc-b825-11e4-9d0e-28d24461215b',ignore_pagination=True)  # Format xml
                    #save_report(rapport, f"rapport_{nom_tache}.xml")
                    filename = f"rapport_{nom_tache}.xml"
                    with open(filename, 'w') as file:
                        file.write(rapport)
                    read_vuln_xml_openvas(filename=filename)
                    os.remove(filename)
                else:
                    print("Aucun rapport trouvé pour la tâche.")

            # Si la tâche a déjà été lancée mais n'est pas encore terminée
            elif id_tache:
                print(f"La tâche {nom_tache} a déjà été lancée : {statut_tache}")
                time.sleep(2)
            # Créer la tâche si elle n'existe pas
            else:
                tache_creer = gmp.create_task(name=nom_tache,
                                            config_id='daba56c8-73ec-11df-a475-002264764cea',
                                            scanner_id='08b69003-5fc2-4037-a479-93b440211c73',
                                            target_id=id_cible)
                tache_xml = ET.fromstring(tache_creer)
                id_tache = tache_xml.get("id")
                print(f"Tâche {nom_tache} créée avec ID : {id_tache}")
                time.sleep(2)

                # Lancer la tâche
                gmp.start_task(id_tache)
                print(f"Tâche {nom_tache} lancée.")

                # Surveiller l'état de la tâche
                tache_en_cours = True
                while tache_en_cours:
                    # Vérifier si la tâche existe toujours
                    toutes_les_taches = gmp.get_tasks()
                    toutes_les_taches_xml = ET.fromstring(toutes_les_taches)
                    toutes_les_taches_existantes = toutes_les_taches_xml.findall(".//task")

                    id_tache_existe = False
                    for t in toutes_les_taches_existantes:
                        if t.get('id') == id_tache:
                            id_tache_existe = True
                            statut_tache = None
                            for status in t.findall('.//status'):
                                statut_tache = status.text
                            break

                    if not id_tache_existe:
                        print(f"La tâche {nom_tache} a été supprimée.")
                        tache_en_cours = False
                    elif statut_tache == 'Done':
                        tache_en_cours = False
                        print(f"La tâche {nom_tache} est terminée.")
                        # Récupérer le rapport complet
                        rapports = gmp.get_reports()
                        rapports_xml = ET.fromstring(rapports)
                        rapport_id = None
                        for rapport in rapports_xml.findall('.//report'):
                            if rapport.find('.//task').get('id') == id_tache:
                                rapport_id = rapport.get('id')
                                break

                        if rapport_id:
                            rapport = gmp.get_report(report_id=rapport_id,report_format_id='5057e5cc-b825-11e4-9d0e-28d24461215b',ignore_pagination=True)  # Format xml
                            filename = f"rapport_{nom_tache}.xml"
                            with open(filename, 'w') as file:
                                file.write(rapport)
                            read_vuln_xml_openvas(filename=filename)
                            os.remove(filename)
                        else:
                            print("Aucun rapport trouvé pour la tâche.")
                    elif statut_tache in ['Stopped', 'Interrupted', 'Aborted']:
                        tache_en_cours = False
                        print(f"La tâche {nom_tache} a rencontré un problème : {statut_tache}.")
                    else:
                        progress = t.find('.//progress')
                        if progress is not None:
                            progress_value = int(progress.text)
                            print_progress_bar(progress_value, 100, prefix=f"Progression de la tâche {nom_tache} :", suffix=f"Statut : {statut_tache}")
                        else:
                            print(f"En attente de la fin de la tâche {nom_tache}...")
                    time.sleep(5)  # Ajuster le temps d'attente selon votre besoin
    except GvmError as e:
        print('Une erreur est survenue lors de la connexion :', e, file=sys.stderr)

def pentest_web():

    global website, website_liste, user_pass_openvas, data_tcp, os_detected,file_result_txt
    website = demander_website()
    website_liste = [website]

    # Créer le dossier "RAPPORT"
    report_directory = create_report_directory()
    
    # Créer un fichier unique dans le dossier "RAPPORT" avec l'adresse IP dans le nom
    file_result_txt = create_unique_file(report_directory, f"Rapport_{website}.txt")
    
    with open(file_result_txt, "w") as f:
        start_time = datetime.datetime.now()
        start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"DATE ET HEURE DU DEBUT DU PENTEST : {start_time_str}\n\n\n")
        f.write(f"SITE  WEB : {website}\n\n\n")

    user_pass_openvas = connect_to_openvasrv()
    data_tcp = my_nmap_tcp_website()
    data_tcp = [dict(zip(clees, entry)) for entry in data_tcp]
    os_detected = my_nmap_os_website()
    recon_web_serveur()
    scan_auto_web()
    verif_common_site_fichier()
    my_dirhunt()
    my_brute_force_reportoir()
    scan_vuln_openvas_web()

########################################################################################################################################################################################################################################################""

##############################################GESTION DE MOT DE PASSE##########################################################################################################################################################################################

def generer_mot_de_passe(longueur=12):
    # Assurez-vous que la longueur minimale est de 12
    if longueur < 12:
        longueur = 12

    # Définir les différents types de caractères
    majuscules = string.ascii_uppercase
    minuscules = string.ascii_lowercase
    chiffres = string.digits
    caracteres_speciaux = string.punctuation

    # Choisir au moins un caractère de chaque type
    mot_de_passe = [
        random.choice(majuscules),
        random.choice(minuscules),
        random.choice(chiffres),
        random.choice(caracteres_speciaux)
    ]

    # Compléter le mot de passe avec des caractères aléatoires jusqu'à la longueur souhaitée
    reste = longueur - len(mot_de_passe)
    tous_les_caracteres = majuscules + minuscules + chiffres + caracteres_speciaux

    for _ in tqdm(range(reste), desc="Génération du mot de passe", bar_format="{l_bar}{bar}{r_bar}", colour='yellow'):
        mot_de_passe.append(random.choice(tous_les_caracteres))
        time.sleep(0.1)  # Simuler un petit délai pour rendre la progression visible

    # Mélanger les caractères pour éviter un schéma prévisible
    random.shuffle(mot_de_passe)

    # Convertir la liste en chaîne de caractères
    mot_de_passe = ''.join(mot_de_passe)

    return mot_de_passe

def analyser_mot_de_passe():
    with open('BRUTE_FORCE/MOTSDEPASSE_FAIBLE.txt', 'r') as f:
        fichier_mauvais_mots_de_passe = f.read().splitlines()

    def verifier_mot_de_passe(username, password):
        # Vérifier si le mot de passe est faible
        mot_de_passe_faible = password.lower() in fichier_mauvais_mots_de_passe or len(password) < 7 or password.lower() == username.lower()

        # Vérifier si le mot de passe est fort
        mot_de_passe_fort = (
            len(password) >= 12 and
            any(char.isdigit() for char in password) and
            any(char.isupper() for char in password) and
            any(char.islower() for char in password) and
            any(char in "!@#$%^&*()-_+=[]{};:',.<>?/" for char in password)
        )

        # Déterminer le résultat
        if mot_de_passe_faible:
            return f"Le mot de passe pour {username} est FAIBLE."
        elif mot_de_passe_fort:
            return f"Le mot de passe pour {username} est FORT."
        else:
            return f"Le mot de passe pour {username} est MOYEN."

    resultat_analyse_mdp = []

    if 'user_passwd' in globals() and user_passwd:
        for username, password in user_passwd:
            resultat_analyse_mdp.append(verifier_mot_de_passe(username, password))
    else:
        username = input("Entrez votre nom d'utilisateur : ")

        while True:
            password = getpass.getpass("Entrez votre mot de passe : ")
            password_confirm = getpass.getpass("Confirmez votre mot de passe : ")

            if password == password_confirm:
                resultat_analyse_mdp.append(verifier_mot_de_passe(username, password))
                break
            else:
                print("Les mots de passe ne correspondent pas. Veuillez réessayer.")

    return resultat_analyse_mdp
######################################################################################################################################################################################################################################"

def menu_principal():

    update_install()
    os.system("clear")

    print("┏╋━━━━━━◥◣◆◢◤━━━━━━╋┓")
    print("╭  ▎▎┣╮")
    print("╰┓┳╰╯┳┏╯     For You")
    print("╭┛╰━━╯┗━━━╮")
    print("┃┃    ┏━╭╰╯╮")
    print("┃┃    ┃┏┻━━┻┓")
    print("╰┫ ╭╮ ┃┃Hack┃")
    print(" ┃ ┃┃ ┃╰━━━━╯ by CLAY-CROW ")
    print("╭┛ ┃┃ ┗-╮")
    print("┗╋━━━━━━◥◣◆◢◤━━━━━━╋┛\n")

    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    for i in range(10):
        for frame in frames:
            print(f"\r{frame} Loading Hacking...", end="")
            time.sleep(0.1)

    os.system("clear")
    print("\nBienvenue dans la  RED TEAM !")

    while True:

        print("\nQue voulez-vous faire ?")
        print("1 - PENTEST SERVEUR ")
        print("2 - PENTEST SERVEUR WEB ")
        print("3 - MOT DE PASSE")
        print("4 - QUITTER")

        choice = input("> ")

        if choice == "1":
            while True:

                os.system("clear")
                pentest_ip()
                print("FIN DU PENTEST ... ")
                time.sleep(5)
                break
                
        elif choice == "2":
            os.system("clear")
            pentest_web()
            print("FIN DU PENTEST WEB ... ")
            time.sleep(5)
            break

        elif choice == "3":
            
            while True:

                os.system("clear")

                print("1 - GENERER UN MOT DE PASSE")
                print("2 - ANALYSER UN MOT DE PASSE")
                print("3 - RETOUR")

                choix = input("> ")
                     
                if choix == "1":

                    os.system("clear")        
                    mot_de_passe = generer_mot_de_passe()
                    print(f"Voici votre mot de passe fort generé : {mot_de_passe}")
                    break
                    
                
                elif choix == "2":
                     
                    os.system("clear") 
                    analyser_mot_de_passe()
                    break

                elif choix == "3":
                    
                    os.system("clear")
                    break

        
        elif choice == "4":
            break

        else:
            os.system("clear")
            print("Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    menu_principal()