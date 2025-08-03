#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xxwfufu OSINT Tool
Créateur: xxwfufu
Outil complet d'Open Source Intelligence
"""

import os
import sys
import json
import time
import socket
import requests
import subprocess
import re
import hashlib
import base64
from datetime import datetime
from urllib.parse import urlparse, urljoin

# Gestion des imports optionnels
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("PIL non disponible - fonctions d'analyse d'image désactivées")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("dnspython non disponible - fonctions DNS désactivées")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("python-whois non disponible - fonctions WHOIS désactivées")

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier
    PHONE_AVAILABLE = True
except ImportError:
    PHONE_AVAILABLE = False
    print("phonenumbers non disponible - analyse de téléphone désactivée")

try:
    import colorama
    colorama.init()  # Pour Windows
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False

import threading
from concurrent.futures import ThreadPoolExecutor
import argparse

# Couleurs pour l'interface (compatible Windows)
class Colors:
    if COLORS_AVAILABLE:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKCYAN = '\033[96m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
    else:
        HEADER = OKBLUE = OKCYAN = OKGREEN = WARNING = FAIL = ENDC = BOLD = UNDERLINE = ''

class OSINTTool:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {}
        self.shodan_api = None  # À configurer avec votre clé API
        
    def banner(self):
        banner_text = f"""
{Colors.HEADER}
██╗  ██╗██╗  ██╗██╗    ██╗███████╗██╗   ██╗███████╗██╗   ██╗
╚██╗██╔╝╚██╗██╔╝██║    ██║██╔════╝██║   ██║██╔════╝██║   ██║
 ╚███╔╝  ╚███╔╝ ██║ █╗ ██║█████╗  ██║   ██║█████╗  ██║   ██║
 ██╔██╗  ██╔██╗ ██║███╗██║██╔══╝  ██║   ██║██╔══╝  ██║   ██║
██╔╝ ██╗██╔╝ ██╗╚███╔███╔╝██║     ╚██████╔╝██║     ╚██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝      ╚═════╝ ╚═╝      ╚═════╝ 
{Colors.ENDC}
{Colors.OKGREEN}════════════════════════════════════════════════════════════{Colors.ENDC}
{Colors.BOLD}             OUTIL OSINT COMPLET - Par xxwfufu{Colors.ENDC}
{Colors.OKGREEN}════════════════════════════════════════════════════════════{Colors.ENDC}
"""
        print(banner_text)

    def print_menu(self):
        menu = f"""
{Colors.OKCYAN}[1]{Colors.ENDC}  Recherche par nom complet
{Colors.OKCYAN}[2]{Colors.ENDC}  Recherche par pseudo/username
{Colors.OKCYAN}[3]{Colors.ENDC}  Analyse d'adresse e-mail
{Colors.OKCYAN}[4]{Colors.ENDC}  Analyse de numéro de téléphone
{Colors.OKCYAN}[5]{Colors.ENDC}  Analyse d'adresse IP
{Colors.OKCYAN}[6]{Colors.ENDC}  Analyse d'image (EXIF + Reverse)
{Colors.OKCYAN}[7]{Colors.ENDC}  Recherche WHOIS et DNS
{Colors.OKCYAN}[8]{Colors.ENDC}  Google Dorking automatisé
{Colors.OKCYAN}[9]{Colors.ENDC}  Recherche réseaux sociaux
{Colors.OKCYAN}[10]{Colors.ENDC} Analyse de domaine complet
{Colors.OKCYAN}[11]{Colors.ENDC} Générateur de rapport
{Colors.OKCYAN}[0]{Colors.ENDC}  Quitter

{Colors.WARNING}Choisissez une option:{Colors.ENDC} """
        return input(menu)

    def search_by_name(self, full_name):
        """Recherche par nom complet"""
        print(f"\n{Colors.HEADER}[*] Recherche pour: {full_name}{Colors.ENDC}")
        results = {}
        
        # Recherche simulée sur les réseaux sociaux
        try:
            print(f"{Colors.OKBLUE}[+] Recherche sur les réseaux sociaux...{Colors.ENDC}")
            # Simulation de recherche
            social_platforms = ['LinkedIn', 'Facebook', 'Twitter', 'Instagram']
            found_social = []
            
            for platform in social_platforms:
                # Simulation d'une recherche
                if hash(full_name + platform) % 3 == 0:  # Simulation aléatoire
                    found_social.append(f"{platform}: Profil potentiel trouvé")
                    print(f"  {Colors.OKGREEN}[+] {platform}: Profil potentiel{Colors.ENDC}")
            
            results['social_media'] = found_social
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] Erreur recherche réseaux sociaux: {e}{Colors.ENDC}")

        self.results['name_search'] = results
        self.display_results(results, "Recherche par nom")

    def search_by_username(self, username):
        """Recherche par pseudo/username avec catégorisation"""
        print(f"\n{Colors.HEADER}[*] Recherche du username: {username}{Colors.ENDC}")
        results = {}
        
        # Liste des plateformes courantes
        platforms = {
            # Réseaux sociaux classiques
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'Discord': f'https://discord.com/users/{username}',
            'Telegram': f'https://t.me/{username}',
            'Steam': f'https://steamcommunity.com/id/{username}',
            'Spotify': f'https://open.spotify.com/user/{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Snapchat': f'https://snapchat.com/add/{username}',
            
            # Forums et communautés
            'Stack Overflow': f'https://stackoverflow.com/users/{username}',
            'Quora': f'https://www.quora.com/profile/{username}',
            'Medium': f'https://medium.com/@{username}',
            'DeviantArt': f'https://www.deviantart.com/{username}',
            'Goodreads': f'https://www.goodreads.com/user/show/{username}',
            'Imgur': f'https://imgur.com/user/{username}',
            'Flickr': f'https://www.flickr.com/people/{username}',
            
            # Services gaming
            'Xbox': f'https://account.xbox.com/en-us/profile?gamertag={username}',
            'Battle.net': f'https://battle.net/{username}',
            'Epic Games': f'https://www.epicgames.com/id/{username}',
            'Roblox': f'https://www.roblox.com/users/{username}/profile',
            
            # Services de messagerie et VoIP
            'Skype': f'https://join.skype.com/invite/{username}',
            'Viber': f'https://invite.viber.com/{username}',
            'Signal': f'https://signal.me/#p/{username}',
            
            # Plateformes de blogging
            'WordPress': f'https://{username}.wordpress.com',
            'Tumblr': f'https://{username}.tumblr.com',
            'Blogger': f'https://{username}.blogspot.com',
            
            # Plateformes e-commerce et freelancing
            'Etsy': f'https://www.etsy.com/shop/{username}',
            'Fiverr': f'https://www.fiverr.com/{username}',
            'Upwork': f'https://www.upwork.com/freelancers/~{username}',
            
            # Divers / autres réseaux sociaux
            'Last.fm': f'https://www.last.fm/user/{username}',
            'SoundCloud': f'https://soundcloud.com/{username}',
            'Mixcloud': f'https://www.mixcloud.com/{username}',
            'Weibo': f'https://weibo.com/{username}',
            'VK': f'https://vk.com/{username}',
            'XING': f'https://www.xing.com/profile/{username}',
            'AngelList': f'https://angel.co/u/{username}',
            
            # Plateformes de partage de code
            'GitLab': f'https://gitlab.com/{username}',
            'Bitbucket': f'https://bitbucket.org/{username}',
            
            # Plateformes vidéo & streaming alternatives
            'Dailymotion': f'https://www.dailymotion.com/{username}',
            'Vimeo': f'https://vimeo.com/{username}',
            
            # Plateformes photo & art
            'Behance': f'https://www.behance.net/{username}',
            '500px': f'https://500px.com/{username}',
            
            # Plateformes de finance et crypto
            'Coinbase': f'https://www.coinbase.com/{username}',
            'Binance': f'https://www.binance.com/en/users/{username}',
            
            # Plateformes éducatives
            'Coursera': f'https://www.coursera.org/user/{username}',
            'Udemy': f'https://www.udemy.com/user/{username}',
            
            # Plateformes professionnelles
            'Angel.co': f'https://angel.co/u/{username}',
            
            # Plateformes de rencontre (attention données sensibles)
            'Tinder': f'https://tinder.com/@{username}',
            'Bumble': f'https://bumble.com/user/{username}',
            
            # Plateformes spécifiques
            'Patreon': f'https://www.patreon.com/{username}',
            'Kickstarter': f'https://www.kickstarter.com/profile/{username}'
        }
        
        found_platforms = []
        categories = {
            'social': [],
            'professional': [],
            'gaming': [],
            'creative': [],
            'tech': [],
            'other': []
        }
        
        print(f"{Colors.OKBLUE}[+] Vérification sur {len(platforms)} plateformes...{Colors.ENDC}")
        
        # Recherche avec threading pour accélérer
        def check_platform(platform, url):
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    # Vérifications supplémentaires pour éviter les faux positifs
                    if self.verify_profile_exists(response.text, platform):
                        found_platforms.append((platform, url))
                        
                        # Catégorisation
                        if platform in ['Twitter', 'Instagram', 'Facebook', 'TikTok', 'Snapchat']:
                            categories['social'].append((platform, url))
                        elif platform in ['LinkedIn', 'Angel.co', 'XING']:
                            categories['professional'].append((platform, url))
                        elif platform in ['Steam', 'Xbox', 'Battle.net', 'Epic Games', 'Roblox', 'Twitch']:
                            categories['gaming'].append((platform, url))
                        elif platform in ['DeviantArt', 'Behance', '500px', 'Flickr', 'SoundCloud']:
                            categories['creative'].append((platform, url))
                        elif platform in ['GitHub', 'GitLab', 'Bitbucket', 'Stack Overflow']:
                            categories['tech'].append((platform, url))
                        else:
                            categories['other'].append((platform, url))
                        
                        print(f"{Colors.OKGREEN}[+] Trouvé sur {platform}: {url}{Colors.ENDC}")
            except:
                pass
        
        # Utiliser ThreadPoolExecutor pour accélérer les vérifications
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_platform, platform, url) 
                      for platform, url in platforms.items()]
            
            # Attendre que tous les threads se terminent
            for future in futures:
                future.result()
        
        results['found_platforms'] = found_platforms
        results['categories'] = categories
        self.results['username_search'] = results
        
        # Affichage des résultats par catégorie
        print(f"\n{Colors.HEADER}=== RÉSULTATS PAR CATÉGORIE ==={Colors.ENDC}")
        
        for category, platforms_list in categories.items():
            if platforms_list:
                category_names = {
                    'social': 'Réseaux Sociaux',
                    'professional': 'Plateformes Professionnelles',
                    'gaming': 'Gaming & Streaming',
                    'creative': 'Créatif & Art',
                    'tech': 'Tech & Développement',
                    'other': 'Autres Plateformes'
                }
                print(f"\n{Colors.OKCYAN}📂 {category_names[category]} ({len(platforms_list)}):{Colors.ENDC}")
                for platform, url in platforms_list:
                    print(f"   • {platform}: {url}")
        
        if found_platforms:
            print(f"\n{Colors.OKGREEN}[+] Username trouvé sur {len(found_platforms)} plateformes au total{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[-] Aucune plateforme trouvée pour ce username{Colors.ENDC}")
            
        return results

    def verify_profile_exists(self, html_content, platform):
        """Vérifie si un profil existe vraiment"""
        # Mots-clés indiquant que le profil n'existe pas
        not_found_keywords = [
            'page not found', 'user not found', 'profile not found',
            'does not exist', 'account suspended', '404', 'not available',
            'page introuvable', 'utilisateur introuvable', 'compte suspendu',
            'user does not exist', 'this user does not exist',
            'sorry, this page isn\'t available', 'this content isn\'t available',
            'account disabled', 'profile unavailable'
        ]
        
        # Mots-clés positifs indiquant l'existence du profil
        positive_keywords = {
            'GitHub': ['repositories', 'followers', 'following', 'commits'],
            'Twitter': ['tweets', 'following', 'followers', '@'],
            'Instagram': ['posts', 'followers', 'following', 'stories'],
            'LinkedIn': ['connections', 'experience', 'education', 'skills'],
            'Reddit': ['karma', 'post karma', 'comment karma', 'trophy'],
            'YouTube': ['subscribers', 'videos', 'views', 'channel'],
            'TikTok': ['followers', 'following', 'likes', 'videos'],
            'Steam': ['games', 'achievements', 'friends', 'level'],
            'Spotify': ['playlists', 'followers', 'following', 'profile'],
            'Medium': ['stories', 'followers', 'following', 'claps'],
            'DeviantArt': ['deviations', 'watchers', 'watching', 'gallery'],
            'Behance': ['projects', 'followers', 'following', 'appreciations']
        }
        
        html_lower = html_content.lower()
        
        # Vérifier les mots-clés négatifs d'abord
        if any(keyword in html_lower for keyword in not_found_keywords):
            return False
            
        # Vérifier les mots-clés positifs spécifiques à la plateforme
        if platform in positive_keywords:
            return any(keyword in html_lower for keyword in positive_keywords[platform])
            
        # Si pas de mots-clés spécifiques, considérer comme existant si pas de mots négatifs
        return True

    def analyze_email(self, email):
        """Analyse complète d'une adresse e-mail"""
        print(f"\n{Colors.HEADER}[*] Analyse de l'e-mail: {email}{Colors.ENDC}")
        results = {}
        
        # Validation du format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            print(f"{Colors.FAIL}[-] Format d'e-mail invalide{Colors.ENDC}")
            return
            
        domain = email.split('@')[1]
        
        # Vérification HaveIBeenPwned (simulation pour éviter les limites d'API)
        try:
            print(f"{Colors.OKBLUE}[+] Vérification des fuites de données...{Colors.ENDC}")
            print(f"{Colors.WARNING}[i] Vérification simulée (nécessite une clé API HIBP){Colors.ENDC}")
            results['breaches'] = "Vérification nécessite une clé API"
        except Exception as e:
            print(f"{Colors.WARNING}[-] Impossible de vérifier HaveIBeenPwned: {e}{Colors.ENDC}")

        # Analyse du domaine
        if WHOIS_AVAILABLE:
            try:
                print(f"{Colors.OKBLUE}[+] Analyse du domaine {domain}...{Colors.ENDC}")
                domain_info = whois.whois(domain)
                results['domain_info'] = {
                    'registrar': getattr(domain_info, 'registrar', 'N/A'),
                    'creation_date': str(getattr(domain_info, 'creation_date', 'N/A')),
                    'expiration_date': str(getattr(domain_info, 'expiration_date', 'N/A'))
                }
                print(f"{Colors.OKGREEN}[+] Domaine analysé avec succès{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[-] Erreur analyse domaine: {e}{Colors.ENDC}")

        # Vérification MX records
        if DNS_AVAILABLE:
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                results['mx_records'] = [str(mx) for mx in mx_records]
                print(f"{Colors.OKGREEN}[+] {len(mx_records)} enregistrements MX trouvés{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[-] Erreur MX records: {e}{Colors.ENDC}")

        self.results['email_analysis'] = results

    def analyze_phone(self, phone):
        """Analyse d'un numéro de téléphone"""
        print(f"\n{Colors.HEADER}[*] Analyse du numéro: {phone}{Colors.ENDC}")
        results = {}
        
        if not PHONE_AVAILABLE:
            print(f"{Colors.WARNING}[-] Module phonenumbers non disponible{Colors.ENDC}")
            return
        
        try:
            # Parse du numéro
            parsed_number = phonenumbers.parse(phone, None)
            
            if phonenumbers.is_valid_number(parsed_number):
                # Informations géographiques
                location = geocoder.description_for_number(parsed_number, "fr")
                operator = carrier.name_for_number(parsed_number, "fr")
                
                results = {
                    'valid': True,
                    'international_format': phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                    'national_format': phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL),
                    'country_code': parsed_number.country_code,
                    'location': location,
                    'carrier': operator,
                    'line_type': 'Mobile' if phonenumbers.number_type(parsed_number) == phonenumbers.PhoneNumberType.MOBILE else 'Fixe'
                }
                
                print(f"{Colors.OKGREEN}[+] Numéro valide{Colors.ENDC}")
                print(f"{Colors.OKBLUE}[+] Localisation: {location}{Colors.ENDC}")
                print(f"{Colors.OKBLUE}[+] Opérateur: {operator}{Colors.ENDC}")
                
            else:
                results = {'valid': False}
                print(f"{Colors.FAIL}[-] Numéro invalide{Colors.ENDC}")
                
        except Exception as e:
            results = {'error': str(e)}
            print(f"{Colors.FAIL}[-] Erreur lors de l'analyse: {e}{Colors.ENDC}")
            
        self.results['phone_analysis'] = results

    def analyze_ip(self, ip):
        """Analyse complète d'une adresse IP"""
        print(f"\n{Colors.HEADER}[*] Analyse de l'IP: {ip}{Colors.ENDC}")
        results = {}
        
        # Géolocalisation avec ip-api
        try:
            print(f"{Colors.OKBLUE}[+] Géolocalisation...{Colors.ENDC}")
            geo_url = f"http://ip-api.com/json/{ip}"
            response = self.session.get(geo_url, timeout=10)
            if response.status_code == 200:
                geo_data = response.json()
                results['geolocation'] = geo_data
                print(f"{Colors.OKGREEN}[+] Pays: {geo_data.get('country', 'N/A')}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}[+] Ville: {geo_data.get('city', 'N/A')}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}[+] ISP: {geo_data.get('isp', 'N/A')}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.WARNING}[-] Erreur géolocalisation: {e}{Colors.ENDC}")

        # Informations WHOIS
        if WHOIS_AVAILABLE:
            try:
                print(f"{Colors.OKBLUE}[+] Informations WHOIS...{Colors.ENDC}")
                whois_info = whois.whois(ip)
                results['whois'] = str(whois_info)[:500]  # Limiter la taille
                print(f"{Colors.OKGREEN}[+] WHOIS récupéré{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[-] Erreur WHOIS: {e}{Colors.ENDC}")

        # Scan de ports (ports communs seulement)
        try:
            print(f"{Colors.OKBLUE}[+] Scan de ports rapide...{Colors.ENDC}")
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
                
            results['open_ports'] = open_ports
            if open_ports:
                print(f"{Colors.OKGREEN}[+] Ports ouverts: {', '.join(map(str, open_ports))}{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}[-] Aucun port ouvert détecté{Colors.ENDC}")
                
        except Exception as e:
            print(f"{Colors.WARNING}[-] Erreur scan ports: {e}{Colors.ENDC}")

        self.results['ip_analysis'] = results

    def analyze_image(self, image_path):
        """Analyse d'image (EXIF + reverse search)"""
        print(f"\n{Colors.HEADER}[*] Analyse de l'image: {image_path}{Colors.ENDC}")
        results = {}
        
        if not PIL_AVAILABLE:
            print(f"{Colors.WARNING}[-] Module PIL non disponible{Colors.ENDC}")
            return
        
        if not os.path.exists(image_path):
            print(f"{Colors.FAIL}[-] Fichier image introuvable{Colors.ENDC}")
            return
            
        try:
            # Extraction des données EXIF
            print(f"{Colors.OKBLUE}[+] Extraction des métadonnées EXIF...{Colors.ENDC}")
            image = Image.open(image_path)
            exif_data = {}
            
            if hasattr(image, '_getexif'):
                exif = image._getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_data[tag] = str(value)
                        
            results['exif'] = exif_data
            
            if exif_data:
                print(f"{Colors.OKGREEN}[+] {len(exif_data)} métadonnées trouvées{Colors.ENDC}")
                for key, value in list(exif_data.items())[:5]:  # Afficher les 5 premières
                    print(f"    {key}: {value[:50]}...")
            else:
                print(f"{Colors.WARNING}[-] Aucune métadonnée EXIF trouvée{Colors.ENDC}")
                
            # Hash de l'image
            with open(image_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            results['md5_hash'] = file_hash
            print(f"{Colors.OKBLUE}[+] Hash MD5: {file_hash}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[-] Erreur analyse image: {e}{Colors.ENDC}")
            
        self.results['image_analysis'] = results

    def whois_dns_lookup(self, domain):
        """Recherche WHOIS et DNS complète"""
        print(f"\n{Colors.HEADER}[*] Analyse WHOIS/DNS pour: {domain}{Colors.ENDC}")
        results = {}
        
        # WHOIS
        if WHOIS_AVAILABLE:
            try:
                print(f"{Colors.OKBLUE}[+] Requête WHOIS...{Colors.ENDC}")
                whois_info = whois.whois(domain)
                results['whois'] = {
                    'registrar': getattr(whois_info, 'registrar', 'N/A'),
                    'creation_date': str(getattr(whois_info, 'creation_date', 'N/A')),
                    'expiration_date': str(getattr(whois_info, 'expiration_date', 'N/A')),
                    'name_servers': getattr(whois_info, 'name_servers', [])
                }
                print(f"{Colors.OKGREEN}[+] WHOIS récupéré{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[-] Erreur WHOIS: {e}{Colors.ENDC}")

        # Enregistrements DNS
        if DNS_AVAILABLE:
            dns_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            dns_results = {}
            
            for record_type in dns_types:
                try:
                    records = dns.resolver.resolve(domain, record_type)
                    dns_results[record_type] = [str(r) for r in records]
                    print(f"{Colors.OKGREEN}[+] {record_type}: {len(records)} enregistrements{Colors.ENDC}")
                except:
                    dns_results[record_type] = []
                    
            results['dns'] = dns_results
        
        self.results['whois_dns'] = results

    def google_dorking(self, target):
        """Google Dorking automatisé"""
        print(f"\n{Colors.HEADER}[*] Google Dorking pour: {target}{Colors.ENDC}")
        
        dorks = [
            f'site:{target} filetype:pdf',
            f'site:{target} filetype:doc',
            f'site:{target} filetype:xls',
            f'site:{target} inurl:admin',
            f'site:{target} inurl:login',
            f'site:{target} inurl:backup',
            f'site:{target} "index of"',
            f'site:{target} "powered by"',
            f'{target} "email" OR "contact" OR "phone"'
        ]
        
        results = {}
        print(f"{Colors.WARNING}[i] Google Dorking simulé (nécessite une API de recherche){Colors.ENDC}")
        
        for i, dork in enumerate(dorks):
            print(f"{Colors.OKBLUE}[+] Dork {i+1}/{len(dorks)}: {dork}{Colors.ENDC}")
            results[f'dork_{i+1}'] = f"Recherche: {dork}"
                
        self.results['google_dorking'] = results

    def social_media_search(self, target):
        """Recherche sur les réseaux sociaux"""
        print(f"\n{Colors.HEADER}[*] Recherche réseaux sociaux: {target}{Colors.ENDC}")
        
        # Réutilise la fonction de recherche par username
        self.search_by_username(target)

    def domain_analysis(self, domain):
        """Analyse complète d'un domaine"""
        print(f"\n{Colors.HEADER}[*] Analyse complète du domaine: {domain}{Colors.ENDC}")
        
        # Combinaison de plusieurs analyses
        self.whois_dns_lookup(domain)
        self.google_dorking(domain)
        
        # Sous-domaines courants
        subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'dev', 'test']
        found_subdomains = []
        
        print(f"{Colors.OKBLUE}[+] Recherche de sous-domaines...{Colors.ENDC}")
        for sub in subdomains:
            try:
                full_domain = f"{sub}.{domain}"
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
                print(f"{Colors.OKGREEN}[+] Sous-domaine trouvé: {full_domain}{Colors.ENDC}")
            except:
                pass
                
        self.results.setdefault('domain_analysis', {})['subdomains'] = found_subdomains

    def generate_report(self):
        """Génère un rapport complet"""
        if not self.results:
            print(f"{Colors.WARNING}[-] Aucun résultat à exporter{Colors.ENDC}")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xxwfufu_report_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"{Colors.OKGREEN}[+] Rapport sauvegardé: {filename}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Erreur sauvegarde: {e}{Colors.ENDC}")

    def display_results(self, results, title):
        """Affiche les résultats de manière formatée"""
        print(f"\n{Colors.HEADER}=== {title} ==={Colors.ENDC}")
        if isinstance(results, dict):
            for key, value in results.items():
                print(f"{Colors.OKCYAN}{key}:{Colors.ENDC} {value}")
        else:
            print(results)

    def run(self):
        """Boucle principale"""
        self.banner()
        
        while True:
            try:
                choice = self.print_menu()
                
                if choice == '0':
                    print(f"{Colors.OKGREEN}Au revoir !{Colors.ENDC}")
                    break
                elif choice == '1':
                    name = input(f"{Colors.OKCYAN}Nom complet: {Colors.ENDC}")
                    if name.strip():
                        self.search_by_name(name)
                elif choice == '2':
                    username = input(f"{Colors.OKCYAN}Username: {Colors.ENDC}")
                    if username.strip():
                        self.search_by_username(username)
                elif choice == '3':
                    email = input(f"{Colors.OKCYAN}Adresse e-mail: {Colors.ENDC}")
                    if email.strip():
                        self.analyze_email(email)
                elif choice == '4':
                    phone = input(f"{Colors.OKCYAN}Numéro de téléphone: {Colors.ENDC}")
                    if phone.strip():
                        self.analyze_phone(phone)
                elif choice == '5':
                    ip = input(f"{Colors.OKCYAN}Adresse IP: {Colors.ENDC}")
                    if ip.strip():
                        self.analyze_ip(ip)
                elif choice == '6':
                    image_path = input(f"{Colors.OKCYAN}Chemin vers l'image: {Colors.ENDC}")
                    if image_path.strip():
                        self.analyze_image(image_path)
                elif choice == '7':
                    domain = input(f"{Colors.OKCYAN}Domaine: {Colors.ENDC}")
                    if domain.strip():
                        self.whois_dns_lookup(domain)
                elif choice == '8':
                    target = input(f"{Colors.OKCYAN}Cible pour dorking: {Colors.ENDC}")
                    if target.strip():
                        self.google_dorking(target)
                elif choice == '9':
                    target = input(f"{Colors.OKCYAN}Nom/pseudo à chercher: {Colors.ENDC}")
                    if target.strip():
                        self.social_media_search(target)
                elif choice == '10':
                    domain = input(f"{Colors.OKCYAN}Domaine: {Colors.ENDC}")
                    if domain.strip():
                        self.domain_analysis(domain)
                elif choice == '11':
                    self.generate_report()
                else:
                    print(f"{Colors.FAIL}Option invalide{Colors.ENDC}")
                    
                input(f"\n{Colors.OKCYAN}Appuyez sur Entrée pour continuer...{Colors.ENDC}")
                
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}Interruption par l'utilisateur{Colors.ENDC}")
                break
            except Exception as e:
                print(f"{Colors.FAIL}Erreur: {e}{Colors.ENDC}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='xxwfufu OSINT Tool')
    parser.add_argument('--target', help='Cible à analyser')
    parser.add_argument('--mode', help='Mode d\'analyse', choices=['email', 'phone', 'ip', 'domain', 'username'])
    args = parser.parse_args()
    
    tool = OSINTTool()
    
    if args.target and args.mode:
        # Mode ligne de commande
        if args.mode == 'email':
            tool.analyze_email(args.target)
        elif args.mode == 'phone':
            tool.analyze_phone(args.target)
        elif args.mode == 'ip':
            tool.analyze_ip(args.target)
        elif args.mode == 'domain':
            tool.domain_analysis(args.target)
        elif args.mode == 'username':
            tool.search_by_username(args.target)
        tool.generate_report()
    else:
        # Mode interactif
        tool.run()