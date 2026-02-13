"""
Port Scanner Attack Module - Ports ouverts = Vulnérabilités
Les ports ouverts sont rapportés comme vulnérabilités pour l'interface
"""
import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScannerAttack:
    def __init__(self, target, parameters):
        self.target = target
        self.parameters = parameters
        port_range = parameters.get('port_range', (1, 1000))
        
        if isinstance(port_range, list):
            self.port_range = tuple(port_range)
        else:
            self.port_range = port_range if isinstance(port_range, tuple) else (1, 1000)
        
        # Extract IP
        self.target_ip = target.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        if self.target_ip.lower() == 'localhost':
            self.target_ip = '127.0.0.1'
        
        self.scan_type = parameters.get('scan_type', 'tcp')
        self.aborted = False
        self.results = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'services_detected': [],
            'vulnerabilities_found': [],  # AJOUTÉ: Pour l'interface
            'total_scanned': 0,
            'target_ip': self.target_ip,
            'success': False
        }
        
        self.common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Proxy'
        }
        
        # Niveaux de risque par port
        self.port_risk = {
            21: 'High',      # FTP
            22: 'Medium',    # SSH
            23: 'Critical',  # Telnet
            25: 'Medium',    # SMTP
            80: 'Medium',    # HTTP
            110: 'Medium',   # POP3
            143: 'Medium',   # IMAP
            443: 'Low',      # HTTPS
            445: 'High',     # SMB
            3306: 'High',    # MySQL
            3389: 'Critical',# RDP
            5432: 'High',    # PostgreSQL
            8080: 'Medium'   # HTTP-Proxy
        }
    
    def execute(self):
        """Execute port scan"""
        start_port, end_port = self.port_range
        
        yield {
            'message': f'🚀 Démarrage scan de ports sur {self.target_ip}',
            'progress': 0,
            'status': 'initializing',
            'ports_scanned': 0
        }
        
        yield {
            'message': f'🎯 Cible: {self.target_ip} | Ports: {start_port}-{end_port}',
            'progress': 5,
            'status': 'configured'
        }
        
        time.sleep(0.3)
        
        ports_to_scan = list(range(start_port, min(end_port + 1, start_port + 200)))
        total_ports = len(ports_to_scan)
        
        print(f"\n[PORT SCAN] Scanning {total_ports} ports on {self.target_ip}")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {
                executor.submit(self._scan_port, self.target_ip, port): port 
                for port in ports_to_scan
            }
            
            scanned_count = 0
            
            for future in as_completed(future_to_port):
                if self.aborted:
                    yield {'message': 'Scan interrompu', 'status': 'aborted'}
                    break
                
                port = future_to_port[future]
                scanned_count += 1
                self.results['total_scanned'] = scanned_count
                
                try:
                    port_status, banner = future.result()
                    
                    if port_status == 'open':
                        service = self.common_services.get(port, 'Unknown')
                        risk_level = self.port_risk.get(port, 'Medium')
                        
                        if banner:
                            service = f"{service} ({banner[:30]})"
                        
                        port_info = {
                            'port': port,
                            'status': 'open',
                            'service': service,
                            'banner': banner,
                            'protocol': 'TCP',
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # AJOUTÉ: Créer une "vulnérabilité" pour chaque port ouvert
                        vulnerability = {
                            'type': 'Open Port',
                            'port': port,
                            'service': service,
                            'severity': risk_level,
                            'description': f'Port {port} ({self.common_services.get(port, "Unknown")}) est ouvert et accessible',
                            'recommendation': f'Vérifier si le service {self.common_services.get(port, "Unknown")} sur le port {port} doit être exposé',
                            'timestamp': datetime.now().isoformat(),
                            'target': self.target_ip
                        }
                        
                        self.results['open_ports'].append(port_info)
                        self.results['services_detected'].append(service)
                        self.results['vulnerabilities_found'].append(vulnerability)  # AJOUTÉ
                        self.results['success'] = True
                        
                        print(f"[PORT SCAN] ✅ Port {port} OUVERT - {service} [{risk_level}]")
                        
                        yield {
                            'message': f'🔓 OUVERT: Port {port} - {service}',
                            'progress': 5 + int(scanned_count / total_ports * 90),
                            'status': 'port_found',
                            'port': port_info,
                            'vulnerability': vulnerability,  # AJOUTÉ
                            'ports_scanned': scanned_count
                        }
                        
                    elif port_status == 'closed':
                        self.results['closed_ports'].append(port)
                    else:
                        self.results['filtered_ports'].append(port)
                    
                    if scanned_count % 25 == 0:
                        open_count = len(self.results['open_ports'])
                        yield {
                            'message': f'⏳ Scan... {scanned_count}/{total_ports} | {open_count} ouvert(s)',
                            'progress': 5 + int(scanned_count / total_ports * 90),
                            'status': 'scanning',
                            'ports_scanned': scanned_count
                        }
                
                except Exception as e:
                    print(f"[PORT SCAN] Erreur port {port}: {e}")
                    self.results['filtered_ports'].append(port)
        
        # Résumé
        open_count = len(self.results['open_ports'])
        closed_count = len(self.results['closed_ports'])
        filtered_count = len(self.results['filtered_ports'])
        
        print(f"\n[PORT SCAN] ========== RÉSULTATS ==========")
        print(f"[PORT SCAN] Ouverts: {open_count}")
        print(f"[PORT SCAN] Fermés: {closed_count}")
        print(f"[PORT SCAN] Filtrés: {filtered_count}")
        print(f"[PORT SCAN] Vulnérabilités: {len(self.results['vulnerabilities_found'])}")
        
        if open_count > 0:
            print(f"[PORT SCAN] Ports ouverts:")
            for p in self.results['open_ports']:
                print(f"[PORT SCAN]   - Port {p['port']}: {p['service']}")
        
        print(f"[PORT SCAN] ================================\n")
        
        security_level = "FAIBLE" if open_count > 10 else "MOYEN" if open_count > 5 else "FORT"
        
        yield {
            'message': f'✅ Scan terminé! {open_count} port(s) ouvert(s) trouvé(s)',
            'progress': 100,
            'status': 'completed',
            'ports_scanned': scanned_count,
            'open_ports_count': open_count,
            'vulnerabilities_count': len(self.results['vulnerabilities_found']),  # AJOUTÉ
            'security_assessment': security_level,
            'summary': {
                'open': open_count,
                'closed': closed_count,
                'filtered': filtered_count
            }
        }
    
    def _scan_port(self, target, port):
        """Scan un port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                banner = None
                try:
                    sock.settimeout(1.0)
                    if port in [21, 22, 25, 110]:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:50]
                    elif port in [80, 8080]:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        time.sleep(0.1)
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        if response:
                            banner = response.split('\n')[0].strip()[:50]
                except:
                    pass
                
                sock.close()
                return 'open', banner
            else:
                sock.close()
                return 'closed', None
                
        except socket.timeout:
            return 'filtered', None
        except:
            return 'closed', None
    
    def get_results(self):
        """Retourne les résultats"""
        return self.results
    
    def abort(self):
        """Interrompre"""
        self.aborted = True