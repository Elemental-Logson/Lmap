from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import nmap
import mysql.connector
from typing import Optional

import uvicorn

# Configuración de la base de datos
DB_CONFIG = {
    'user': 'user_raspi',
    'password': 'ciberscan2024*',
    'host': '10.11.0.17',
    'database': 'db_logson'
}

app = FastAPI()



class ScanRequest(BaseModel):
    target_ip: str
    scan_name: str
    ports: Optional[str] = '1-1024'
    intensity: Optional[str] = 'normal'

def save_scan_results_to_db(scan_name, scan_results):
    # Conectar a la base de datos
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    
    # Insertar un nuevo escaneo en la tabla scan
    cursor.execute('''
        INSERT INTO scan (name)
        VALUES (%s)
    ''', (scan_name,))
    scan_id = cursor.lastrowid
    
    # Insertar los resultados del escaneo en la base de datos
    for host_data in scan_results:
        host = host_data['host']
        hostname = host_data['hostname']
        state = host_data['state']

        # Insertar un registro en la tabla scanned_ips
        cursor.execute('''
            INSERT INTO scanned_ips (scan_id, host, hostname, state)
            VALUES (%s, %s, %s, %s)
        ''', (scan_id, host, hostname, state))
        scanned_ip_id = cursor.lastrowid
        
        for proto_data in host_data['protocols']:
            protocol = proto_data['protocol']
            
            for port_data in proto_data['ports']:
                port = port_data['port']
                service = port_data['service']
                product = port_data['product']
                version = port_data['version']
                script_id = None
                script_output = None

                # Insertar datos del puerto y servicio en la tabla scan_details
                cursor.execute('''
                    INSERT INTO scan_details (scanned_ip_id, protocol, port, service, product, version, script_id, script_output)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ''', (scanned_ip_id, protocol, port, service, product, version, script_id, script_output))
                
                # Insertar resultados de los scripts si existen
                for script in port_data.get('scripts', []):
                    script_id = script['script_id']
                    script_output = script['output']
                    
                    cursor.execute('''
                        INSERT INTO scan_details (scanned_ip_id, protocol, port, service, product, version, script_id, script_output)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (scanned_ip_id, protocol, port, service, product, version, script_id, script_output))
    
    # Guardar cambios y cerrar la conexión a la base de datos
    conn.commit()
    cursor.close()
    conn.close()

def scan_ports_services(target_ip, scan_name, ports='1-1024', intensity='normal'):
    # Crear un escáner de nmap
    nm = nmap.PortScanner()
    
    # Selección de intensidad de escaneo
    if intensity == 'normal':
        arguments = '-sV'
    elif intensity == 'agresivo':
        arguments = '-sV -T4'
    elif intensity == 'intenso':
        arguments = '-sV -T5'
    else:
        arguments = '-sV'
    
    print(f"Escaneando {target_ip} en los puertos {ports} con un escaneo de intensidad '{intensity}' para puertos y servicios...")
    # Escanear el objetivo
    nm.scan(target_ip, ports, arguments=arguments)

    # Crear estructura para almacenar resultados
    scan_results = []

    # Recopilar resultados
    for host in nm.all_hosts():
        host_data = {
            'host': host,
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'protocols': []
        }

        for proto in nm[host].all_protocols():
            proto_data = {
                'protocol': proto,
                'ports': []
            }

            lport = nm[host][proto].keys()
            for port in sorted(lport):
                port_data = {
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'service': nm[host][proto][port].get('name', 'N/A'),
                    'product': nm[host][proto][port].get('product', 'N/A'),
                    'version': nm[host][proto][port].get('version', 'N/A')
                }
                
                proto_data['ports'].append(port_data)
            
            host_data['protocols'].append(proto_data)

        scan_results.append(host_data)

    # Devolver los resultados del escaneo
    return scan_results

def scan_vulnerabilities(target_ip, scan_name, ports='1-1024', intensity='normal'):
    # Crear un escáner de nmap
    nm = nmap.PortScanner()
    
    # Selección de intensidad de escaneo
    if intensity == 'normal':
        arguments = '-sV --script vuln'
    elif intensity == 'agresivo':
        arguments = '-sV -T4 --script vuln'
    elif intensity == 'intenso':
        arguments = '-sV -T5 --script vuln'
    else:
        arguments = '-sV --script vuln'
    
    print(f"Escaneando {target_ip} en los puertos {ports} con un escaneo de intensidad '{intensity}' para vulnerabilidades...")
    # Escanear el objetivo
    nm.scan(target_ip, ports, arguments=arguments)

    # Crear estructura para almacenar resultados
    scan_results = []

    # Recopilar resultados
    for host in nm.all_hosts():
        host_data = {
            'host': host,
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'protocols': []
        }

        for proto in nm[host].all_protocols():
            proto_data = {
                'protocol': proto,
                'ports': []
            }

            lport = nm[host][proto].keys()
            for port in sorted(lport):
                port_data = {
                    'port': port,
                    'state': nm[host][proto][port]['state'],
                    'service': nm[host][proto][port].get('name', 'N/A'),
                    'product': nm[host][proto][port].get('product', 'N/A'),
                    'version': nm[host][proto][port].get('version', 'N/A'),
                    'scripts': []
                }
                
                if 'script' in nm[host][proto][port]:
                    for script_id, output in nm[host][proto][port]['script'].items():
                        port_data['scripts'].append({
                            'script_id': script_id,
                            'output': output.replace('\n', ' ')
                        })
                
                proto_data['ports'].append(port_data)
            
            host_data['protocols'].append(proto_data)

        scan_results.append(host_data)

    # Devolver los resultados del escaneo
    return scan_results

@app.post("/scan/ports-services")
async def scan_ports_services_api(request: ScanRequest):
    try:
        scan_results = scan_ports_services(request.target_ip, request.scan_name, request.ports, request.intensity)
        save_scan_results_to_db(request.scan_name, scan_results)
        return {"status": "success", "scan_results": scan_results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/vulnerabilities")
async def scan_vulnerabilities_api(request: ScanRequest):
    try:
        scan_results = scan_vulnerabilities(request.target_ip, request.scan_name, request.ports, request.intensity)
        save_scan_results_to_db(request.scan_name, scan_results)
        return {"status": "success", "scan_results": scan_results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(
        "LogsonMapHibrido:app",  # Nombre de tu archivo FastAPI
        host="0.0.0.0",          # Dirección del host
        port=8001,               # Puerto
        log_level="info",        # Nivel de logs
        reload=True,             # Recarga automática en desarrollo
    )
