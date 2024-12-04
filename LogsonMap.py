import nmap
import json
import mysql.connector
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# Configuración de la base de datos
DB_CONFIG = {
    'user': 'root',
    'password': '',
    'host': 'localhost',
    'database': 'db_logson'
}

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

def export_to_csv(scan_results, filename="nmap_scan_report.csv"):
    flattened_results = []

    for host_data in scan_results:
        host = host_data['host']
        hostname = host_data['hostname']
        state = host_data['state']

        for proto_data in host_data['protocols']:
            protocol = proto_data['protocol']

            for port_data in proto_data['ports']:
                flattened_results.append({
                    'Host': host,
                    'Hostname': hostname,
                    'State': state,
                    'Protocol': protocol,
                    'Port': port_data['port'],
                    'Service': port_data['service'],
                    'Product': port_data['product'],
                    'Version': port_data['version'],
                    'Script ID': port_data.get('script_id', 'N/A'),
                    'Script Output': port_data.get('script_output', 'N/A')
                })

    df = pd.DataFrame(flattened_results)
    df.to_csv(filename, index=False)
    print(f"Informe guardado en {filename}")

def generate_pdf_report(scan_results, filename="nmap_scan_report.pdf"):
    # Crear el documento PDF
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Título del informe
    elements.append(Paragraph("Reporte de Escaneo Nmap", styles['Title']))
    elements.append(Spacer(1, 12))

    # Generar los datos del informe
    for host_data in scan_results:
        elements.append(Paragraph(f"Host: {host_data['host']} ({host_data['hostname']})", styles['Heading2']))
        elements.append(Paragraph(f"Estado: {host_data['state']}", styles['Normal']))
        elements.append(Spacer(1, 12))

        for proto_data in host_data['protocols']:
            elements.append(Paragraph(f"Protocolo: {proto_data['protocol']}", styles['Heading3']))
            data = [["Puerto", "Estado", "Servicio", "Producto", "Versión"]]

            for port_data in proto_data['ports']:
                data.append([
                    port_data['port'],
                    port_data['state'],
                    port_data['service'],
                    port_data['product'],
                    port_data['version']
                ])

            # Crear tabla estilizada
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 12))

    # Construir el PDF
    doc.build(elements)
    print(f"Informe PDF guardado en {filename}")

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
    try:
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

        # Convertir los resultados a JSON
        scan_results_json = json.dumps(scan_results, indent=4)
        print(scan_results_json)

        # Guardar resultados en la base de datos
        save_scan_results_to_db(scan_name, scan_results)

        # Generar informes
        export_to_csv(scan_results)
        generate_pdf_report(scan_results)

    except Exception as e:
        print(f"Error al escanear: {e}")

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
    try:
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

        # Convertir los resultados a JSON
        scan_results_json = json.dumps(scan_results, indent=4)
        print(scan_results_json)

        # Guardar resultados en la base de datos
        save_scan_results_to_db(scan_name, scan_results)

        # Generar informes
        export_to_csv(scan_results)
        generate_pdf_report(scan_results)

    except Exception as e:
        print(f"Error al escanear: {e}")

if __name__ == "__main__":
    # Definir la IP del objetivo
    target_ip = input("Introduce la IP o el rango a escanear: ")
    scan_name = input("Introduce un nombre para el escaneo: ")
    # Opcionalmente puedes cambiar el rango de puertos
    ports = input("Introduce el rango de puertos (por defecto 1-1024): ") or '1-1024'
    
    # Seleccionar el nivel de intensidad
    print("\nSeleccione la intensidad del escaneo:")
    print("1. Normal (por defecto)")
    print("2. Agresivo")
    print("3. Intenso")
    intensity_choice = input("Seleccione una opción (1-3): ")
    
    if intensity_choice == '2':
        intensity = 'agresivo'
    elif intensity_choice == '3':
        intensity = 'intenso'
    else:
        intensity = 'normal'
    
    # Seleccionar tipo de escaneo
    print("\nSeleccione el tipo de escaneo:")
    print("1. Puertos y servicios")
    print("2. Vulnerabilidades")
    scan_type_choice = input("Seleccione una opción (1-2): ")

    if scan_type_choice == '2':
        scan_vulnerabilities(target_ip, scan_name, ports, intensity)
    else:
        scan_ports_services(target_ip, scan_name, ports, intensity)
