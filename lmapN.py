import nmap
import time
from tabulate import tabulate

# Crear un objeto de escaneo
nm = nmap.PortScanner()

# Pedir al usuario el rango de IPs y los puertos a escanear
ip_range = input("Introduce el rango de IPs a escanear (Ejemplo: 192.168.56.1-192.168.56.10 o 192.168.56.0/24): ")

# Pedir puertos a escanear, si se deja vacío se escanean todos los puertos
puertos = input("Introduce los puertos a escanear (Ejemplo: 22-80) o deja vacío para escanear todos: ")

# Si no se introduce un rango de puertos, escanear todos
if not puertos:
    puertos = '1-65535'

# Registrar el tiempo de inicio
start_time = time.time()

# Realizar el escaneo
print(f"Escaneando el rango de IPs {ip_range} en los puertos {puertos}...")
nm.scan(hosts=ip_range, arguments=f'-p {puertos} -T4')  # Usamos -T4 para aumentar la velocidad del escaneo

# Calcular el tiempo de análisis
end_time = time.time()
scan_time = end_time - start_time

# Crear una lista para los resultados
scan_results = []

# Mostrar los resultados
for host in nm.all_hosts():
    if 'tcp' in nm[host]:  # Asegurarnos de que hay puertos TCP abiertos
        for port in nm[host]['tcp']:
            # Recolectamos la información del puerto
            port_info = nm[host]['tcp'][port]
            port_number = port
            state = port_info['state']
            service_name = port_info.get('name', 'N/A')  # Usamos 'N/A' si el servicio no está disponible
            protocol = port_info.get('protocol', 'N/A')  # Usamos 'N/A' si el protocolo no está disponible
            service_version = port_info.get('version', 'Desconocida')  # Usamos 'Desconocida' si la versión no está disponible
            
            # Añadir la fila de datos a la lista
            scan_results.append([host, port_number, state, service_name, service_version, protocol])

# Mostrar los resultados en formato tabla
headers = ['IP', 'Puerto', 'Estado', 'Servicio', 'Versión', 'Protocolo']
print(f"\nResultados del escaneo en {ip_range}:")
print(tabulate(scan_results, headers=headers, tablefmt='pretty'))

# Mostrar el tiempo de análisis
print(f"\nTiempo total del análisis: {scan_time:.2f} segundos")