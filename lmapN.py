import nmap
import time
import mysql.connector
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

# Pedir el tipo de escaneo
print("\nSelecciona el tipo de escaneo:")
print("1. Escaneo rápido (-T4)")
print("2. Escaneo agresivo (-T5)")
print("3. Escaneo de ping (-sn)")
print("4. Escaneo SYN (-sS)")
print("5. Escaneo completo (-sS -sV)")
escaneo_tipo = input("Introduce el número del tipo de escaneo (1-5): ")

# Asignar los argumentos del escaneo según la opción seleccionada
if escaneo_tipo == '1':
    scan_args = f'-p {puertos} -T4 -sV -A -v'
elif escaneo_tipo == '2':
    scan_args = f'-p {puertos} -T5 -sV -A -v'
elif escaneo_tipo == '3':
    scan_args = f'-sn {ip_range}'
elif escaneo_tipo == '4':
    scan_args = f'-sS -p {puertos} -T4 -sV -A -v'
elif escaneo_tipo == '5':
    scan_args = f'-sS -sV -p {puertos} -T4 -A -v'
else:
    print("Opción no válida, se usará el escaneo rápido por defecto.")
    scan_args = f'-p {puertos} -T4 -sV -A -v'

# Registrar el tiempo de inicio
start_time = time.time()

# Realizar el escaneo
print(f"Escaneando el rango de IPs {ip_range} en los puertos {puertos} con los parámetros: {scan_args}...")
nm.scan(hosts=ip_range, arguments=scan_args)

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
            service_name = port_info.get('name', 'N/A')
            service_version = port_info.get('version', 'Desconocida')
            
            # Determinar el protocolo (TCP por defecto para puertos abiertos escaneados con -sS, pero podrías tener UDP si usas -sU)
            protocol = 'TCP' if 'tcp' in nm[host] else 'UDP' if 'udp' in nm[host] else 'N/A'

            # Añadir la fila de datos a la lista
            scan_results.append([host, port_number, state, service_name, service_version, protocol])

# Mostrar los resultados en formato tabla
headers = ['IP', 'Puerto', 'Estado', 'Servicio', 'Versión', 'Protocolo']
print(f"\nResultados del escaneo en {ip_range}:")
print(tabulate(scan_results, headers=headers, tablefmt='pretty'))

# Mostrar el tiempo de análisis
print(f"\nTiempo total del análisis: {scan_time:.2f} segundos")

# Preguntar si el usuario desea guardar el escaneo
guardar = input("\n¿Deseas guardar este escaneo en la base de datos? (si/no): ").strip().lower()
if guardar == 'si':
    nombre_escaneo = input("Introduce un nombre para este escaneo: ")

    # Conectar a la base de datos MySQL
    try:
        conexion = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="dbLogson"
        )
        cursor = conexion.cursor()
        # Insertar el escaneo en la base de datos
        cursor.execute("INSERT INTO escaneos (nombre, rango_ip, puertos, tiempo_analisis) VALUES (%s, %s, %s, %s)",
                       (nombre_escaneo, ip_range, puertos, scan_time))
        escaneo_id = cursor.lastrowid  # Obtener el ID del escaneo insertado
        
        # Insertar los resultados de cada puerto escaneado
        for result in scan_results:
            cursor.execute("INSERT INTO escaneo_resultados (escaneo_id, ip, puerto, estado, servicio, version, protocolo) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                           (escaneo_id, *result))
        
        # Confirmar los cambios en la base de datos
        conexion.commit()
        print(f"\nEscaneo '{nombre_escaneo}' guardado exitosamente en la base de datos.")

    except mysql.connector.Error as err:
        print(f"Error al conectar a la base de datos: {err}")

    finally:
        # Cerrar la conexión a la base de datos
        if conexion.is_connected():
            cursor.close()
            conexion.close()