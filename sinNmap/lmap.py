import socket
import threading

# Diccionario de puertos comunes y sus servicios
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3389: "RDP", 3306: "MySQL",
    8080: "HTTP-alt", 21: "FTP", 139: "NetBIOS", 445: "Microsoft-DS"
}

# Función para obtener el servicio asociado al puerto
def get_service(port):
    return COMMON_PORTS.get(port, "Desconocido")

# Función para escanear un puerto
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Tiempo de espera por conexión
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            # Obtener el protocolo (por defecto TCP)
            protocol = "TCP"
            service = get_service(port)
            # Mostrar los resultados en formato tabla
            print(f"{port:<10} {protocol:<10} {service:<20} Abierto")
        sock.close()
    except socket.error:
        pass

# Función para realizar el escaneo en varios puertos
def scan_ports():
    target_ip = input("Ingresa la IP objetivo: ")
    ports_input = input("Ingresa los puertos (separados por comas), vacío para escanear todos: ")

    # Si no se ingresa ningún puerto, se escanearán todos los puertos (1-65535)
    if not ports_input:
        ports = range(1, 65536)
    else:
        ports = ports_input.split(',')
        ports = [int(port.strip()) for port in ports]  # Convertir a lista de puertos

    # Insertar encabezados de la tabla
    print(f"\n{'Puerto':<10} {'Protocolo':<10} {'Servicio':<20} {'Estado'}")

    threads = []

    # Crear y ejecutar los hilos para cada puerto
    for port in ports:
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(t)
        t.start()

    # Esperar a que todos los hilos terminen
    for t in threads:
        t.join()

# Iniciar el escaneo
if __name__ == "__main__":
    scan_ports()
