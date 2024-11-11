import sys
import socket
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit
from PyQt5.QtCore import QThread, pyqtSignal


# Diccionario de puertos comunes y sus servicios
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3389: "RDP", 3306: "MySQL",
    8080: "HTTP-alt", 139: "NetBIOS", 445: "Microsoft-DS"
}

def get_service(port):
    return COMMON_PORTS.get(port, "Desconocido")


class PortScannerThread(QThread):
    # Señal para actualizar la interfaz con los resultados
    update_signal = pyqtSignal(str)

    def __init__(self, target_ip, ports):
        super().__init__()
        self.target_ip = target_ip
        self.ports = ports

    def run(self):
        for port in self.ports:
            result = self.scan_port(self.target_ip, port)
            if result:
                # Emitir señal para actualizar la GUI
                self.update_signal.emit(result)
                # También imprimir en la consola
                print(result)

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Tiempo de espera por conexión
            result = sock.connect_ex((ip, port))

            if result == 0:
                # Si el puerto está abierto, devolver la información
                service = get_service(port)
                return f"{port:<10} {'TCP':<10} {service:<20} Abierto"
            sock.close()
        except socket.error:
            pass
        return None


class PortScannerApp(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Escaneo de Puertos')
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        self.target_ip_entry = QLineEdit(self)
        self.target_ip_entry.setPlaceholderText("Ingresa la IP objetivo")
        layout.addWidget(self.target_ip_entry)

        self.ports_entry = QLineEdit(self)
        self.ports_entry.setPlaceholderText("Ingresa los puertos (separados por comas)")
        layout.addWidget(self.ports_entry)

        self.result_text = QTextEdit(self)
        self.result_text.setPlaceholderText("Resultados del escaneo...")
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

        self.scan_button = QPushButton('Escanear', self)
        self.scan_button.clicked.connect(self.on_scan_button_click)
        layout.addWidget(self.scan_button)

        self.setLayout(layout)

        self.thread = None

    def on_scan_button_click(self):
        target_ip = self.target_ip_entry.text().strip()
        ports_input = self.ports_entry.text().strip()

        if not target_ip:
            self.result_text.append("Por favor, ingresa una IP objetivo.")
            return

        # Si no se ingresan puertos, escanear todos los puertos (1-65535)
        if not ports_input:
            ports = range(1, 65536)
        else:
            ports = ports_input.split(',')
            valid_ports = []
            for port in ports:
                port = port.strip()
                if port.isdigit():
                    valid_ports.append(int(port))
                else:
                    self.result_text.append(f"Error: '{port}' no es un puerto válido. Ignorando.")
            if not valid_ports:
                self.result_text.append("No se ingresaron puertos válidos. Escaneando todos los puertos.")
                ports = range(1, 65536)
            else:
                ports = valid_ports

        # Mostrar encabezado de los resultados
        self.result_text.append(f"\n{'Puerto':<10} {'Protocolo':<10} {'Servicio':<20} {'Estado'}")

        # Iniciar el hilo de escaneo
        self.thread = PortScannerThread(target_ip, ports)
        self.thread.update_signal.connect(lambda result: self.result_text.append(result))
        self.thread.finished.connect(self.on_thread_finished)

        self.thread.start()

    def on_thread_finished(self):
        self.result_text.append("\nEscaneo completado.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PortScannerApp()
    window.show()
    sys.exit(app.exec_())
