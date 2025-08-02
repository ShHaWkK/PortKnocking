#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Serveur de démonstration pour un mécanisme de port‑knocking utilisant le protocole UDP.

Ce serveur écoute simultanément sur plusieurs ports UDP définis dans une séquence.
Lorsqu'il reçoit la bonne combinaison de frappes (paquets UDP) de la part d'une même
adresse IP dans le bon ordre et dans un délai imparti, il ouvre temporairement
un port TCP de service pour cette adresse IP. Ce port permet ensuite au client
d'établir une connexion réelle et d'échanger un message.
"""
import socket
import threading
import time
from typing import Dict, List, Tuple

class UDPKnockServer:
    def __init__(self, sequence: List[int], service_port: int, seq_timeout: float = 5.0, service_timeout: float = 30.0) -> None:
        self.sequence = sequence
        self.service_port = service_port
        self.seq_timeout = seq_timeout
        self.service_timeout = service_timeout
        self.states: Dict[str, Tuple[int, float]] = {}
        self.lock = threading.Lock()

    def start(self) -> None:
        sockets: List[socket.socket] = []
        for port in self.sequence:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('', port))
            sockets.append(sock)
            print(f"[INFO] Écoute UDP sur le port {port}")
        for idx, sock in enumerate(sockets):
            thread = threading.Thread(target=self._listen_knock, args=(sock, idx), daemon=True)
            thread.start()
        print("[INFO] Serveur UDPKnock prêt. Séquence: {}".format(self.sequence))
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[INFO] Arrêt du serveur")

    def _listen_knock(self, sock: socket.socket, port_index: int) -> None:
        while True:
            data, addr = sock.recvfrom(1024)
            client_ip, _ = addr
            now = time.time()
            with self.lock:
                state = self.states.get(client_ip, (0, now))
                expected_index, last_time = state
                if now - last_time > self.seq_timeout:
                    expected_index = 0
                if port_index == expected_index:
                    expected_index += 1
                    if expected_index == len(self.sequence):
                        print(f"[INFO] Séquence complète reçue de {client_ip} ! Ouverture du port {self.service_port}")
                        threading.Thread(target=self._open_service_port, args=(client_ip,), daemon=True).start()
                        expected_index = 0
                else:
                    expected_index = 0
                self.states[client_ip] = (expected_index, now)

    def _open_service_port(self, client_ip: str) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(('', self.service_port))
            srv.listen(1)
            print(f"[INFO] Service TCP ouvert sur le port {self.service_port} pour {client_ip}")
            srv.settimeout(self.service_timeout)
            start_time = time.time()
            try:
                while time.time() - start_time < self.service_timeout:
                    try:
                        conn, addr = srv.accept()
                    except socket.timeout:
                        continue
                    if addr[0] != client_ip:
                        conn.close()
                        continue
                    with conn:
                        message = "Bonjour, vous avez réussi la séquence UDP !"
                        conn.sendall(message.encode('utf-8'))
                        print(f"[INFO] Client {addr[0]} s'est connecté au service." )
                        break
            finally:
                print(f"[INFO] Fermeture du port de service {self.service_port}")

if __name__ == "__main__":
    SEQUENCE = [12001, 12002, 12003]
    SERVICE_PORT = 2223
    server = UDPKnockServer(SEQUENCE, SERVICE_PORT)
    server.start()
