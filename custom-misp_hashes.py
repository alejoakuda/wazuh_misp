#!/usr/bin/env python3

# Wazuh - MISP Integration Script
# Autor: Alejandro Fernandes aka Vernizus

import json
import os
import sys
import requests
import re
from socket import AF_UNIX, SOCK_DGRAM, socket
from datetime import datetime

# ==========================================
# CONFIGURACIÓN
# ==========================================
TIMEOUT = 10
RETRIES = 2
VERIFY_SSL = False   # Cambiar a True si tienes certificados válidos en MISP
SOURCE_TAG = "Wazuh-SOC"
# ==========================================

# Variables de entorno Wazuh
requests.packages.urllib3.disable_warnings()
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

# --- Funcion para registrar los errores
def log_error(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now()} MISP-ERROR: {msg}\n")

# --- Funcion de Avistamientos
def push_misp_sighting(url, apikey, attribute_id):
    try:
        sighting_url = f"{url.split('/attributes')[0]}/sightings/add"
        payload = {"id": attribute_id, "source": SOURCE_TAG}
        r = requests.post(sighting_url, headers={'Authorization': apikey},
                          json=payload, verify=VERIFY_SSL, timeout=TIMEOUT)
        if r.status_code != 200:
            log_error(f"Sighting fallido. Atributo: {attribute_id} - HTTP {r.status_code}: {r.text}")
    except Exception as e:
        log_error(f"Excepcion en sighting: {str(e)}")

# --- Funcion para consultar a MISP
def request_misp_info(hashes, apikey, url):
    headers = {
        'Authorization': apikey,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    # --- Sanitizacion
    valid_hashes = [h for h in hashes.values() if re.match(r"^[a-fA-F0-9]{32,64}$", str(h))]
    
    payload = {
        "returnFormat": "json",
        "value": valid_hashes,
        "searchall": 1
    }

    # --- Estructura base que siempre debe volver a Wazuh
    output = {'misp': {}, 'integration': 'misp'}

    for i in range(RETRIES + 1):
        try:
            response = requests.post(url, headers=headers, json=payload,
                                     verify=VERIFY_SSL, timeout=TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                inner_data = data.get('response', data)
                attributes = inner_data.get('Attribute', [])

                if attributes:
                    attr = attributes[0]
                    event_id = attr.get('event_id')
                    output['misp'] = {
                        'found': 1,
                        'value': attr.get('value'),
                        'event_id': event_id,
                        'info': attr.get('Event', {}).get('info', 'Amenaza detectada'),
                        'permalink': f"{url.split('/attributes')[0]}/events/view/{event_id}"
                    }
                    push_misp_sighting(url, apikey, attr.get('id'))
                    return output
	    # --- Si no hay coincidencia, no loguea ---
                else:
                    output['misp'] = {'found': 0, 'error': 'Hash no encontrado'}
                    return output

            # --- Si hay error de API (403, 500, etc.) ---
            else:
                error_msg = f"Error API MISP: {response.status_code}"
                log_error(f"{error_msg} - Msg: {response.text}")

                # Permite reintentos, si el último falla, cae aqui
                # Y Activa regla 100804
                output['misp'] = {'found': 0, 'error': 'Error API', 'http_code': response.status_code}

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if i == RETRIES:
                log_error(f"Fallo critico de red: {str(e)}")
                output['misp'] = {'found': 0, 'error': 'Error API', 'details': 'Fallo de conexion'}
            continue
        except Exception as e:
            log_error(f"Error inesperado: {str(e)}")
            output['misp'] = {'found': 0, 'error': 'Error API', 'details': 'Error interno script'}
            break

    return output

def main(args):
    try:
        # --- Validar argumentos ---
        if len(args) < 4:
            log_error(f"Argumentos insuficientes. Recibidos: {len(args)}")
            sys.exit(1)

        alert_file_location = args[1]
        apikey = args[2]
        hook_url = args[3]

        # --- Leer alerta original ---
        with open(alert_file_location) as f:
            alert_json = json.load(f)

        # --- Extraer contexto local (Agente y Syscheck) ---
        agent_info = alert_json.get('agent', {})
        syscheck = alert_json.get('syscheck', {})
        
        local_context = {
            'path': syscheck.get('path', 'unknown'),
            'source_rule': alert_json.get('rule', {}).get('id', 'unknown'),
            'agent_id': agent_info.get('id'),
            'agent_name': agent_info.get('name'),
            'agent_ip': agent_info.get('ip', 'any')
        }

        # --- Extraer hashes para la consulta externa ---
        hashes = {h: syscheck.get(f'{h}_after') for h in ['md5', 'sha1', 'sha256'] if syscheck.get(f'{h}_after')}

        if not hashes:
            return

        # --- Consultar a MISP (Manteniendo Privacidad) ---
        msg = request_misp_info(hashes, apikey, hook_url)

        # --- INYECCIÓN DE CONTEXTO ---
        # Añadimos los datos locales al JSON que vuelve a Wazuh
        msg['misp']['local_path'] = local_context['path']
        msg['misp']['source_rule'] = local_context['source_rule']
        msg['misp']['agent_id'] = local_context['agent_id']
        msg['misp']['agent_name'] = local_context['agent_name']
        msg['misp']['agent_ip'] = local_context['agent_ip']

        # --- Resultado ---
        # Enviamos el paquete completo
        send_msg(msg, agent_info)

    except Exception as e:
        log_error(f"Error critico en main: {str(e)}")

# --- Funcion para comunicar a Wazuh la respuesta
def send_msg(msg, agent=None):
    if not agent or agent['id'] == '000':
        # Si la alerta se originó en el manager o no hay agente
        string = '1:misp:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any')
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->misp:{1}'.format(location, json.dumps(msg))

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        log_error(f"Error de socket: {str(e)}")

if __name__ == '__main__':
    main(sys.argv)
