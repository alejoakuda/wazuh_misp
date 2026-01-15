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

def log_error(msg):
    """Escribe en el log solo cuando algo falla"""
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now()} MISP-ERROR: {msg}\n")

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

def request_misp_info(hashes, apikey, url):
    headers = {
        'Authorization': apikey,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Sanitización
    valid_hashes = [h for h in hashes.values() if re.match(r"^[a-fA-F0-9]{32,64}$", str(h))]
    
    payload = {
        "returnFormat": "json",
        "value": valid_hashes,
        "searchall": 1
    }

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
                else:
                    # Hash limpio. No log.
                    output['misp'] = {'found': 0, 'error': 'Hash no encontrado'}
                    return output
            else:
                log_error(f"Error API MISP (Intento {i+1}). Status: {response.status_code} - Msg: {response.text}")

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if i == RETRIES:
                log_error(f"Fallo critico de red tras reintentos: {str(e)} - URL: {url}")
                output['misp'] = {'found': 0, 'error': 'Fallo de conexion'}
            continue
        except Exception as e:
            log_error(f"Error inesperado en consulta: {str(e)}")
            output['misp'] = {'found': 0, 'error': 'Error interno script'}
            break

    return output

def main(args):
    try:
        if len(args) < 4:
            log_error(f"Argumentos insuficientes. Recibidos: {len(args)}")
            sys.exit(1)

        alert_file_location = args[1]
        apikey = args[2]
        hook_url = args[3]

        with open(alert_file_location) as f:
            alert_json = json.load(f)

        syscheck = alert_json.get('syscheck', {})
        hashes = {h: syscheck.get(f'{h}_after') for h in ['md5', 'sha1', 'sha256'] if syscheck.get(f'{h}_after')}

        if not hashes:
            return

        msg = request_misp_info(hashes, apikey, hook_url)
        send_msg(msg, alert_json.get('agent'))

    except Exception as e:
        log_error(f"Error critico en main: {str(e)}")

def send_msg(msg, agent=None):
    if not agent or agent['id'] == '000':
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
        log_error(f"Error de socket (no se pudo enviar alerta a Wazuh): {str(e)}")

if __name__ == '__main__':
    main(sys.argv)
