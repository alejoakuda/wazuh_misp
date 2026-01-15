#!/usr/bin/env python3
import json
import os
import sys
import requests
from socket import AF_UNIX, SOCK_DGRAM, socket
from datetime import datetime

# Variables de entorno Wazuh
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

def debug(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now()} MISP-DEBUG: {msg}\n")

def request_misp_info(hash_value, is_sha256, apikey, url):
    headers = {
        'Authorization': apikey,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Optimizamos el payload para restSearch
    payload = {
        "returnFormat": "json",
        "value": hash_value,
	"searchall": 1
    }
    debug(f"Buscando Hash: {hash_value} en URL: {url}")

    output = {'misp': {}, 'integration': 'misp'}
    
    try:
        # Importante: Usamos POST y verify=False
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            # La respuesta de restSearch suele venir en data['response']['Attribute']
            # o directamente en data['Attribute']
            inner_data = data.get('response', data)
            attributes = inner_data.get('Attribute', [])

            if attributes and len(attributes) > 0:
                attr = attributes[0]
                output['misp']['found'] = 1
                output['misp']['value'] = attr.get('value')
                output['misp']['event_id'] = attr.get('event_id')
                output['misp']['info'] = "Amenaza detectada"
            else:
                output['misp']['found'] = 0
                output['misp']['error'] = "Hash no encontrado en la base de datos"
        else:
            output['misp']['found'] = 0
            output['misp']['error'] = f"MISP respondio con error: {response.status_code}"
            
    except Exception as e:
        output['misp']['found'] = 0
        output['misp']['error'] = f"Fallo de red: {str(e)}"
    
    return output

def main(args):
    try:
        if len(args) < 4:
            debug("Error: Argumentos insuficientes")
            sys.exit(1)

        alert_file_location = args[1]
        apikey = args[2]
        hook_url = args[3]

        with open(alert_file_location) as f:
            alert_json = json.load(f)

        syscheck = alert_json.get('syscheck', {})
        sha256 = syscheck.get('sha256_after')
        md5 = syscheck.get('md5_after')
        
        hash_to_check = sha256 if sha256 else md5
        is_sha256 = True if sha256 else False

        if not hash_to_check:
            return

        # LLAMADA CORREGIDA: 4 argumentos pasando por aqui
        msg = request_misp_info(hash_to_check, is_sha256, apikey, hook_url)
        
        send_msg(msg, alert_json.get('agent'))

    except Exception as e:
        debug(f"Error en main: {str(e)}")

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
    except Exception:
        try:
            from socket import SOCK_STREAM
            sock = socket(AF_UNIX, SOCK_STREAM)
            sock.connect(SOCKET_ADDR)
            sock.send(string.encode())
            sock.close()
        except Exception as e:
            debug(f"Error de socket: {str(e)}")

if __name__ == '__main__':
    main(sys.argv)
