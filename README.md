* **Autor:** Alejandro Fernandes
* **Alias:** Vernizus
* **Rol:** Cybersecurity Analyst
* **Especialidad:** Infraestructura y Optimización de SOC con herramientas opensource (Wazuh & MISP)

### Preparación de Wazuh

Debes copiar los Scripts:

1. custom-misp_hashes
2. custom-misp_hashes.py

Dentro de la carpeta de Wazuh manager:

> /var/ossec/integrations

Puedes editar el script de python para ajustar:
1. confianza en el certificado de MISP
2. Tiempos y veces de reintento de conexión con MISP. 

### Wazuh Integrator
Debemos darle permisos a los archivos para que Wazuh Integrator pueda usarlos.

```bash
# Dar permisos al integrador
chmod 750 /var/ossec/integrations/custom-misp_hashes*
chown root:wazuh /var/ossec/integrations/custom-misp_hashes*
```

### Reglas para la integración
En el archivo `misp_rules.xml` estan las reglas necesarias para que se activen las alertar o tener infromación al respecto de la integración en caso de que falle.

Copia el archivo y ponlo en:
> /var/ossec/rules

En caso de que no veas las alertas, pega el contenido al final del archivo `local_rules.xml` en la misma ruta.

### Archivo de configuración ossec.conf

Pega el siguiente bloque fuera de la sección `<ossec_conf>` de tu Manager.
Si lo pones dentro asegurate de quitarle las etiquetas `<ossec_conf>`.

```xml
<ossec_conf>
  <!-- Integracion con MISP -->
  <integration>
    <name>custom-misp_hashes</name>
    <rule_id>554,550</rule_id>
    <hook_url>https://url:puerto/attributes/restSearch</hook_url>
    <api_key></api_key>
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>
</ossec_conf>
```

### Reiniciamos 
 
```bash
# Comprobación de configuración del manager
/var/ossec/bin/wazuh-analysisd -t
```

```bash
# Reinicio del servicio
systemctl restart wazuh-manager
```

### Prueba de Ejecución manual del Script de python 
(debug en caso de fallo)
Para verificar que el entorno de Python de Wazuh reconoce los scripts y las dependencias (como requests), realizamos una prueba de carga manual:

```bash
# Prueba de ejecución manual del script
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-misp_hashes.py
```

Explicación: Este comando usa el binario interno de Python de Wazuh. Si el script inicia y solo te da un error de "falta de argumentos" (porque no le pasamos un evento real), significa que el binario está bien ubicado y tiene los permisos correctos.
