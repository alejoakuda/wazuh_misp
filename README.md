---

* **Autor:** Alejandro Fernandes
* **Alias:** Vernizus
* **Rol:** Cybersecurity Analyst
* **Especialidad:** Infraestructura y Optimización de SOC con herramientas opensource (Wazuh & MISP)

---
### Preparación de Wazuh

Debes copiar los Scripts:

1. custom-misp_hashes
2. custom-misp_hashes.py

Dentro de la carpeta de Wazuh manager:

> /var/ossec/integration/

Puedes editar el script de python para ajustar la confianza en el certificado de MISP y/o los tiempos y veces de reintento 

### Reglas para la integración

En el archivo `misp_rules.xml` estan las reglas necesarias para que se activen las alertar o tener infromación al respecto de la integración en caso de que falle.

Copia el archivo y ponlo en:
> /var/ossec/rules

En caso de que no veas las alertas, pega el contenido al final del archivo `Local_rules.xml` en la misma ruta.

### Archivo de configuración ossec.conf

Pega el siguiente bloque fuera de la sección `<ossec_conf>` de tu Manager:
Si lo pegaras dentro asegurate de quitarle las etiquetas `<ossec_conf>`

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
