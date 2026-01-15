# Wazuh-MISP Integration
Integración personalizada para consultar hashes de Syscheck en MISP.


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
