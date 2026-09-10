# SIEM Integration

Delivery is disabled by default. Configuration is read from server environment variables, not browser input. The application does not automatically load .env files.

## Splunk

Set SIEM_MODE=splunk, SPLUNK_HEC_URL=https://your-collector:8088/services/collector/event and SPLUNK_HEC_TOKEN to a restricted collector token. Never commit the token. HTTPS verification is mandatory; redirects are not followed. Use REQUESTS_CA_BUNDLE for an organization-managed CA bundle if required; do not disable certificate verification.

Open a case and select Send case metadata. The record contains case ID, original-email hash, score, review priority, authentication statuses, finding names and fixture status. It excludes email bodies, subject, addresses, URL values, and attachments. HEC code 0 means accepted, not proven indexed. Indexer acknowledgment is not implemented. Search Splunk for the event_id to confirm indexing. If a request times out, check the collector before retrying; retries use the same event ID but the collector must deduplicate if necessary.

Reference: https://help.splunk.com/en?resourceId=Splunk_Data_UsetheHTTPEventCollector

## Wazuh

Set SIEM_MODE=wazuh and WAZUH_LOG_PATH to an absolute path in an existing, restricted directory. Configure the Wazuh agent on the application host to collect this newline-delimited JSON file. Example configuration, replacing the path with the actual one:

```xml
<localfile>
  <location>/data/email-siem.jsonl</location>
  <log_format>json</log_format>
</localfile>
```

Example manager rule for identifying these records:

```xml
<group name="email_forensics,">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="integration">^email_threat_detection$</field>
    <description>Email threat analysis metadata</description>
  </rule>
  <rule id="100101" level="10">
    <if_sid>100100</if_sid>
    <field name="review_priority">^urgent$</field>
    <description>Email analysis requires urgent review</description>
  </rule>
</group>
```

Review rule IDs for conflicts and validate with wazuh-logtest before enabling them. The app reports written only after flushing the local file; this does not establish Wazuh server ingestion. Administrator rotation is required at the 10 MiB local cap. Collector logs have their own retention and are not removed when browser-session evidence expires.

Reference: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html

## CEF Export

Every case can export a minimal CEF record through its CEF button or /api/cases/{id}/export/cef. CEF export is not delivery. Case data and SIEM delivery attempts remain session-scoped; delivery receipts are appended to the evidence event chain without modifying the original report.

## Verification Scope

Automated tests cover disabled mode, session isolation, payload minimization, bad configuration, redirects, failed acknowledgments, timeout uncertainty, local Wazuh log writing, and a real HTTPS exchange with a mock HEC using certificate verification. Neither a live Splunk index nor a Wazuh server has been supplied. Their end-to-end ingestion remains unverified.
