use anyhow::{Context, Result};
use quick_xml::{Reader, Writer, events::Event};
use std::io::Cursor;
use tracing::{info, warn};

/// Security configuration for XML processing
#[derive(Debug, Clone)]
pub struct XmlSecurityConfig {
    /// Maximum XML document size in bytes
    pub max_document_size: usize,
    /// Maximum nesting depth
    pub max_depth: usize,
    /// Maximum number of attributes per element
    pub max_attributes: usize,
    /// Maximum attribute value length
    pub max_attribute_length: usize,
    /// Allowed element names (whitelist)
    pub allowed_elements: Vec<String>,
    /// Disallow external entities
    pub disallow_external_entities: bool,
}

impl Default for XmlSecurityConfig {
    fn default() -> Self {
        Self {
            max_document_size: 1024 * 1024, // 1MB
            max_depth: 50,
            max_attributes: 20,
            max_attribute_length: 1024,
            allowed_elements: vec![
                // BOINC protocol elements
                "scheduler_request".to_string(),
                "scheduler_reply".to_string(),
                "platform".to_string(),
                "app".to_string(),
                "app_version".to_string(),
                "user_info".to_string(),
                "host_info".to_string(),
                "work_req".to_string(),
                "result".to_string(),
                "workunit".to_string(),
                "file_info".to_string(),
                "file_ref".to_string(),
                "authenticator".to_string(),
                "hostid".to_string(),
                "rpc_seqno".to_string(),
                "userid".to_string(),
                "teamid".to_string(),
                "venue".to_string(),
                "name".to_string(),
                "version".to_string(),
                "cpu_time".to_string(),
                "credit".to_string(),
                "flops".to_string(),
                "memory".to_string(),
                "disk".to_string(),
                "network".to_string(),
                // Add more as needed for BOINC protocol
            ],
            disallow_external_entities: true,
        }
    }
}

/// Secure XML validator and sanitizer for BOINC communications
#[derive(Clone)]
pub struct SecureXmlValidator {
    config: XmlSecurityConfig,
}

impl SecureXmlValidator {
    /// Create a new secure XML validator
    pub fn new(config: XmlSecurityConfig) -> Self {
        Self { config }
    }

    /// Create with default BOINC-safe configuration
    pub fn new_boinc_safe() -> Self {
        Self::new(XmlSecurityConfig::default())
    }

    /// Validate and sanitize XML input
    pub fn validate_and_sanitize(&self, xml_input: &str) -> Result<String> {
        // Size validation
        if xml_input.len() > self.config.max_document_size {
            return Err(anyhow::anyhow!(
                "XML document too large: {} bytes (max: {})",
                xml_input.len(),
                self.config.max_document_size
            ));
        }

        // Check for suspicious patterns
        self.check_suspicious_patterns(xml_input)?;

        // Parse and validate structure
        let sanitized = self.parse_and_sanitize(xml_input)?;

        info!(
            "XML validation successful: {} -> {} bytes",
            xml_input.len(),
            sanitized.len()
        );

        Ok(sanitized)
    }

    /// Check for suspicious XML patterns that could indicate attacks
    fn check_suspicious_patterns(&self, xml: &str) -> Result<()> {
        // Check for external entity references
        if self.config.disallow_external_entities && (xml.contains("<!ENTITY") || xml.contains("&"))
        {
            // More detailed check for external entities
            if xml.contains("SYSTEM") || xml.contains("PUBLIC") {
                return Err(anyhow::anyhow!(
                    "External entity references are not allowed"
                ));
            }

            // Check for entity expansion attacks
            let entity_count = xml.matches("&").count();
            if entity_count > 10 {
                warn!(
                    "High number of entity references detected: {}",
                    entity_count
                );
            }
        }

        // Check for DOCTYPE declarations (potential XXE)
        if xml.contains("<!DOCTYPE") {
            return Err(anyhow::anyhow!(
                "DOCTYPE declarations are not allowed for security"
            ));
        }

        // Check for processing instructions that could be dangerous
        if xml.contains("<?") && !xml.starts_with("<?xml") {
            warn!("Processing instruction detected in XML");
        }

        // Check for CDATA sections (can hide malicious content)
        let cdata_count = xml.matches("<![CDATA[").count();
        if cdata_count > 5 {
            warn!("High number of CDATA sections: {}", cdata_count);
        }

        Ok(())
    }

    /// Parse XML and sanitize content
    fn parse_and_sanitize(&self, xml_input: &str) -> Result<String> {
        let mut reader = Reader::from_str(xml_input);

        let mut writer = Writer::new(Cursor::new(Vec::new()));
        let mut buf = Vec::new();
        let mut depth = 0;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    depth += 1;

                    // Check depth limit
                    if depth > self.config.max_depth {
                        return Err(anyhow::anyhow!(
                            "XML nesting too deep: {} (max: {})",
                            depth,
                            self.config.max_depth
                        ));
                    }

                    // Validate element name
                    let name_ref = e.name();
                    let element_name = std::str::from_utf8(name_ref.as_ref())
                        .context("Invalid UTF-8 in element name")?;

                    if !self.is_allowed_element(element_name) {
                        return Err(anyhow::anyhow!("Element '{}' is not allowed", element_name));
                    }

                    // Validate attributes
                    self.validate_attributes(e)?;

                    // Write sanitized element
                    writer.write_event(Event::Start(e.clone()))?;
                }
                Ok(Event::End(ref e)) => {
                    depth -= 1;
                    writer.write_event(Event::End(e.clone()))?;
                }
                Ok(Event::Text(ref e)) => {
                    // Sanitize text content
                    let text = std::str::from_utf8(e).context("Failed to read text")?;
                    let sanitized_text = self.sanitize_text(text)?;

                    writer.write_event(Event::Text(quick_xml::events::BytesText::new(
                        &sanitized_text,
                    )))?;
                }
                Ok(Event::Empty(ref e)) => {
                    // Validate empty element
                    let name_ref = e.name();
                    let element_name = std::str::from_utf8(name_ref.as_ref())
                        .context("Invalid UTF-8 in element name")?;

                    if !self.is_allowed_element(element_name) {
                        return Err(anyhow::anyhow!("Element '{}' is not allowed", element_name));
                    }

                    self.validate_attributes(e)?;
                    writer.write_event(Event::Empty(e.clone()))?;
                }
                Ok(Event::Comment(_)) => {
                    // Skip comments for security
                    info!("Stripped XML comment for security");
                }
                Ok(Event::CData(ref e)) => {
                    // Validate CDATA content
                    let cdata_text = std::str::from_utf8(e).context("Invalid UTF-8 in CDATA")?;
                    let sanitized = self.sanitize_text(cdata_text)?;

                    writer
                        .write_event(Event::Text(quick_xml::events::BytesText::new(&sanitized)))?;
                }
                Ok(Event::Decl(ref e)) => {
                    // Keep XML declaration
                    writer.write_event(Event::Decl(e.clone()))?;
                }
                Ok(Event::PI(_)) => {
                    // Skip processing instructions for security
                    info!("Stripped processing instruction for security");
                }
                Ok(Event::DocType(_)) => {
                    // Reject DOCTYPE for security
                    return Err(anyhow::anyhow!("DOCTYPE declarations are not allowed"));
                }
                Ok(Event::Eof) => break,
                Ok(_) => {
                    // Handle other event types
                    info!("Skipping unsupported XML event type");
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("XML parsing error: {}", e));
                }
            }
            buf.clear();
        }

        let result = writer.into_inner().into_inner();
        String::from_utf8(result).context("Generated XML contains invalid UTF-8")
    }

    /// Check if element name is allowed
    fn is_allowed_element(&self, name: &str) -> bool {
        self.config
            .allowed_elements
            .iter()
            .any(|allowed| allowed == name || name.starts_with(&format!("{}.", allowed)))
    }

    /// Validate element attributes
    fn validate_attributes(&self, element: &quick_xml::events::BytesStart) -> Result<()> {
        let attr_count = element.attributes().count();
        if attr_count > self.config.max_attributes {
            return Err(anyhow::anyhow!(
                "Too many attributes: {} (max: {})",
                attr_count,
                self.config.max_attributes
            ));
        }

        for attr in element.attributes() {
            let attr = attr.context("Failed to parse attribute")?;
            let value = attr.value;

            if value.len() > self.config.max_attribute_length {
                return Err(anyhow::anyhow!(
                    "Attribute value too long: {} bytes (max: {})",
                    value.len(),
                    self.config.max_attribute_length
                ));
            }
        }

        Ok(())
    }

    /// Sanitize text content
    fn sanitize_text(&self, text: &str) -> Result<String> {
        // Remove control characters except newline, tab, carriage return
        let sanitized: String = text
            .chars()
            .filter(|&c| {
                c == '\n' || c == '\t' || c == '\r' || (c >= ' ' && c != '\x7F') || (c > '\x7F') // Allow Unicode
            })
            .collect();

        // Basic length check
        if sanitized.len() > 10000 {
            warn!("Very long text content: {} characters", sanitized.len());
        }

        Ok(sanitized)
    }
}

/// Quick validation for basic XML well-formedness
pub fn validate_xml_wellformed(xml: &str) -> Result<()> {
    let mut reader = Reader::from_str(xml);

    let mut buf = Vec::new();
    let mut depth = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(_)) => {
                depth += 1;
                if depth > 100 {
                    return Err(anyhow::anyhow!("XML too deeply nested"));
                }
            }
            Ok(Event::End(_)) => {
                depth -= 1;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {
                // Handle other events
            }
            Err(e) => {
                return Err(anyhow::anyhow!("XML not well-formed: {}", e));
            }
        }
        buf.clear();
    }

    if depth != 0 {
        return Err(anyhow::anyhow!("Unbalanced XML elements"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_validation() {
        let validator = SecureXmlValidator::new_boinc_safe();

        let valid_xml = r#"<?xml version="1.0"?>
<scheduler_request>
    <authenticator>test_auth</authenticator>
    <hostid>12345</hostid>
</scheduler_request>"#;

        assert!(validator.validate_and_sanitize(valid_xml).is_ok());
    }

    #[test]
    fn test_external_entity_rejection() {
        let validator = SecureXmlValidator::new_boinc_safe();

        let malicious_xml = r#"<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<scheduler_request>&xxe;</scheduler_request>"#;

        assert!(validator.validate_and_sanitize(malicious_xml).is_err());
    }

    #[test]
    fn test_disallowed_element() {
        let validator = SecureXmlValidator::new_boinc_safe();

        let bad_xml = r#"<?xml version="1.0"?>
<malicious_element>
    <authenticator>test</authenticator>
</malicious_element>"#;

        assert!(validator.validate_and_sanitize(bad_xml).is_err());
    }
}
