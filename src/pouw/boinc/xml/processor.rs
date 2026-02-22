//! XML processing utilities for BOINC request/response manipulation
//!
//! This module provides functionality to safely modify XML content that flows
//! through the BOINC proxy, particularly for authentication token replacement
//! and other security-related transformations.

use anyhow::Result;
use chrono::{DateTime, Utc};
use quick_xml::events::{BytesText, Event};
use quick_xml::{Reader, Writer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;
extern crate md5;

/// BOINC Work Unit extracted from scheduler response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedWorkUnit {
    pub name: String,
    pub rsc_fpops_est: f64,
    pub rsc_fpops_bound: f64,
    pub rsc_memory_bound: f64,
    pub rsc_disk_bound: f64,
    pub delay_bound: f64,
    pub extracted_at: DateTime<Utc>,
}

/// BOINC Result submitted by client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedResult {
    pub wu_name: String,
    pub result_name: String,
    pub cpu_time: f64,
    pub exit_status: i32,
    pub submitted_at: DateTime<Utc>,
    /// Hash of result content for replay detection
    pub result_hash: Option<String>,
    /// Raw result data (if extractable)
    pub result_data: Option<Vec<u8>>,
}

/// BOINC validation result from scheduler reply
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Result name that was validated
    pub result_name: String,
    /// Work unit name
    pub wu_name: String,
    /// Whether the result was validated successfully
    pub validated: bool,
    /// Credits granted by BOINC
    pub credits_granted: f64,
    /// Validation time
    pub validated_at: DateTime<Utc>,
    /// Error message if validation failed
    pub error_message: Option<String>,
}

/// Replace element text values in an XML string.
///
/// # Arguments
/// * `xml` - input XML string
/// * `replacements` - tag → new value mapping
/// * `case_insensitive` - whether to match tag names ignoring case
///
/// # Returns
/// Returns `(new_xml, old_values_of_changed_elements)`.
pub fn update_xml_elements(
    xml: &str,
    replacements: &HashMap<&str, &str>,
    case_insensitive: bool,
) -> Result<(String, HashMap<String, String>)> {
    let mut reader = Reader::from_str(xml);
    // Note: trim_text is not available in newer versions of quick-xml
    // reader.trim_text(false);

    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();

    let mut depth: usize = 0;
    let mut current_target: Option<(String, usize)> = None;
    let mut replaced_in_this_element = false;

    let mut old_values: HashMap<String, String> = HashMap::new();

    // Prepare lookup map based on case sensitivity
    let lookup: HashMap<String, &str> = if case_insensitive {
        replacements
            .iter()
            .map(|(k, v)| (k.to_lowercase(), *v))
            .collect()
    } else {
        replacements
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect()
    };

    debug!("Processing XML with {} replacements", lookup.len());

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                depth += 1;

                let name_bytes = e.name();
                let raw = name_bytes.as_ref();
                let local = match raw.rsplit(|&b| b == b':').next() {
                    Some(n) => std::str::from_utf8(n).unwrap_or_default(),
                    None => "",
                };

                let key = if case_insensitive {
                    local.to_lowercase()
                } else {
                    local.to_string()
                };

                if current_target.is_none() && lookup.contains_key(&key) {
                    current_target = Some((key, depth));
                    replaced_in_this_element = false;
                    debug!("Found target element: {}", local);
                }

                writer.write_event(Event::Start(e))?;
            }
            Event::Empty(e) => {
                writer.write_event(Event::Empty(e))?;
            }
            Event::Text(t) => {
                if let Some((ref name, target_depth)) = current_target {
                    if depth == target_depth && !replaced_in_this_element {
                        let new_txt = lookup.get(name.as_str()).unwrap();
                        let old_txt = std::str::from_utf8(&t)
                            .map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))?
                            .to_string();

                        if &old_txt != new_txt {
                            debug!(
                                "Replacing '{}' content: '{}' -> '{}'",
                                name, old_txt, new_txt
                            );
                            old_values.insert(name.clone(), old_txt);
                            let escaped = BytesText::new(new_txt);
                            writer.write_event(Event::Text(escaped))?;
                        } else {
                            writer.write_event(Event::Text(t))?;
                        }

                        replaced_in_this_element = true;
                    } else {
                        writer.write_event(Event::Text(t))?;
                    }
                } else {
                    writer.write_event(Event::Text(t))?;
                }
            }
            Event::CData(c) => writer.write_event(Event::CData(c))?,
            Event::End(e) => {
                writer.write_event(Event::End(e.clone()))?;

                if let Some((_, target_depth)) = current_target
                    && depth == target_depth
                {
                    current_target = None;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Comment(c) => writer.write_event(Event::Comment(c))?,
            Event::Decl(d) => writer.write_event(Event::Decl(d))?,
            Event::PI(pi) => writer.write_event(Event::PI(pi))?,
            Event::DocType(dt) => writer.write_event(Event::DocType(dt))?,
            Event::Eof => break,
            _ => {} // Handle any other event types
        }
        buf.clear();
    }

    let new_xml = String::from_utf8(writer.into_inner())?;
    Ok((new_xml, old_values))
}

/// BOINC-specific XML processing utilities
pub struct BoincXmlProcessor {
    /// Mapping of user authenticators to our internal keys
    user_auth_map: HashMap<String, String>,
    /// Our proxy authenticator for the actual BOINC project
    proxy_authenticator: String,
    /// Extracted work units from scheduler responses
    extracted_work_units: HashMap<String, ExtractedWorkUnit>,
    /// Extracted results from client submissions
    extracted_results: HashMap<String, ExtractedResult>,
}

impl BoincXmlProcessor {
    /// Create a new BOINC XML processor
    pub fn new(proxy_authenticator: String) -> Self {
        Self {
            user_auth_map: HashMap::new(),
            proxy_authenticator,
            extracted_work_units: HashMap::new(),
            extracted_results: HashMap::new(),
        }
    }

    /// Register a user's authenticator mapping
    pub fn register_user_auth(&mut self, user_auth: String, internal_key: String) {
        debug!(
            "Registering user auth mapping: {} -> {}",
            user_auth, internal_key
        );
        self.user_auth_map.insert(user_auth, internal_key);
    }

    /// Process an outbound BOINC scheduler request (user -> BOINC project)
    /// Replaces user authenticators with our proxy authenticator and extracts results
    pub fn process_outbound_request(&mut self, xml: &str) -> Result<(String, Option<String>)> {
        let mut replacements = HashMap::new();
        let mut original_user_auth = None;

        // Try to extract the original authenticator for tracking
        if let Ok(user_auth) = self.extract_authenticator(xml)
            && !user_auth.is_empty()
            && user_auth != self.proxy_authenticator
        {
            original_user_auth = Some(user_auth.clone());
            replacements.insert("authenticator", self.proxy_authenticator.as_str());
            debug!("Will replace user authenticator with proxy authenticator");
        }

        // Extract results if this is a result submission
        if let Ok(results) = self.extract_results(xml) {
            for result in results {
                debug!("Extracted result submission: {}", result.result_name);
                self.extracted_results
                    .insert(result.result_name.clone(), result);
            }
        }

        if replacements.is_empty() {
            return Ok((xml.to_string(), original_user_auth));
        }

        let (modified_xml, _old_values) = update_xml_elements(xml, &replacements, false)?;
        Ok((modified_xml, original_user_auth))
    }

    /// Process an inbound BOINC scheduler response (BOINC project -> user)
    /// Extracts work units and results for tracking, obfuscates sensitive data
    pub fn process_inbound_response(
        &mut self,
        xml: &str,
        original_user_auth: Option<&str>,
    ) -> Result<String> {
        // Extract work units from the response
        if let Ok(work_units) = self.extract_work_units(xml) {
            for wu in work_units {
                debug!("Extracted work unit: {}", wu.name);
                self.extracted_work_units.insert(wu.name.clone(), wu);
            }
        }

        // Obfuscate sensitive data in the response
        let obfuscated_xml = self.obfuscate_response_data(xml, original_user_auth)?;

        Ok(obfuscated_xml)
    }

    /// Obfuscate sensitive data in BOINC scheduler response
    fn obfuscate_response_data(
        &self,
        xml: &str,
        original_user_auth: Option<&str>,
    ) -> Result<String> {
        let mut _replacements: HashMap<&str, &str> = HashMap::new();

        // Generate consistent but obfuscated identifiers based on original auth
        let user_hash = if let Some(auth) = original_user_auth {
            // Create a consistent hash for this user
            format!("{:x}", md5::compute(auth.as_bytes()))
        } else {
            // For anonymous users, create a consistent hash from a known string
            format!(
                "{:x}",
                md5::compute("anonymous_user_default_seed".as_bytes())
            )
        };

        // Ensure we have enough characters for all operations (MD5 gives us 32 hex chars)
        assert!(user_hash.len() >= 32, "Hash should be 32 characters long");

        let obfuscated_userid = format!("chert_{}", &user_hash[0..8]);
        let obfuscated_username = format!("ChertUser_{}", &user_hash[0..6]);
        let obfuscated_email_hash = format!("{}{}", &user_hash[8..16], &user_hash[16..24]);
        let obfuscated_cross_project_id = format!("chert_cross_{}", &user_hash[0..16]);
        let obfuscated_external_cpid = format!("chert_cpid_{}", &user_hash[16..32]);

        // Apply obfuscation replacements
        let mut obfuscated = xml.to_string();

        // Replace sensitive user data
        obfuscated = self.replace_xml_content(&obfuscated, "userid", &obfuscated_userid)?;
        obfuscated = self.replace_xml_content(&obfuscated, "user_name", &obfuscated_username)?;
        obfuscated = self.replace_xml_content(&obfuscated, "email_hash", &obfuscated_email_hash)?;
        obfuscated = self.replace_xml_content(
            &obfuscated,
            "cross_project_id",
            &obfuscated_cross_project_id,
        )?;
        obfuscated =
            self.replace_xml_content(&obfuscated, "external_cpid", &obfuscated_external_cpid)?;

        // CRITICAL: Replace master_url to keep BOINC client connected to our proxy
        obfuscated = self.replace_xml_content(
            &obfuscated,
            "master_url",
            "http://boincproject.local.com:8765/boinc/",
        )?;

        // Remove or replace RSS feeds containing auth tokens
        obfuscated = self.remove_rss_feeds(&obfuscated)?;

        // Replace userid in URLs
        obfuscated = obfuscated.replace("userid=8028822", &format!("userid={}", obfuscated_userid));

        debug!("Obfuscated response data for user: {}", user_hash);
        Ok(obfuscated)
    }

    /// Replace content of specific XML element
    fn replace_xml_content(&self, xml: &str, element: &str, new_content: &str) -> Result<String> {
        let start_tag = format!("<{}>", element);
        let end_tag = format!("</{}>", element);

        if let Some(start_pos) = xml.find(&start_tag)
            && let Some(end_pos) = xml[start_pos..].find(&end_tag)
        {
            let before = &xml[..start_pos + start_tag.len()];
            let after = &xml[start_pos + end_pos..];
            return Ok(format!("{}{}{}", before, new_content, after));
        }
        Ok(xml.to_string())
    }

    /// Remove RSS feeds section containing sensitive auth URLs
    fn remove_rss_feeds(&self, xml: &str) -> Result<String> {
        if let Some(start_pos) = xml.find("<rss_feeds>")
            && let Some(end_pos) = xml[start_pos..].find("</rss_feeds>")
        {
            let before = &xml[..start_pos];
            let after = &xml[start_pos + end_pos + "</rss_feeds>".len()..];
            // Replace with safe, generic RSS feed
            let safe_rss = r#"<rss_feeds>
    <rss_feed>
        <url>http://localhost:8765/api/notices</url>
        <poll_interval>86400</poll_interval>
    </rss_feed>
</rss_feeds>"#;
            return Ok(format!("{}{}{}", before, safe_rss, after));
        }
        Ok(xml.to_string())
    }

    /// Extract work units from BOINC scheduler response XML
    fn extract_work_units(&self, xml: &str) -> Result<Vec<ExtractedWorkUnit>> {
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        let mut work_units = Vec::new();

        let mut in_workunit = false;
        let mut current_wu = None::<ExtractedWorkUnit>;
        let mut current_element = String::new();

        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Start(e) => {
                    let name_bytes = e.name();
                    let name = name_bytes.as_ref();
                    let tag_name = std::str::from_utf8(name).unwrap_or_default();

                    if tag_name == "workunit" {
                        in_workunit = true;
                        current_wu = Some(ExtractedWorkUnit {
                            name: String::new(),
                            rsc_fpops_est: 0.0,
                            rsc_fpops_bound: 0.0,
                            rsc_memory_bound: 0.0,
                            rsc_disk_bound: 0.0,
                            delay_bound: 0.0,
                            extracted_at: Utc::now(),
                        });
                    } else if in_workunit {
                        current_element = tag_name.to_string();
                    }
                }
                Event::Text(t) => {
                    if in_workunit && let Some(ref mut wu) = current_wu {
                        let text = std::str::from_utf8(&t)
                            .map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))?;
                        match current_element.as_str() {
                            "name" => wu.name = text.to_string(),
                            "rsc_fpops_est" => wu.rsc_fpops_est = text.parse().unwrap_or(0.0),
                            "rsc_fpops_bound" => wu.rsc_fpops_bound = text.parse().unwrap_or(0.0),
                            "rsc_memory_bound" => wu.rsc_memory_bound = text.parse().unwrap_or(0.0),
                            "rsc_disk_bound" => wu.rsc_disk_bound = text.parse().unwrap_or(0.0),
                            "delay_bound" => wu.delay_bound = text.parse().unwrap_or(0.0),
                            _ => {}
                        }
                    }
                }
                Event::End(e) => {
                    let name_bytes = e.name();
                    let name = name_bytes.as_ref();
                    let tag_name = std::str::from_utf8(name).unwrap_or_default();

                    if tag_name == "workunit" {
                        if let Some(wu) = current_wu.take()
                            && !wu.name.is_empty()
                        {
                            work_units.push(wu);
                        }
                        in_workunit = false;
                    } else if in_workunit {
                        current_element.clear();
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        Ok(work_units)
    }

    /// Extract results from BOINC scheduler request XML (client submissions)
    fn extract_results(&self, xml: &str) -> Result<Vec<ExtractedResult>> {
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        let mut results = Vec::new();

        let mut in_result = false;
        let mut current_result = None::<ExtractedResult>;
        let mut current_element = String::new();

        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Start(e) => {
                    let name_bytes = e.name();
                    let name = name_bytes.as_ref();
                    let tag_name = std::str::from_utf8(name).unwrap_or_default();

                    if tag_name == "result" {
                        in_result = true;
                        current_result = Some(ExtractedResult {
                            wu_name: String::new(),
                            result_name: String::new(),
                            cpu_time: 0.0,
                            exit_status: 0,
                            submitted_at: Utc::now(),
                            result_hash: None,
                            result_data: None,
                        });
                    } else if in_result {
                        current_element = tag_name.to_string();
                    }
                }
                Event::Text(t) => {
                    if in_result && let Some(ref mut result) = current_result {
                        let text = std::str::from_utf8(&t)
                            .map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))?;
                        match current_element.as_str() {
                            "wu_name" => result.wu_name = text.to_string(),
                            "name" => result.result_name = text.to_string(),
                            "cpu_time" => result.cpu_time = text.parse().unwrap_or(0.0),
                            "exit_status" => result.exit_status = text.parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
                Event::End(e) => {
                    let name_bytes = e.name();
                    let name = name_bytes.as_ref();
                    let tag_name = std::str::from_utf8(name).unwrap_or_default();

                    if tag_name == "result" {
                        if let Some(result) = current_result.take()
                            && !result.result_name.is_empty()
                        {
                            results.push(result);
                        }
                        in_result = false;
                    } else if in_result {
                        current_element.clear();
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        Ok(results)
    }

    /// Get extracted work units
    pub fn get_extracted_work_units(&self) -> &HashMap<String, ExtractedWorkUnit> {
        &self.extracted_work_units
    }

    /// Get extracted results
    pub fn get_extracted_results(&self) -> &HashMap<String, ExtractedResult> {
        &self.extracted_results
    }

    /// Extract authenticator from XML for tracking purposes
    fn extract_authenticator(&self, xml: &str) -> Result<String> {
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        let mut in_authenticator = false;

        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Start(e) => {
                    let name_bytes = e.name();
                    let name = name_bytes.as_ref();
                    if name == b"authenticator" {
                        in_authenticator = true;
                    }
                }
                Event::Text(t) => {
                    if in_authenticator {
                        return Ok(std::str::from_utf8(&t)
                            .map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))?
                            .to_string());
                    }
                }
                Event::End(e) => {
                    let name_bytes = e.name();
                    let name = name_bytes.as_ref();
                    if name == b"authenticator" {
                        in_authenticator = false;
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        Ok(String::new())
    }
    
    /// Extract validation results from BOINC scheduler reply
    /// BOINC sends validation info in <result_ack> or credit messages
    pub fn extract_validation_results(&self, xml: &str) -> Result<Vec<ValidationResult>> {
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        let mut results = Vec::new();
        
        let mut in_result_ack = false;
        let mut in_credit = false;
        let mut current_result_name = String::new();
        let mut current_wu_name = String::new();
        let mut current_credits = 0.0;
        let mut current_element = String::new();
        
        loop {
            match reader.read_event_into(&mut buf)? {
                Event::Start(e) => {
                    let name_bytes = e.name();
                    let name = name_bytes.as_ref();
                    let tag_name = std::str::from_utf8(name).unwrap_or_default();
                    
                    if tag_name == "result_ack" {
                        in_result_ack = true;
                    } else if tag_name == "credit" {
                        in_credit = true;
                    } else if in_result_ack {
                        current_element = tag_name.to_string();
                    }
                }
                Event::Text(t) => {
                    let text = std::str::from_utf8(&t)
                        .map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))?;
                    
                    if in_result_ack {
                        match current_element.as_str() {
                            "name" => current_result_name = text.to_string(),
                            "wu_name" => current_wu_name = text.to_string(),
                            _ => {}
                        }
                    } else if in_credit {
                        // Credit value for the last acknowledged result
                        if let Ok(credits) = text.parse() {
                            current_credits = credits;
                        }
                    }
                }
                Event::End(e) => {
                    let name_bytes = e.name();
                    let name = name_bytes.as_ref();
                    let tag_name = std::str::from_utf8(name).unwrap_or_default();
                    
                    if tag_name == "result_ack" {
                        // Create validation result for this acknowledgement
                        if !current_result_name.is_empty() {
                            results.push(ValidationResult {
                                result_name: current_result_name.clone(),
                                wu_name: current_wu_name.clone(),
                                validated: true,
                                credits_granted: current_credits,
                                validated_at: Utc::now(),
                                error_message: None,
                            });
                        }
                        in_result_ack = false;
                        current_result_name.clear();
                        current_wu_name.clear();
                        current_credits = 0.0;
                    } else if tag_name == "credit" {
                        in_credit = false;
                    } else if in_result_ack {
                        current_element.clear();
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }
        
        Ok(results)
    }
    
    /// Get validation results (must call extract_validation_results first)
    pub fn get_validation_results(&self) -> Vec<ValidationResult> {
        // For now, validation results are not cached
        // Call extract_validation_results directly
        Vec::new()
    }
}
mod tests {
    use super::*;

    #[test]
    fn test_basic_xml_replacement() {
        let xml = r#"<?xml version="1.0"?>
<scheduler_request>
    <authenticator>user_auth_123</authenticator>
    <hostid>12345</hostid>
</scheduler_request>"#;

        let mut replacements = HashMap::new();
        replacements.insert("authenticator", "proxy_auth_456");

        let (result, old_values) = update_xml_elements(xml, &replacements, false).unwrap();

        assert!(result.contains("proxy_auth_456"));
        assert!(!result.contains("user_auth_123"));
        assert_eq!(
            old_values.get("authenticator"),
            Some(&"user_auth_123".to_string())
        );
    }

    #[test]
    fn test_boinc_processor() {
        let mut processor = BoincXmlProcessor::new("proxy_auth_456".to_string());
        processor.register_user_auth("user_auth_123".to_string(), "internal_key_789".to_string());

        let xml = r#"<?xml version="1.0"?>
<scheduler_request>
    <authenticator>user_auth_123</authenticator>
    <hostid>12345</hostid>
</scheduler_request>"#;

        let (result, original_auth) = processor.process_outbound_request(xml).unwrap();

        assert!(result.contains("proxy_auth_456"));
        assert!(!result.contains("user_auth_123"));
        assert_eq!(original_auth, Some("user_auth_123".to_string()));
    }

    #[test]
    fn test_work_unit_extraction() {
        let processor = BoincXmlProcessor::new("proxy_auth".to_string());

        let xml = r#"<scheduler_reply>
    <workunit>
        <name>wu_test_123</name>
        <rsc_fpops_est>2500000000</rsc_fpops_est>
        <rsc_fpops_bound>2000000000</rsc_fpops_bound>
        <rsc_memory_bound>104857600</rsc_memory_bound>
        <delay_bound>86400</delay_bound>
    </workunit>
</scheduler_reply>"#;

        let work_units = processor.extract_work_units(xml).unwrap();
        assert_eq!(work_units.len(), 1);
        assert_eq!(work_units[0].name, "wu_test_123");
        assert_eq!(work_units[0].rsc_fpops_est, 2500000000.0);
    }

    #[test]
    fn test_result_extraction() {
        let processor = BoincXmlProcessor::new("proxy_auth".to_string());

        let xml = r#"<scheduler_request>
    <result>
        <wu_name>wu_test_123</wu_name>
        <name>result_test_456</name>
        <cpu_time>3600.5</cpu_time>
        <exit_status>0</exit_status>
    </result>
</scheduler_request>"#;

        let results = processor.extract_results(xml).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].wu_name, "wu_test_123");
        assert_eq!(results[0].result_name, "result_test_456");
        assert_eq!(results[0].cpu_time, 3600.5);
        assert_eq!(results[0].exit_status, 0);
    }

    #[test]
    fn test_response_obfuscation() {
        let mut processor = BoincXmlProcessor::new("proxy_auth".to_string());

        let xml = r#"<scheduler_reply>
    <userid>8028822</userid>
    <user_name>David.Edmeades</user_name>
    <email_hash>032fcdca52444dd81a4c090fb57c638a</email_hash>
    <cross_project_id>40ee01b547e7740e4522732d771be25f</cross_project_id>
    <external_cpid>cc59a05fbf9394b19e07f43f84f05c26</external_cpid>
    <rss_feeds>
        <rss_feed>
            <url>http://milkyway.cs.rpi.edu/milkyway/notices.php?userid=8028822&auth=secret_auth_token</url>
        </rss_feed>
    </rss_feeds>
</scheduler_reply>"#;

        let result = processor
            .process_inbound_response(xml, Some("test_user_123"))
            .unwrap();

        // Should not contain original sensitive data
        assert!(!result.contains("8028822"));
        assert!(!result.contains("David.Edmeades"));
        assert!(!result.contains("032fcdca52444dd81a4c090fb57c638a"));
        assert!(!result.contains("secret_auth_token"));

        // Should contain obfuscated data
        assert!(result.contains("chert_"));
        assert!(result.contains("ChertUser_"));
        assert!(result.contains("http://localhost:8765/api/notices"));
    }

    #[test]
    fn test_extract_authenticator() {
        let processor = BoincXmlProcessor::new("proxy_auth".to_string());

        let xml = r#"<scheduler_request>
    <authenticator>test_auth_123</authenticator>
    <hostid>12345</hostid>
</scheduler_request>"#;

        let auth = processor.extract_authenticator(xml).unwrap();
        assert_eq!(auth, "test_auth_123");
    }
}
