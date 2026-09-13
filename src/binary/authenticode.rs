//! # Authenticode & Digital Signature Forensics
//!
//! Parses the PE Attribute Certificate Table (`IMAGE_DIRECTORY_ENTRY_SECURITY`),
//! extracts PKCS#7 SignedData certificate metadata (Subject, Issuer, Digest Algorithm),
//! identifies self-signed certificates, and audits for signature padding / overlay anomalies
//! (bytes appended after the Authenticode block to evade file-hash detection).

/// Authenticode certificate details and signature integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthenticodeInfo {
    /// True if the PE specifies a valid non-empty Security Directory.
    pub is_signed: bool,
    /// Offset of the WIN_CERTIFICATE structure within the file.
    pub cert_offset: usize,
    /// Declared size of the certificate block in bytes.
    pub cert_size: usize,
    /// Revision of the WIN_CERTIFICATE structure (e.g. 0x0200 = WIN_CERT_REVISION_2_0).
    pub revision: u16,
    /// Certificate type (e.g. 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA).
    pub cert_type: u16,
    /// Subject Common Name (CN), if extractable from ASN.1 X.509 certificates.
    pub subject_cn: Option<String>,
    /// Organization (O), if extractable.
    pub organization: Option<String>,
    /// Issuer Common Name (CN).
    pub issuer_cn: Option<String>,
    /// True if the certificate is self-signed (Subject CN matches Issuer CN).
    pub is_self_signed: bool,
    /// Digest algorithm (e.g. "SHA-256", "SHA-1").
    pub digest_algorithm: Option<String>,
    /// True if file bytes exist beyond the declared certificate boundary (overlay tampering).
    pub has_signature_overlay: bool,
    /// Size of the trailing overlay in bytes.
    pub overlay_size: usize,
}

/// Parses the Authenticode WIN_CERTIFICATE structure from a PE binary.
pub fn parse_authenticode(
    data: &[u8],
    cert_offset: usize,
    cert_size: usize,
) -> Option<AuthenticodeInfo> {
    if cert_offset == 0 || cert_size == 0 || cert_offset >= data.len() {
        return None;
    }

    let end_offset = (cert_offset + cert_size).min(data.len());
    let cert_data = &data[cert_offset..end_offset];
    if cert_data.len() < 8 {
        return None;
    }

    let dw_length =
        u32::from_le_bytes([cert_data[0], cert_data[1], cert_data[2], cert_data[3]]) as usize;
    let w_revision = u16::from_le_bytes([cert_data[4], cert_data[5]]);
    let w_cert_type = u16::from_le_bytes([cert_data[6], cert_data[7]]);

    let pkcs_bytes = if cert_data.len() > 8 {
        &cert_data[8..dw_length.min(cert_data.len())]
    } else {
        &[]
    };

    // Audit for trailing overlay after certificate boundary
    let expected_end = cert_offset + dw_length;
    let has_signature_overlay = data.len() > expected_end + 8;
    let overlay_size = if has_signature_overlay {
        data.len().saturating_sub(expected_end)
    } else {
        0
    };

    // Extract X.509 CN / O strings from ASN.1 DER data
    let (subject_cn, organization, issuer_cn, digest_algorithm) = extract_x509_strings(pkcs_bytes);

    let is_self_signed = match (&subject_cn, &issuer_cn) {
        (Some(s), Some(i)) => s == i && !s.is_empty(),
        _ => false,
    };

    Some(AuthenticodeInfo {
        is_signed: true,
        cert_offset,
        cert_size: dw_length,
        revision: w_revision,
        cert_type: w_cert_type,
        subject_cn,
        organization,
        issuer_cn,
        is_self_signed,
        digest_algorithm,
        has_signature_overlay,
        overlay_size,
    })
}

/// Helper to extract printable names and OID indicators from raw ASN.1 DER payload.
fn extract_x509_strings(
    der: &[u8],
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    if der.is_empty() {
        return (None, None, None, None);
    }

    // Common OIDs:
    // 2.5.4.3 (id-at-commonName): 55 04 03
    // 2.5.4.10 (id-at-organizationName): 55 04 0A
    // 2.16.840.1.101.3.4.2.1 (SHA-256): 60 86 48 01 65 03 04 02 01
    // 1.3.14.3.2.26 (SHA-1): 2B 0E 03 02 1A

    let mut common_names = Vec::new();
    let mut organizations = Vec::new();
    let mut digest_algo = None;

    // Check for SHA-256 vs SHA-1 OIDs
    if der
        .windows(9)
        .any(|w| w == [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
    {
        digest_algo = Some("SHA-256".to_string());
    } else if der.windows(5).any(|w| w == [0x2B, 0x0E, 0x03, 0x02, 0x1A]) {
        digest_algo = Some("SHA-1".to_string());
    }

    // Scan for CN OID (55 04 03) and Organization OID (55 04 0A)
    let mut i = 0;
    while i + 3 < der.len() {
        if der[i] == 0x55 && der[i + 1] == 0x04 {
            let attr_type = der[i + 2];
            let mut p = i + 3;
            // Look for ASN.1 string tag (0x13 = PrintableString, 0x0C = UTF8String, 0x14 = T61String)
            if p < der.len() && (der[p] == 0x13 || der[p] == 0x0C || der[p] == 0x14) {
                p += 1;
                if p < der.len() {
                    let len = der[p] as usize;
                    p += 1;
                    if p + len <= der.len() {
                        if let Ok(s) = std::str::from_utf8(&der[p..p + len]) {
                            let trimmed = s.trim().to_string();
                            if !trimmed.is_empty() {
                                if attr_type == 0x03 {
                                    common_names.push(trimmed);
                                } else if attr_type == 0x0A {
                                    organizations.push(trimmed);
                                }
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }

    let subject_cn = common_names.first().cloned();
    let issuer_cn = if common_names.len() > 1 {
        common_names.last().cloned()
    } else {
        common_names.first().cloned()
    };
    let organization = organizations.first().cloned();

    (subject_cn, organization, issuer_cn, digest_algo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticode_parsing_and_overlay() {
        let cert_offset = 512;
        let cert_len = 256;
        let mut mock_file = vec![0u8; cert_offset + cert_len]; // exactly ends at certificate

        // Mock WIN_CERTIFICATE header
        mock_file[cert_offset..cert_offset + 4].copy_from_slice(&(cert_len as u32).to_le_bytes());
        mock_file[cert_offset + 4..cert_offset + 6].copy_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
        mock_file[cert_offset + 6..cert_offset + 8].copy_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA

        // Embed a mock CN string in DER format: 55 04 03 13 0C "Example Corp"
        let cn_tag = [
            0x55, 0x04, 0x03, 0x13, 0x0C, b'E', b'x', b'a', b'm', b'p', b'l', b'e', b' ', b'C',
            b'o', b'r', b'p',
        ];
        mock_file[cert_offset + 10..cert_offset + 10 + cn_tag.len()].copy_from_slice(&cn_tag);

        let info = parse_authenticode(&mock_file, cert_offset, cert_len).expect("Parsed cert");
        assert!(info.is_signed);
        assert_eq!(info.revision, 0x0200);
        assert_eq!(info.subject_cn.as_deref(), Some("Example Corp"));
        assert!(!info.has_signature_overlay);

        // Append 100 bytes of overlay
        mock_file.extend_from_slice(&[0x90; 100]);
        let info_overlay =
            parse_authenticode(&mock_file, cert_offset, cert_len).expect("Parsed cert");
        assert!(info_overlay.has_signature_overlay);
        assert_eq!(info_overlay.overlay_size, 100);
    }
}
