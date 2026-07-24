// SPDX-License-Identifier: Apache-2.0

//! Target-specific RFC 3161 CMS signature and TSA certificate verification.
//!
//! Unix keeps the mature OpenSSL CMS verifier. Windows uses RustCrypto CMS
//! parsing plus WebPKI/ring verification so the desktop build has no
//! `openssl-sys`/Perl prerequisite while retaining the same acceptance gates:
//! canonical signed TSTInfo content, an operator-pinned chain at `genTime`,
//! and the dedicated critical `id-kp-timeStamping` certificate purpose.

use super::AnchorError;

#[cfg(not(target_os = "windows"))]
pub(super) fn verify_cms_signature_and_chain(
    response_der: &[u8],
    configured_trust_root_files: Option<&[Vec<u8>]>,
    verification_time_unix_secs: u64,
) -> Result<(), AnchorError> {
    use der::{Decode, Encode};
    use openssl::cms::{CMSOptions, CmsContentInfo};
    use openssl::x509::{store::X509StoreBuilder, verify::X509VerifyParam, X509PurposeId, X509};
    use x509_tsp::TimeStampResp;

    let response = TimeStampResp::from_der(response_der)
        .map_err(|e| AnchorError::Parse(format!("decode TimeStampResp for CMS verify: {e}")))?;
    let token = response
        .time_stamp_token
        .as_ref()
        .ok_or_else(|| AnchorError::Parse("TimeStampResp has no CMS timeStampToken".to_owned()))?;
    let token_der = token
        .to_der()
        .map_err(|e| AnchorError::Parse(format!("encode CMS timeStampToken: {e}")))?;
    let mut cms = CmsContentInfo::from_der(&token_der)
        .map_err(|e| AnchorError::Parse(format!("decode CMS timeStampToken: {e}")))?;

    let mut store = X509StoreBuilder::new()
        .map_err(|e| AnchorError::Parse(format!("create TSA trust store: {e}")))?;
    store
        .set_default_paths()
        .map_err(|e| AnchorError::Parse(format!("load system TSA trust roots: {e}")))?;
    let verification_time = verification_time_unix_secs.try_into().map_err(|_| {
        AnchorError::Parse("TSTInfo.genTime is outside the platform time_t range".to_owned())
    })?;
    let mut verify_params = X509VerifyParam::new()
        .map_err(|e| AnchorError::Parse(format!("create TSA verification parameters: {e}")))?;
    verify_params.set_time(verification_time);
    store
        .set_param(&verify_params)
        .map_err(|e| AnchorError::Parse(format!("set TSA certificate verification time: {e}")))?;
    store
        .set_purpose(X509PurposeId::TIMESTAMP_SIGN)
        .map_err(|e| AnchorError::Parse(format!("set TSA certificate purpose: {e}")))?;
    if let Some(root_files) = configured_trust_root_files {
        if root_files.is_empty() {
            return Err(AnchorError::Parse(
                "OLYMPUS_ANCHOR_RFC3161_TRUST_ROOTS contains no files".to_owned(),
            ));
        }
        for root_file in root_files {
            let first_non_whitespace = root_file
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .unwrap_or(root_file.len());
            let certs = if root_file[first_non_whitespace..].starts_with(b"-----BEGIN") {
                X509::stack_from_pem(root_file).map_err(|e| {
                    AnchorError::Parse(format!("parse configured TSA trust-root PEM: {e}"))
                })?
            } else {
                vec![X509::from_der(root_file).map_err(|e| {
                    AnchorError::Parse(format!("parse configured TSA trust-root DER: {e}"))
                })?]
            };
            if certs.is_empty() {
                return Err(AnchorError::Parse(
                    "configured TSA trust-root file contains no certificates".to_owned(),
                ));
            }
            for cert in certs {
                store.add_cert(cert).map_err(|e| {
                    AnchorError::Parse(format!("add configured TSA trust root: {e}"))
                })?;
            }
        }
    }
    let store = store.build();
    let mut signed_content = Vec::new();
    cms.verify(
        None,
        Some(&store),
        None,
        Some(&mut signed_content),
        CMSOptions::BINARY,
    )
    .map_err(|e| {
        AnchorError::Parse(format!(
            "RFC 3161 CMS signature or TSA certificate-chain verification failed: {e}"
        ))
    })?;
    if signed_content.is_empty() {
        return Err(AnchorError::Parse(
            "verified RFC 3161 CMS token contains no signed TSTInfo".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
mod windows {
    use std::{cell::RefCell, time::Duration};

    use cms::cert::CertificateChoices;
    use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
    use der::asn1::{Any, ObjectIdentifier, OctetString};
    use der::{Decode, Encode, Sequence};
    use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use spki07::AlgorithmIdentifierOwned;
    use webpki::{EndEntityCert, KeyUsage as WebPkiKeyUsage};
    use x509_cert::attr::{Attribute, Attributes};
    use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
    use x509_cert::ext::pkix::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage as CertificateKeyUsage, SubjectKeyIdentifier,
    };
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::Certificate;
    use x509_tsp::TimeStampResp;

    use super::AnchorError;

    const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    const ID_CT_TST_INFO: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
    const ID_CONTENT_TYPE_ATTR: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
    const ID_MESSAGE_DIGEST_ATTR: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
    const ID_SIGNING_CERTIFICATE_ATTR: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
    const ID_SIGNING_CERTIFICATE_V2_ATTR: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
    const ID_KP_TIMESTAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
    const ID_KP_TIMESTAMPING_VALUE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
    const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
    const ID_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    const ID_CE_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");

    const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

    const ID_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    const ID_SHA256_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const ID_SHA384_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    const ID_SHA512_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    const ID_ECDSA_WITH_SHA256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const ID_ECDSA_WITH_SHA384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    struct SigningCertificate {
        certs: Vec<EssCertId>,
        policies: Option<Any>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    struct EssCertId {
        cert_hash: OctetString,
        issuer_serial: Option<IssuerSerial>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    struct SigningCertificateV2 {
        certs: Vec<EssCertIdV2>,
        policies: Option<Any>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    struct EssCertIdV2 {
        hash_algorithm: Option<AlgorithmIdentifierOwned>,
        cert_hash: OctetString,
        issuer_serial: Option<IssuerSerial>,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
    struct IssuerSerial {
        issuer: GeneralNames,
        serial_number: SerialNumber,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DigestKind {
        Sha1,
        Sha256,
        Sha384,
        Sha512,
    }

    impl DigestKind {
        fn digest(self, input: &[u8]) -> Vec<u8> {
            match self {
                Self::Sha1 => Sha1::digest(input).to_vec(),
                Self::Sha256 => Sha256::digest(input).to_vec(),
                Self::Sha384 => Sha384::digest(input).to_vec(),
                Self::Sha512 => Sha512::digest(input).to_vec(),
            }
        }
    }

    pub(super) fn verify_cms_signature_and_chain(
        response_der: &[u8],
        configured_trust_root_files: Option<&[Vec<u8>]>,
        verification_time_unix_secs: u64,
    ) -> Result<(), AnchorError> {
        let response = TimeStampResp::from_der(response_der)
            .map_err(|e| AnchorError::Parse(format!("decode TimeStampResp for CMS verify: {e}")))?;
        let token = response.time_stamp_token.as_ref().ok_or_else(|| {
            AnchorError::Parse("TimeStampResp has no CMS timeStampToken".to_owned())
        })?;
        if token.content_type != ID_SIGNED_DATA {
            return Err(AnchorError::Parse(
                "RFC 3161 timeStampToken is not CMS SignedData".to_owned(),
            ));
        }
        let signed_data_der = token
            .content
            .to_der()
            .map_err(|e| AnchorError::Parse(format!("encode CMS SignedData: {e}")))?;
        let signed_data = SignedData::from_der(&signed_data_der)
            .map_err(|e| AnchorError::Parse(format!("decode CMS SignedData: {e}")))?;
        if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
            return Err(AnchorError::Parse(
                "CMS eContentType is not id-ct-TSTInfo".to_owned(),
            ));
        }
        let econtent_any = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or_else(|| {
                AnchorError::Parse("CMS SignedData has no TSTInfo content".to_owned())
            })?;
        let econtent_der = econtent_any
            .to_der()
            .map_err(|e| AnchorError::Parse(format!("encode CMS eContent: {e}")))?;
        let econtent = OctetString::from_der(&econtent_der)
            .map_err(|e| AnchorError::Parse(format!("decode CMS TSTInfo eContent: {e}")))?;

        if signed_data.signer_infos.0.len() != 1 {
            return Err(AnchorError::Parse(
                "RFC 3161 token must contain exactly one TSA signature".to_owned(),
            ));
        }
        let signer = signed_data
            .signer_infos
            .0
            .iter()
            .next()
            .ok_or_else(|| AnchorError::Parse("CMS SignedData has no signer".to_owned()))?;
        let signer_digest_kind = digest_kind(&signer.digest_alg, false)?;
        if !signed_data.digest_algorithms.iter().any(|algorithm| {
            digest_kind(algorithm, false).is_ok_and(|listed| listed == signer_digest_kind)
        }) {
            return Err(AnchorError::Parse(
                "CMS signer digest algorithm is absent from SignedData.digestAlgorithms".to_owned(),
            ));
        }
        if signer_digest_kind == DigestKind::Sha1 {
            return Err(AnchorError::Parse(
                "SHA-1 CMS content signatures are not accepted".to_owned(),
            ));
        }

        let attrs = signer.signed_attrs.as_ref().ok_or_else(|| {
            AnchorError::Parse("RFC 3161 TSA SignerInfo has no signed attributes".to_owned())
        })?;
        verify_signed_attributes(attrs, &signed_data, econtent.as_bytes(), signer_digest_kind)?;
        let signed_attrs_der = attrs
            .to_der()
            .map_err(|e| AnchorError::Parse(format!("encode CMS signed attributes: {e}")))?;
        verify_signed_attributes_wire_encoding(&signed_data_der, &signed_attrs_der)?;

        let certificates = signed_data.certificates.as_ref().ok_or_else(|| {
            AnchorError::Parse("RFC 3161 SignedData contains no TSA certificate".to_owned())
        })?;
        let embedded = certificates
            .0
            .iter()
            .filter_map(|choice| match choice {
                CertificateChoices::Certificate(cert) => Some(cert),
                _ => None,
            })
            .collect::<Vec<_>>();
        if embedded.is_empty() {
            return Err(AnchorError::Parse(
                "RFC 3161 SignedData contains no X.509 certificates".to_owned(),
            ));
        }
        let signer_index = find_signer_certificate(&embedded, signer)?;
        let signer_cert = embedded[signer_index];
        verify_timestamping_certificate_profile(signer_cert)?;
        let signer_cert_der = signer_cert
            .to_der()
            .map_err(|e| AnchorError::Parse(format!("encode TSA signer certificate: {e}")))?;
        verify_signing_certificate_attribute(attrs, signer_cert, &signer_cert_der)?;

        let signer_der = CertificateDer::from(signer_cert_der);
        let end_entity = EndEntityCert::try_from(&signer_der)
            .map_err(|e| AnchorError::Parse(format!("parse TSA signer certificate: {e}")))?;
        verify_cms_signature(&end_entity, signer, signer_digest_kind, &signed_attrs_der)?;

        let intermediates = embedded
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != signer_index)
            .map(|(_, cert)| {
                cert.to_der().map(CertificateDer::from).map_err(|e| {
                    AnchorError::Parse(format!("encode embedded TSA certificate: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let root_certs = load_trust_roots(configured_trust_root_files)?;
        let trust_anchors = build_trust_anchors(&root_certs, verification_time_unix_secs)?;
        let verification_time =
            UnixTime::since_unix_epoch(Duration::from_secs(verification_time_unix_secs));
        verify_timestamping_certificate_chain(
            &end_entity,
            &trust_anchors,
            &intermediates,
            verification_time,
        )
    }

    fn verify_timestamping_certificate_chain<'a>(
        end_entity: &'a EndEntityCert<'a>,
        trust_anchors: &'a [TrustAnchor<'a>],
        intermediates: &'a [CertificateDer<'a>],
        verification_time: UnixTime,
    ) -> Result<(), AnchorError> {
        let path_profile_error = RefCell::new(None);
        let verify_path = |path: &webpki::VerifiedPath<'_>| {
            match verify_intermediate_certificate_profiles(path) {
                Ok(()) => Ok(()),
                Err(error) => {
                    let mut first_error = path_profile_error.borrow_mut();
                    if first_error.is_none() {
                        *first_error = Some(error);
                    }
                    Err(webpki::Error::UnknownIssuer)
                }
            }
        };
        if let Err(error) = end_entity.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            trust_anchors,
            intermediates,
            verification_time,
            // RFC 5280 constrains a CA only when it carries EKU. The signer
            // itself remains subject to the stricter, mandatory and exclusive
            // id-kp-timeStamping profile checked above.
            WebPkiKeyUsage::required_if_present(ID_KP_TIMESTAMPING_VALUE),
            None,
            Some(&verify_path),
        ) {
            if let Some(profile_error) = path_profile_error.into_inner() {
                return Err(profile_error);
            }
            return Err(AnchorError::Parse(format!(
                "RFC 3161 TSA certificate-chain verification failed: {error}"
            )));
        }
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct DerTlv<'a> {
        tag: u8,
        full: &'a [u8],
        value: &'a [u8],
    }

    fn take_der_tlv<'a>(input: &mut &'a [u8], context: &str) -> Result<DerTlv<'a>, AnchorError> {
        if input.len() < 2 {
            return Err(AnchorError::Parse(format!(
                "truncated DER while reading {context}"
            )));
        }
        let tag = input[0];
        if tag & 0x1f == 0x1f {
            return Err(AnchorError::Parse(format!(
                "unsupported high-tag-number DER while reading {context}"
            )));
        }
        let first_length = input[1];
        let (value_length, length_octets) = if first_length & 0x80 == 0 {
            (usize::from(first_length), 0usize)
        } else {
            let count = usize::from(first_length & 0x7f);
            if count == 0 || count > std::mem::size_of::<usize>() || input.len() < 2 + count {
                return Err(AnchorError::Parse(format!(
                    "invalid DER length while reading {context}"
                )));
            }
            if input[2] == 0 {
                return Err(AnchorError::Parse(format!(
                    "non-canonical DER length while reading {context}"
                )));
            }
            let mut length = 0usize;
            for byte in &input[2..2 + count] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or_else(|| {
                        AnchorError::Parse(format!(
                            "overflowing DER length while reading {context}"
                        ))
                    })?;
            }
            if length < 128 {
                return Err(AnchorError::Parse(format!(
                    "non-canonical DER length while reading {context}"
                )));
            }
            (length, count)
        };
        let header_length = 2usize.checked_add(length_octets).ok_or_else(|| {
            AnchorError::Parse(format!("overflowing DER header while reading {context}"))
        })?;
        let total_length = header_length.checked_add(value_length).ok_or_else(|| {
            AnchorError::Parse(format!("overflowing DER value while reading {context}"))
        })?;
        if input.len() < total_length {
            return Err(AnchorError::Parse(format!(
                "truncated DER value while reading {context}"
            )));
        }
        let (full, remaining) = input.split_at(total_length);
        *input = remaining;
        Ok(DerTlv {
            tag,
            full,
            value: &full[header_length..],
        })
    }

    fn require_der_tag(tlv: DerTlv<'_>, expected: u8, context: &str) -> Result<(), AnchorError> {
        if tlv.tag == expected {
            Ok(())
        } else {
            Err(AnchorError::Parse(format!(
                "unexpected DER tag {:02x} while reading {context}",
                tlv.tag
            )))
        }
    }

    fn signed_attributes_wire_der(signed_data_der: &[u8]) -> Result<&[u8], AnchorError> {
        let mut outer = signed_data_der;
        let signed_data = take_der_tlv(&mut outer, "CMS SignedData")?;
        require_der_tag(signed_data, 0x30, "CMS SignedData")?;
        if !outer.is_empty() {
            return Err(AnchorError::Parse(
                "trailing DER after CMS SignedData".to_owned(),
            ));
        }

        let mut fields = signed_data.value;
        require_der_tag(
            take_der_tlv(&mut fields, "SignedData.version")?,
            0x02,
            "SignedData.version",
        )?;
        require_der_tag(
            take_der_tlv(&mut fields, "SignedData.digestAlgorithms")?,
            0x31,
            "SignedData.digestAlgorithms",
        )?;
        require_der_tag(
            take_der_tlv(&mut fields, "SignedData.encapContentInfo")?,
            0x30,
            "SignedData.encapContentInfo",
        )?;
        while fields
            .first()
            .is_some_and(|tag| *tag == 0xa0 || *tag == 0xa1)
        {
            take_der_tlv(&mut fields, "SignedData optional certificates or CRLs")?;
        }
        let signer_infos = take_der_tlv(&mut fields, "SignedData.signerInfos")?;
        require_der_tag(signer_infos, 0x31, "SignedData.signerInfos")?;
        if !fields.is_empty() {
            return Err(AnchorError::Parse(
                "trailing fields after SignedData.signerInfos".to_owned(),
            ));
        }

        let mut signer_infos_value = signer_infos.value;
        let signer_info = take_der_tlv(&mut signer_infos_value, "SignerInfo")?;
        require_der_tag(signer_info, 0x30, "SignerInfo")?;
        if !signer_infos_value.is_empty() {
            return Err(AnchorError::Parse(
                "RFC 3161 token must contain exactly one wire SignerInfo".to_owned(),
            ));
        }
        let mut signer_fields = signer_info.value;
        require_der_tag(
            take_der_tlv(&mut signer_fields, "SignerInfo.version")?,
            0x02,
            "SignerInfo.version",
        )?;
        let sid = take_der_tlv(&mut signer_fields, "SignerInfo.sid")?;
        if sid.tag != 0x30 && sid.tag != 0x80 {
            return Err(AnchorError::Parse(
                "SignerInfo.sid has an unexpected DER tag".to_owned(),
            ));
        }
        require_der_tag(
            take_der_tlv(&mut signer_fields, "SignerInfo.digestAlgorithm")?,
            0x30,
            "SignerInfo.digestAlgorithm",
        )?;
        let signed_attrs = take_der_tlv(&mut signer_fields, "SignerInfo.signedAttrs")?;
        require_der_tag(signed_attrs, 0xa0, "SignerInfo.signedAttrs")?;
        Ok(signed_attrs.full)
    }

    fn verify_signed_attributes_wire_encoding(
        signed_data_der: &[u8],
        canonical_set_der: &[u8],
    ) -> Result<(), AnchorError> {
        if canonical_set_der.first() != Some(&0x31) {
            return Err(AnchorError::Parse(
                "encoded CMS signed attributes are not a DER SET".to_owned(),
            ));
        }
        let mut canonical_implicit = canonical_set_der.to_vec();
        canonical_implicit[0] = 0xa0;
        if signed_attributes_wire_der(signed_data_der)? != canonical_implicit {
            return Err(AnchorError::Parse(
                "CMS signed attributes are not in canonical DER wire order".to_owned(),
            ));
        }
        Ok(())
    }

    fn verify_signed_attributes(
        attrs: &Attributes,
        signed_data: &SignedData,
        econtent: &[u8],
        digest_kind: DigestKind,
    ) -> Result<(), AnchorError> {
        let content_type_value =
            required_single_attribute_value(attrs, ID_CONTENT_TYPE_ATTR, "content-type")?;
        let content_type_der = content_type_value
            .to_der()
            .map_err(|e| AnchorError::Parse(format!("encode CMS content-type attribute: {e}")))?;
        let content_type = ObjectIdentifier::from_der(&content_type_der)
            .map_err(|e| AnchorError::Parse(format!("decode CMS content-type attribute: {e}")))?;
        if content_type != signed_data.encap_content_info.econtent_type {
            return Err(AnchorError::Parse(
                "CMS content-type attribute does not match eContentType".to_owned(),
            ));
        }

        let message_digest_value =
            required_single_attribute_value(attrs, ID_MESSAGE_DIGEST_ATTR, "message-digest")?;
        let message_digest_der = message_digest_value
            .to_der()
            .map_err(|e| AnchorError::Parse(format!("encode CMS message-digest attribute: {e}")))?;
        let message_digest = OctetString::from_der(&message_digest_der)
            .map_err(|e| AnchorError::Parse(format!("decode CMS message-digest attribute: {e}")))?;
        if message_digest.as_bytes() != digest_kind.digest(econtent) {
            return Err(AnchorError::Parse(
                "CMS message-digest attribute does not bind the TSTInfo content".to_owned(),
            ));
        }
        Ok(())
    }

    fn find_signer_certificate(
        embedded: &[&Certificate],
        signer: &SignerInfo,
    ) -> Result<usize, AnchorError> {
        let mut matching = Vec::new();
        for (index, cert) in embedded.iter().enumerate() {
            let matches = match &signer.sid {
                SignerIdentifier::IssuerAndSerialNumber(identifier) => {
                    cert.tbs_certificate.issuer == identifier.issuer
                        && cert.tbs_certificate.serial_number == identifier.serial_number
                }
                SignerIdentifier::SubjectKeyIdentifier(identifier) => cert
                    .tbs_certificate
                    .get::<SubjectKeyIdentifier>()
                    .map_err(|e| {
                        AnchorError::Parse(format!("decode TSA signer SubjectKeyIdentifier: {e}"))
                    })?
                    .is_some_and(|(_, ski)| ski.0.as_bytes() == identifier.0.as_bytes()),
            };
            if matches {
                matching.push(index);
            }
        }
        match matching.as_slice() {
            [index] => Ok(*index),
            [] => Err(AnchorError::Parse(
                "CMS signer identifier matches no embedded certificate".to_owned(),
            )),
            _ => Err(AnchorError::Parse(
                "CMS signer identifier ambiguously matches multiple certificates".to_owned(),
            )),
        }
    }

    fn verify_timestamping_certificate_profile(cert: &Certificate) -> Result<(), AnchorError> {
        let (critical, eku) = cert
            .tbs_certificate
            .get::<ExtendedKeyUsage>()
            .map_err(|e| AnchorError::Parse(format!("decode TSA extended-key-usage: {e}")))?
            .ok_or_else(|| {
                AnchorError::Parse(
                    "TSA certificate has no id-kp-timeStamping extended-key-usage".to_owned(),
                )
            })?;
        if !critical || eku.0.as_slice() != [ID_KP_TIMESTAMPING] {
            return Err(AnchorError::Parse(
                "TSA certificate EKU must be critical and exclusively id-kp-timeStamping"
                    .to_owned(),
            ));
        }
        if let Some((_, key_usage)) = cert
            .tbs_certificate
            .get::<CertificateKeyUsage>()
            .map_err(|e| AnchorError::Parse(format!("decode TSA key-usage: {e}")))?
        {
            if !key_usage.digital_signature() && !key_usage.non_repudiation() {
                return Err(AnchorError::Parse(
                    "TSA certificate key-usage does not permit signatures".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn verify_signing_certificate_attribute(
        attrs: &Attributes,
        signer_cert: &Certificate,
        signer_cert_der: &[u8],
    ) -> Result<(), AnchorError> {
        let v1 = single_attribute(attrs, ID_SIGNING_CERTIFICATE_ATTR, "SigningCertificate")?;
        let v2 = single_attribute(
            attrs,
            ID_SIGNING_CERTIFICATE_V2_ATTR,
            "SigningCertificateV2",
        )?;
        match (v1, v2) {
            (Some(_), Some(_)) => {
                return Err(AnchorError::Parse(
                    "CMS signer has both SigningCertificate and SigningCertificateV2".to_owned(),
                ))
            }
            (None, None) => {
                return Err(AnchorError::Parse(
                    "RFC 3161 TSA signer lacks a SigningCertificate identifier".to_owned(),
                ))
            }
            (Some(attribute), None) => {
                let value = single_value(attribute, "SigningCertificate")?;
                let encoded = value.to_der().map_err(|e| {
                    AnchorError::Parse(format!("encode SigningCertificate attribute: {e}"))
                })?;
                let signing = SigningCertificate::from_der(&encoded).map_err(|e| {
                    AnchorError::Parse(format!("decode SigningCertificate attribute: {e}"))
                })?;
                let cert_id = signing.certs.first().ok_or_else(|| {
                    AnchorError::Parse("SigningCertificate contains no certificate ID".to_owned())
                })?;
                if cert_id.cert_hash.as_bytes() != DigestKind::Sha1.digest(signer_cert_der) {
                    return Err(AnchorError::Parse(
                        "SigningCertificate does not identify the TSA signer certificate"
                            .to_owned(),
                    ));
                }
                verify_ess_issuer_serial(
                    cert_id.issuer_serial.as_ref(),
                    signer_cert,
                    "SigningCertificate",
                )?;
            }
            (None, Some(attribute)) => {
                let value = single_value(attribute, "SigningCertificateV2")?;
                let encoded = value.to_der().map_err(|e| {
                    AnchorError::Parse(format!("encode SigningCertificateV2 attribute: {e}"))
                })?;
                let signing = SigningCertificateV2::from_der(&encoded).map_err(|e| {
                    AnchorError::Parse(format!("decode SigningCertificateV2 attribute: {e}"))
                })?;
                let cert_id = signing.certs.first().ok_or_else(|| {
                    AnchorError::Parse("SigningCertificateV2 contains no certificate ID".to_owned())
                })?;
                let hash_kind = match &cert_id.hash_algorithm {
                    Some(algorithm) => digest_kind(algorithm, true)?,
                    None => DigestKind::Sha256,
                };
                if cert_id.cert_hash.as_bytes() != hash_kind.digest(signer_cert_der) {
                    return Err(AnchorError::Parse(
                        "SigningCertificateV2 does not identify the TSA signer certificate"
                            .to_owned(),
                    ));
                }
                verify_ess_issuer_serial(
                    cert_id.issuer_serial.as_ref(),
                    signer_cert,
                    "SigningCertificateV2",
                )?;
            }
        }
        Ok(())
    }

    fn verify_ess_issuer_serial(
        issuer_serial: Option<&IssuerSerial>,
        signer_cert: &Certificate,
        attribute_name: &str,
    ) -> Result<(), AnchorError> {
        let Some(issuer_serial) = issuer_serial else {
            return Ok(());
        };
        if issuer_serial.serial_number != signer_cert.tbs_certificate.serial_number {
            return Err(AnchorError::Parse(format!(
                "{attribute_name} issuerSerial does not match the TSA signer serial number"
            )));
        }
        if issuer_serial.issuer.is_empty()
            || !issuer_serial.issuer.iter().any(|name| {
                matches!(
                    name,
                    GeneralName::DirectoryName(issuer)
                        if issuer == &signer_cert.tbs_certificate.issuer
                )
            })
        {
            return Err(AnchorError::Parse(format!(
                "{attribute_name} issuerSerial does not match the TSA signer issuer"
            )));
        }
        Ok(())
    }

    fn verify_cms_signature(
        signer_cert: &EndEntityCert<'_>,
        signer: &SignerInfo,
        digest_kind: DigestKind,
        signed_attrs_der: &[u8],
    ) -> Result<(), AnchorError> {
        let algorithms = signature_algorithms(signer, digest_kind)?;
        if algorithms.iter().any(|algorithm| {
            signer_cert
                .verify_signature(*algorithm, signed_attrs_der, signer.signature.as_bytes())
                .is_ok()
        }) {
            Ok(())
        } else {
            Err(AnchorError::Parse(
                "RFC 3161 CMS signature verification failed".to_owned(),
            ))
        }
    }

    fn signature_algorithms(
        signer: &SignerInfo,
        digest_kind: DigestKind,
    ) -> Result<Vec<&'static dyn SignatureVerificationAlgorithm>, AnchorError> {
        use webpki::ring;

        let oid = signer.signature_algorithm.oid;
        if oid == ID_RSA_ENCRYPTION
            || oid == ID_SHA256_WITH_RSA
            || oid == ID_SHA384_WITH_RSA
            || oid == ID_SHA512_WITH_RSA
        {
            require_null_or_absent_parameters(
                &signer.signature_algorithm,
                "RSA CMS signature algorithm",
            )?;
            let expected = match oid {
                ID_SHA256_WITH_RSA => Some(DigestKind::Sha256),
                ID_SHA384_WITH_RSA => Some(DigestKind::Sha384),
                ID_SHA512_WITH_RSA => Some(DigestKind::Sha512),
                _ => None,
            };
            if expected.is_some_and(|expected| expected != digest_kind) {
                return Err(AnchorError::Parse(
                    "CMS signature and digest algorithms disagree".to_owned(),
                ));
            }
            return match digest_kind {
                DigestKind::Sha256 => Ok(vec![
                    ring::RSA_PKCS1_2048_8192_SHA256,
                    ring::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
                ]),
                DigestKind::Sha384 => Ok(vec![
                    ring::RSA_PKCS1_2048_8192_SHA384,
                    ring::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
                ]),
                DigestKind::Sha512 => Ok(vec![
                    ring::RSA_PKCS1_2048_8192_SHA512,
                    ring::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
                ]),
                DigestKind::Sha1 => Err(AnchorError::Parse(
                    "SHA-1 RSA CMS signatures are not accepted".to_owned(),
                )),
            };
        }

        if oid == ID_ECDSA_WITH_SHA256 || oid == ID_ECDSA_WITH_SHA384 {
            require_absent_parameters(
                &signer.signature_algorithm,
                "ECDSA CMS signature algorithm",
            )?;
            let expected = if oid == ID_ECDSA_WITH_SHA256 {
                DigestKind::Sha256
            } else {
                DigestKind::Sha384
            };
            if digest_kind != expected {
                return Err(AnchorError::Parse(
                    "CMS ECDSA signature and digest algorithms disagree".to_owned(),
                ));
            }
            return if digest_kind == DigestKind::Sha256 {
                Ok(vec![ring::ECDSA_P256_SHA256, ring::ECDSA_P384_SHA256])
            } else {
                Ok(vec![ring::ECDSA_P256_SHA384, ring::ECDSA_P384_SHA384])
            };
        }

        if oid == ID_ED25519 {
            require_absent_parameters(
                &signer.signature_algorithm,
                "Ed25519 CMS signature algorithm",
            )?;
            if digest_kind != DigestKind::Sha512 {
                return Err(AnchorError::Parse(
                    "Ed25519 CMS SignerInfo must use SHA-512 as its digest algorithm".to_owned(),
                ));
            }
            return Ok(vec![ring::ED25519]);
        }

        Err(AnchorError::Parse(format!(
            "unsupported RFC 3161 CMS signature algorithm {oid}"
        )))
    }

    fn digest_kind(
        algorithm: &AlgorithmIdentifierOwned,
        allow_sha1: bool,
    ) -> Result<DigestKind, AnchorError> {
        require_null_or_absent_parameters(algorithm, "digest algorithm")?;
        match algorithm.oid {
            ID_SHA1 if allow_sha1 => Ok(DigestKind::Sha1),
            ID_SHA256 => Ok(DigestKind::Sha256),
            ID_SHA384 => Ok(DigestKind::Sha384),
            ID_SHA512 => Ok(DigestKind::Sha512),
            oid => Err(AnchorError::Parse(format!(
                "unsupported RFC 3161 digest algorithm {oid}"
            ))),
        }
    }

    fn require_null_or_absent_parameters(
        algorithm: &AlgorithmIdentifierOwned,
        label: &str,
    ) -> Result<(), AnchorError> {
        let Some(parameters) = &algorithm.parameters else {
            return Ok(());
        };
        let encoded = parameters
            .to_der()
            .map_err(|e| AnchorError::Parse(format!("encode {label} parameters: {e}")))?;
        if encoded == [0x05, 0x00] {
            Ok(())
        } else {
            Err(AnchorError::Parse(format!(
                "{label} has non-canonical parameters"
            )))
        }
    }

    fn require_absent_parameters(
        algorithm: &AlgorithmIdentifierOwned,
        label: &str,
    ) -> Result<(), AnchorError> {
        if algorithm.parameters.is_none() {
            Ok(())
        } else {
            Err(AnchorError::Parse(format!(
                "{label} parameters must be absent"
            )))
        }
    }

    fn single_attribute<'a>(
        attrs: &'a Attributes,
        oid: ObjectIdentifier,
        label: &str,
    ) -> Result<Option<&'a Attribute>, AnchorError> {
        let mut matching = attrs.iter().filter(|attribute| attribute.oid == oid);
        let first = matching.next();
        if matching.next().is_some() {
            return Err(AnchorError::Parse(format!(
                "CMS signed attributes contain duplicate {label} entries"
            )));
        }
        Ok(first)
    }

    fn required_single_attribute_value<'a>(
        attrs: &'a Attributes,
        oid: ObjectIdentifier,
        label: &str,
    ) -> Result<&'a Any, AnchorError> {
        let attribute = single_attribute(attrs, oid, label)?
            .ok_or_else(|| AnchorError::Parse(format!("CMS signed attributes lack {label}")))?;
        single_value(attribute, label)
    }

    fn single_value<'a>(attribute: &'a Attribute, label: &str) -> Result<&'a Any, AnchorError> {
        if attribute.values.len() != 1 {
            return Err(AnchorError::Parse(format!(
                "CMS {label} attribute must contain exactly one value"
            )));
        }
        attribute
            .values
            .iter()
            .next()
            .ok_or_else(|| AnchorError::Parse(format!("CMS {label} attribute contains no value")))
    }

    fn load_trust_roots(
        configured_trust_root_files: Option<&[Vec<u8>]>,
    ) -> Result<Vec<CertificateDer<'static>>, AnchorError> {
        let root_files = configured_trust_root_files.ok_or_else(|| {
            AnchorError::Parse(
                "OLYMPUS_ANCHOR_RFC3161_TRUST_ROOTS is required on Windows; \
                 the current-user ROOT store is not accepted for RFC 3161 trust"
                    .to_owned(),
            )
        })?;
        if root_files.is_empty() {
            return Err(AnchorError::Parse(
                "OLYMPUS_ANCHOR_RFC3161_TRUST_ROOTS contains no files".to_owned(),
            ));
        }

        let mut roots = Vec::new();
        for root_file in root_files {
            if root_file.is_empty() {
                return Err(AnchorError::Parse(
                    "configured TSA trust-root file is empty".to_owned(),
                ));
            }
            let first_non_whitespace = root_file
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .unwrap_or(root_file.len());
            let configured = if root_file[first_non_whitespace..].starts_with(b"-----BEGIN") {
                Certificate::load_pem_chain(root_file).map_err(|e| {
                    AnchorError::Parse(format!("parse configured TSA trust-root PEM: {e}"))
                })?
            } else {
                vec![Certificate::from_der(root_file).map_err(|e| {
                    AnchorError::Parse(format!("parse configured TSA trust-root DER: {e}"))
                })?]
            };
            if configured.is_empty() {
                return Err(AnchorError::Parse(
                    "configured TSA trust-root file contains no certificates".to_owned(),
                ));
            }
            for cert in configured {
                let der = cert.to_der().map_err(|e| {
                    AnchorError::Parse(format!("encode configured TSA trust root: {e}"))
                })?;
                roots.push(CertificateDer::from(der));
            }
        }
        if roots.is_empty() {
            return Err(AnchorError::Parse(
                "OLYMPUS_ANCHOR_RFC3161_TRUST_ROOTS contains no certificates".to_owned(),
            ));
        }
        Ok(roots)
    }

    fn build_trust_anchors<'a>(
        roots: &'a [CertificateDer<'a>],
        verification_time_unix_secs: u64,
    ) -> Result<Vec<TrustAnchor<'a>>, AnchorError> {
        let mut anchors = Vec::new();
        for root in roots {
            let certificate = Certificate::from_der(root.as_ref()).map_err(|error| {
                AnchorError::Parse(format!(
                    "configured TSA trust root is not a valid X.509 certificate: {error}"
                ))
            })?;
            verify_ca_certificate_profile(&certificate, "configured TSA trust root")?;
            let validity = certificate.tbs_certificate.validity;
            if verification_time_unix_secs < validity.not_before.to_unix_duration().as_secs()
                || verification_time_unix_secs > validity.not_after.to_unix_duration().as_secs()
            {
                continue;
            }
            let anchor = webpki::anchor_from_trusted_cert(root).map_err(|error| {
                AnchorError::Parse(format!(
                    "configured TSA trust root is not a valid WebPKI trust anchor: {error}"
                ))
            })?;
            anchors.push(anchor);
        }
        if anchors.is_empty() {
            return Err(AnchorError::Parse(
                "no usable TSA certificate trust anchor is valid at TSTInfo.genTime".to_owned(),
            ));
        }
        Ok(anchors)
    }

    fn verify_intermediate_certificate_profiles(
        path: &webpki::VerifiedPath<'_>,
    ) -> Result<(), AnchorError> {
        for intermediate in path.intermediate_certificates() {
            let certificate =
                Certificate::from_der(intermediate.der().as_ref()).map_err(|error| {
                    AnchorError::Parse(format!(
                        "RFC 3161 TSA intermediate is not a valid X.509 certificate: {error}"
                    ))
                })?;
            verify_ca_certificate_profile(&certificate, "RFC 3161 TSA intermediate")?;
        }
        Ok(())
    }

    fn verify_ca_certificate_profile(
        certificate: &Certificate,
        label: &str,
    ) -> Result<(), AnchorError> {
        let (critical, constraints) = certificate
            .tbs_certificate
            .get::<BasicConstraints>()
            .map_err(|error| {
                AnchorError::Parse(format!("decode {label} basicConstraints: {error}"))
            })?
            .ok_or_else(|| AnchorError::Parse(format!("{label} has no basicConstraints")))?;
        if !critical || !constraints.ca {
            return Err(AnchorError::Parse(format!(
                "{label} basicConstraints must be critical with cA=true"
            )));
        }
        if let Some((_, key_usage)) = certificate
            .tbs_certificate
            .get::<CertificateKeyUsage>()
            .map_err(|error| AnchorError::Parse(format!("decode {label} keyUsage: {error}")))?
        {
            if !key_usage.key_cert_sign() {
                return Err(AnchorError::Parse(format!(
                    "{label} keyUsage does not permit certificate signing"
                )));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::anchoring::test_fixtures::{
            fixture_root_ca_pem, fixture_tsr, FIXTURE_GEN_TIME_UNIX_SECS,
        };

        fn fixture_root_files() -> Vec<Vec<u8>> {
            vec![fixture_root_ca_pem().to_vec()]
        }

        fn fixture_root_certificate() -> Certificate {
            Certificate::load_pem_chain(fixture_root_ca_pem())
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        }

        fn fixture_signer_certificate() -> Certificate {
            let fixture = fixture_tsr();
            let response = TimeStampResp::from_der(&fixture).unwrap();
            let token = response.time_stamp_token.unwrap();
            let signed_data = SignedData::from_der(&token.content.to_der().unwrap()).unwrap();
            signed_data
                .certificates
                .unwrap()
                .0
                .iter()
                .find_map(|choice| match choice {
                    CertificateChoices::Certificate(cert)
                        if cert.tbs_certificate.subject != cert.tbs_certificate.issuer =>
                    {
                        Some(cert.clone())
                    }
                    _ => None,
                })
                .unwrap()
        }

        #[test]
        fn windows_backend_verifies_the_real_timestamp_fixture() {
            let roots = fixture_root_files();
            verify_cms_signature_and_chain(
                &fixture_tsr(),
                Some(&roots),
                FIXTURE_GEN_TIME_UNIX_SECS,
            )
            .unwrap();
        }

        #[test]
        fn windows_backend_requires_operator_pinned_roots() {
            let err =
                verify_cms_signature_and_chain(&fixture_tsr(), None, FIXTURE_GEN_TIME_UNIX_SECS)
                    .unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message)
                    if message.contains("OLYMPUS_ANCHOR_RFC3161_TRUST_ROOTS is required")
            ));
        }

        #[test]
        fn windows_backend_accepts_a_der_encoded_pinned_root() {
            let roots = vec![fixture_root_certificate().to_der().unwrap()];
            verify_cms_signature_and_chain(
                &fixture_tsr(),
                Some(&roots),
                FIXTURE_GEN_TIME_UNIX_SECS,
            )
            .unwrap();
        }

        #[test]
        fn windows_backend_rejects_a_tampered_cms_signature() {
            let fixture = fixture_tsr();
            let mut response = TimeStampResp::from_der(&fixture).unwrap();
            let token = response.time_stamp_token.as_mut().unwrap();
            let mut signed_data = SignedData::from_der(&token.content.to_der().unwrap()).unwrap();
            let signer = signed_data.signer_infos.0.iter().next().unwrap().clone();
            let mut signature = signer.signature.as_bytes().to_vec();
            signature[0] ^= 0x80;
            let mut replacement = signer;
            replacement.signature = OctetString::new(signature).unwrap();
            signed_data.signer_infos =
                cms::signed_data::SignerInfos::try_from(vec![replacement]).unwrap();
            token.content = Any::from_der(&signed_data.to_der().unwrap()).unwrap();
            let tampered = response.to_der().unwrap();

            let roots = fixture_root_files();
            let err =
                verify_cms_signature_and_chain(&tampered, Some(&roots), FIXTURE_GEN_TIME_UNIX_SECS)
                    .unwrap_err();
            assert!(matches!(err, AnchorError::Parse(_)));
        }

        #[test]
        fn signed_message_digest_must_bind_the_tstinfo() {
            let fixture = fixture_tsr();
            let response = TimeStampResp::from_der(&fixture).unwrap();
            let token = response.time_stamp_token.unwrap();
            let signed_data = SignedData::from_der(&token.content.to_der().unwrap()).unwrap();
            let signer = signed_data.signer_infos.0.iter().next().unwrap();
            let attrs = signer.signed_attrs.as_ref().unwrap();
            let digest_kind = digest_kind(&signer.digest_alg, false).unwrap();

            let err =
                verify_signed_attributes(attrs, &signed_data, b"not the TSTInfo", digest_kind)
                    .unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message) if message.contains("does not bind the TSTInfo")
            ));
        }

        #[test]
        fn signed_attributes_wire_order_must_be_canonical() {
            let fixture = fixture_tsr();
            let mut response = TimeStampResp::from_der(&fixture).unwrap();
            let token = response.time_stamp_token.as_mut().unwrap();
            let signed_data_der = token.content.to_der().unwrap();
            let wire_attrs = signed_attributes_wire_der(&signed_data_der).unwrap();
            let attrs_offset = wire_attrs.as_ptr() as usize - signed_data_der.as_ptr() as usize;

            let mut attrs_value = {
                let mut wire = wire_attrs;
                take_der_tlv(&mut wire, "test signedAttrs").unwrap().value
            };
            let first = take_der_tlv(&mut attrs_value, "first signed attribute").unwrap();
            let second = take_der_tlv(&mut attrs_value, "second signed attribute").unwrap();
            let mut reordered = Vec::with_capacity(wire_attrs.len());
            let header_length =
                wire_attrs.len() - first.full.len() - second.full.len() - attrs_value.len();
            reordered.extend_from_slice(&wire_attrs[..header_length]);
            reordered.extend_from_slice(second.full);
            reordered.extend_from_slice(first.full);
            reordered.extend_from_slice(attrs_value);
            assert_eq!(reordered.len(), wire_attrs.len());
            let wire_attrs_length = wire_attrs.len();

            let mut non_canonical_signed_data = signed_data_der;
            non_canonical_signed_data[attrs_offset..attrs_offset + wire_attrs_length]
                .copy_from_slice(&reordered);
            token.content = Any::from_der(&non_canonical_signed_data).unwrap();
            let non_canonical_response = response.to_der().unwrap();
            let roots = fixture_root_files();
            let err = verify_cms_signature_and_chain(
                &non_canonical_response,
                Some(&roots),
                FIXTURE_GEN_TIME_UNIX_SECS,
            )
            .unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message) if message.contains("canonical DER wire order")
            ));
        }

        #[test]
        fn signing_certificate_attribute_must_bind_the_signer_certificate() {
            let fixture = fixture_tsr();
            let response = TimeStampResp::from_der(&fixture).unwrap();
            let token = response.time_stamp_token.unwrap();
            let signed_data = SignedData::from_der(&token.content.to_der().unwrap()).unwrap();
            let signer = signed_data.signer_infos.0.iter().next().unwrap();
            let attrs = signer.signed_attrs.as_ref().unwrap();
            let signer_cert = signed_data
                .certificates
                .as_ref()
                .unwrap()
                .0
                .iter()
                .find_map(|choice| match choice {
                    CertificateChoices::Certificate(cert)
                        if cert.tbs_certificate.subject != cert.tbs_certificate.issuer =>
                    {
                        Some(cert)
                    }
                    _ => None,
                })
                .unwrap();

            let err = verify_signing_certificate_attribute(
                attrs,
                signer_cert,
                b"not the signer certificate",
            )
            .unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message)
                    if message.contains("does not identify the TSA signer certificate")
            ));
        }

        #[test]
        fn chain_is_checked_at_the_tstinfo_generation_time() {
            let roots = fixture_root_files();
            let err = verify_cms_signature_and_chain(&fixture_tsr(), Some(&roots), 0).unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message)
                    if message.contains("TSTInfo.genTime")
            ));
        }

        #[test]
        fn timestamp_profile_requires_a_critical_exclusive_eku() {
            let fixture = fixture_tsr();
            let response = TimeStampResp::from_der(&fixture).unwrap();
            let token = response.time_stamp_token.unwrap();
            let signed_data = SignedData::from_der(&token.content.to_der().unwrap()).unwrap();
            let mut signer_cert = signed_data
                .certificates
                .unwrap()
                .0
                .iter()
                .find_map(|choice| match choice {
                    CertificateChoices::Certificate(cert)
                        if cert.tbs_certificate.subject != cert.tbs_certificate.issuer =>
                    {
                        Some(cert.clone())
                    }
                    _ => None,
                })
                .unwrap();

            verify_timestamping_certificate_profile(&signer_cert).unwrap();
            let extensions = signer_cert.tbs_certificate.extensions.as_mut().unwrap();
            let eku = extensions
                .iter_mut()
                .find(|extension| extension.extn_id == ID_CE_EXT_KEY_USAGE)
                .unwrap();
            eku.critical = false;
            assert!(verify_timestamping_certificate_profile(&signer_cert).is_err());
        }

        #[test]
        fn configured_trust_root_must_be_a_ca() {
            let root = CertificateDer::from(fixture_signer_certificate().to_der().unwrap());
            let err = build_trust_anchors(&[root], FIXTURE_GEN_TIME_UNIX_SECS).unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message)
                    if message.contains("configured TSA trust root")
                        && message.contains("basicConstraints")
            ));
        }

        #[test]
        fn intermediate_profile_allows_an_absent_eku() {
            let mut intermediate = fixture_root_certificate();
            intermediate
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .retain(|extension| extension.extn_id != ID_CE_EXT_KEY_USAGE);
            verify_ca_certificate_profile(&intermediate, "test intermediate").unwrap();
        }

        #[test]
        fn intermediate_profile_rejects_missing_basic_constraints() {
            let mut intermediate = fixture_root_certificate();
            intermediate
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .retain(|extension| extension.extn_id != ID_CE_BASIC_CONSTRAINTS);
            let err =
                verify_ca_certificate_profile(&intermediate, "test intermediate").unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message) if message.contains("has no basicConstraints")
            ));
        }

        #[test]
        fn intermediate_profile_rejects_key_usage_without_key_cert_sign() {
            let mut intermediate = fixture_root_certificate();
            let key_usage = intermediate
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|extension| extension.extn_id == ID_CE_KEY_USAGE)
                .expect("fixture CA has a keyUsage extension");
            let digital_signature_only =
                CertificateKeyUsage(x509_cert::ext::pkix::KeyUsages::DigitalSignature.into())
                    .to_der()
                    .unwrap();
            key_usage.extn_value = OctetString::new(digital_signature_only).unwrap();

            let err =
                verify_ca_certificate_profile(&intermediate, "test intermediate").unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message)
                    if message.contains("does not permit certificate signing")
            ));
        }

        #[test]
        fn ess_issuer_serial_must_match_the_signer() {
            let signer = fixture_signer_certificate();
            let matching = IssuerSerial {
                issuer: vec![GeneralName::DirectoryName(
                    signer.tbs_certificate.issuer.clone(),
                )],
                serial_number: signer.tbs_certificate.serial_number.clone(),
            };
            let parsed = IssuerSerial::from_der(&matching.to_der().unwrap()).unwrap();
            verify_ess_issuer_serial(Some(&parsed), &signer, "SigningCertificateV2").unwrap();

            let mut wrong_serial = parsed.clone();
            wrong_serial.serial_number = SerialNumber::from(u64::MAX);
            let err =
                verify_ess_issuer_serial(Some(&wrong_serial), &signer, "SigningCertificateV2")
                    .unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message) if message.contains("serial number")
            ));

            let wrong_issuer = IssuerSerial {
                issuer: vec![GeneralName::RegisteredId(ID_SHA256)],
                serial_number: signer.tbs_certificate.serial_number.clone(),
            };
            let err =
                verify_ess_issuer_serial(Some(&wrong_issuer), &signer, "SigningCertificateV2")
                    .unwrap_err();
            assert!(matches!(
                err,
                AnchorError::Parse(message) if message.contains("signer issuer")
            ));
        }
    }
}

#[cfg(target_os = "windows")]
pub(super) fn verify_cms_signature_and_chain(
    response_der: &[u8],
    configured_trust_root_files: Option<&[Vec<u8>]>,
    verification_time_unix_secs: u64,
) -> Result<(), AnchorError> {
    windows::verify_cms_signature_and_chain(
        response_der,
        configured_trust_root_files,
        verification_time_unix_secs,
    )
}
