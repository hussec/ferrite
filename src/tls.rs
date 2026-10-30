use crate::project::Project;
use anyhow::Result;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use rcgen::{CertificateParams, DistinguishedName, DnType, PublicKeyData};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

struct RustKey {
    key: SigningKey,
    public: Vec<u8>,
}
impl RustKey {
    fn new() -> Self {
        Self::from_key(SigningKey::random(&mut rand_core::OsRng))
    }
    fn from_key(key: SigningKey) -> Self {
        let public = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { key, public }
    }
    fn pkcs8(&self) -> Result<Vec<u8>> {
        Ok(self.key.to_pkcs8_der()?.as_bytes().to_vec())
    }
}
impl PublicKeyData for RustKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
impl rcgen::SigningKey for RustKey {
    fn sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let sig: Signature = self.key.sign(msg);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}
struct AuthorityState {
    issuer: rcgen::Issuer<'static, RustKey>,
    certificate: rcgen::Certificate,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}
pub struct Authority {
    state: std::sync::RwLock<AuthorityState>,
}
impl Authority {
    pub fn generate_key() -> Result<Vec<u8>> {
        RustKey::new().pkcs8()
    }
    pub fn load(project: &mut Project) -> Result<Self> {
        let key = match project.ca_key() {
            Some(der) => RustKey::from_key(SigningKey::from_pkcs8_der(&der)?),
            None => {
                let key = RustKey::new();
                project.set_ca_key(key.pkcs8()?)?;
                key
            }
        };
        Self::from_rust_key(key)
    }
    pub fn from_key(der: &[u8]) -> Result<Self> {
        Self::from_rust_key(RustKey::from_key(SigningKey::from_pkcs8_der(der)?))
    }
    fn from_rust_key(key: RustKey) -> Result<Self> {
        let mut params = CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        // Explicit key-id method avoids rcgen's optional C-backed crypto feature.
        params.key_identifier_method =
            rcgen::KeyIdMethod::PreSpecified(Sha256::digest(&key.public)[..20].to_vec());
        let mut serial = Sha256::digest(&key.public)[..20].to_vec();
        serial[0] &= 0x7f;
        params.serial_number = Some(serial.into());
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Ferrite Project CA");
        params.distinguished_name = dn;
        let certificate = params.self_signed(&key)?;
        let issuer = rcgen::Issuer::new(params, key);
        Ok(Self {
            state: std::sync::RwLock::new(AuthorityState {
                issuer,
                certificate,
                cache: Mutex::new(HashMap::new()),
            }),
        })
    }
    pub fn pem(&self) -> String {
        self.state.read().unwrap().certificate.pem()
    }
    pub fn der(&self) -> CertificateDer<'static> {
        self.state.read().unwrap().certificate.der().clone()
    }
    fn issue_certificate(
        state: &AuthorityState,
        host: &str,
    ) -> Result<(rcgen::Certificate, RustKey)> {
        let key = RustKey::new();
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_identifier_method =
            rcgen::KeyIdMethod::PreSpecified(Sha256::digest(&key.public)[..20].to_vec());
        let mut serial = Sha256::digest(&key.public)[..20].to_vec();
        serial[0] &= 0x7f;
        params.serial_number = Some(serial.into());
        // Let clients distinguish this issuer from other Ferrite project CAs with
        // the same subject name, including certificates already trusted by Firefox.
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &state.issuer)?;
        Ok((cert, key))
    }
    pub fn replace(&self, authority: Self) {
        *self.state.write().unwrap() = authority.state.into_inner().unwrap();
    }
    pub fn fingerprint(&self) -> String {
        Sha256::digest(self.state.read().unwrap().certificate.der().as_ref())
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let state = self.state.read().unwrap();
        let mut cache = state.cache.lock().unwrap();
        if let Some(config) = cache.get(host) {
            return Ok(config.clone());
        }
        let (cert, key) = Self::issue_certificate(&state, host)?;
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone(), state.certificate.der().clone()],
                PrivatePkcs8KeyDer::from(key.pkcs8()?).into(),
            )?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(host.into(), config.clone());
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_certificate_identifies_its_project_ca() {
        let mut project = Project::temporary();
        let authority = Authority::load(&mut project).unwrap();
        let other = Authority::load(&mut Project::temporary()).unwrap();
        let (cert, _) =
            Authority::issue_certificate(&authority.state.read().unwrap(), "www.google.com")
                .unwrap();
        let key =
            RustKey::from_key(SigningKey::from_pkcs8_der(&project.ca_key().unwrap()).unwrap());
        let digest = Sha256::digest(&key.public);
        let issuer_id = &digest[..20];
        // AuthorityKeyIdentifier is a sequence containing context tag 0 and the key identifier.
        let mut extension = vec![0x30, 0x16, 0x80, 0x14];
        extension.extend_from_slice(issuer_id);
        assert!(
            cert.der()
                .as_ref()
                .windows(extension.len())
                .any(|v| v == extension)
        );
        assert_ne!(authority.fingerprint(), other.fingerprint());
    }
}
