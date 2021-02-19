//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{crypto, proto, HKDF, PublicKey, IdentityKeyPair, PrivateKey, IdentityKey};
use crate::error::{SignalProtocolError, Result};

use std::convert::TryFrom;

use prost::Message;
use subtle::ConstantTimeEq;

pub struct ProvisioningUuid {
    uuid: String
}

impl ProvisioningUuid {
    #[inline]
    pub fn uuid(&self) -> &String {
        &self.uuid
    }
}

impl TryFrom<&[u8]> for ProvisioningUuid {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let proto_structure =
            proto::device_messages::ProvisioningUuid::decode(value)?;

        let uuid = proto_structure
            .uuid
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        Ok(ProvisioningUuid {
            uuid
        })
    }
}

pub struct ProvisionEnvelope {
    public_key: PublicKey,
    body: Box<[u8]>,
}

impl ProvisionEnvelope {
    const MAC_LENGTH: usize = 32;
    const IV_LENGTH: usize = 16;

    #[inline]
    pub fn body(&self) -> &[u8] {
        &*self.body
    }

    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn decrypt(&self, ephemeral_private_key: PrivateKey) -> Result<Vec<u8>> {
        let ec_res = ephemeral_private_key.calculate_agreement(self.public_key())?;
        let hkdf = HKDF::new(3)?;
        let secrets = hkdf.derive_secrets(&ec_res, "TextSecure Provisioning Message".as_bytes(), 64)?;
        let (cipher_key, mac_key) = secrets.split_at(32);

        let mac_valid = self.verify_mac(mac_key)?;

        if !mac_valid {
            return Err(SignalProtocolError::InvalidCiphertext);
        }
        let (iv, body) = self.body[1..self.body.len() - Self::MAC_LENGTH].split_at(Self::IV_LENGTH);
        crypto::aes_256_cbc_decrypt(body, cipher_key, iv)
    }

    pub fn verify_mac(&self, mac_key: &[u8]) -> Result<bool> {
        let our_mac = &Self::compute_mac(
            mac_key,
            &self.body[..self.body.len() - Self::MAC_LENGTH])?;
        let their_mac = &self.body[self.body.len() - Self::MAC_LENGTH..];
        let result: bool = our_mac.ct_eq(their_mac).into();
        if !result {
            log::error!(
                "Bad Mac! Their Mac: {} Our Mac: {}",
                hex::encode(their_mac),
                hex::encode(our_mac)
            );
        }
        Ok(result)
    }

    fn compute_mac(
        mac_key: &[u8],
        message: &[u8],
    ) -> Result<[u8; Self::MAC_LENGTH]> {
        if mac_key.len() != 32 {
            return Err(SignalProtocolError::InvalidMacKeyLength(mac_key.len()));
        }
        crypto::hmac_sha256(mac_key, message)
    }
}

impl TryFrom<&[u8]> for ProvisionEnvelope {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let proto_structure =
            proto::device_messages::ProvisionEnvelope::decode(value)?;

        let body = proto_structure
            .body
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into_boxed_slice();
        let public_key = proto_structure
            .public_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let public_key = PublicKey::deserialize(public_key.as_slice())?;

        Ok(ProvisionEnvelope {
            public_key,
            body
        })
    }
}

#[derive(Clone)]
pub struct ProvisionMessage {
    identity_key_pair: IdentityKeyPair,
    number: String,
    provisioning_code: String,
    uuid: Option<String>,
    user_agent: Option<String>,
    read_receipts: Option<bool>,
}

impl ProvisionMessage {
    #[inline]
    pub fn identity_key_pair(&self) -> &IdentityKeyPair { &self.identity_key_pair }

    #[inline]
    pub fn number(&self) -> &String { &self.number }

    #[inline]
    pub fn provisioning_code(&self) -> &String { &self.provisioning_code }

    #[inline]
    pub fn uuid(&self) -> &Option<String> { &self.uuid }

    #[inline]
    pub fn user_agent(&self) -> &Option<String> { &self.user_agent }

    #[inline]
    pub fn read_receipts(&self) -> &Option<bool> { &self.read_receipts }
}

impl TryFrom<&[u8]> for ProvisionMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let proto_structure =
            proto::device_messages::ProvisionMessage::decode(value)?;

        let private_key = proto_structure
            .identity_key_private
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let private_key = PrivateKey::deserialize(private_key.as_slice())?;
        let public_key = private_key.public_key()?;
        let identity_key_pair = IdentityKeyPair::new(IdentityKey::new(public_key), private_key);

        let number = proto_structure
            .number
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let provisioning_code = proto_structure
            .provisioning_code
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let uuid = proto_structure
            .uuid
            .map(|x| x.to_lowercase());

        Ok(ProvisionMessage {
            identity_key_pair,
            number,
            provisioning_code,
            uuid,
            user_agent: proto_structure.user_agent,
            read_receipts: proto_structure.read_receipts,
        })
    }
}
