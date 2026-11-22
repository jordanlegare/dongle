#![no_main]
#![no_std]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use core::time::Duration;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uefi::{
    boot::{self, LoadImageSource},
    prelude::*,
    proto::{
        BootPolicy,
        device_path::text::DevicePathFromText,
        network::{
            http::{HttpHelper, HttpMethod},
            ip4config2::Ip4Config2,
            snp::SimpleNetwork,
        },
        tcg::{HashAlgorithm, v2::Tcg},
        unsafe_protocol,
    },
};

const MAX_SIGNATURE: usize = 512;
const MAX_QUOTE: usize = 4096;
const MAX_PCR_DATA: usize = 4096;

// UEFI TLS Service Binding and TLS Configuration protocol GUIDs.
// Firmware must expose these and enforce peer certificate validation.
const TLS_SERVICE_BINDING: Guid = guid!("952cb795-ff36-48cf-a249-4df486d6ab8d");
const TLS_CONFIGURATION: Guid = guid!("1682fe44-bd7a-4407-b7c7-dca37ca3922d");

// Vendor adapter contract. Install a signed UEFI driver implementing this
// protocol before this application in the firmware driver/boot sequence.
#[unsafe_protocol("8bc0c4a2-12d2-4e8c-a51a-6d6a9c2e1001")]
#[repr(C)]
struct DongleAttestationProtocol {
    revision: u32,
    attest: unsafe extern "efiapi" fn(
        this: *mut DongleAttestationProtocol,
        nonce: *const u8,
        nonce_len: usize,
        transcript: *const u8,
        transcript_len: usize,
        evidence: *mut AttestationEvidence,
    ) -> Status,
}

#[repr(C)]
struct AttestationEvidence {
    dongle_signature: [u8; MAX_SIGNATURE],
    dongle_signature_len: usize,
    quote_message: [u8; MAX_QUOTE],
    quote_message_len: usize,
    quote_signature: [u8; MAX_SIGNATURE],
    quote_signature_len: usize,
    pcr_values: [u8; MAX_PCR_DATA],
    pcr_values_len: usize,
}

impl AttestationEvidence {
    fn new() -> Self {
        Self {
            dongle_signature: [0; MAX_SIGNATURE],
            dongle_signature_len: 0,
            quote_message: [0; MAX_QUOTE],
            quote_message_len: 0,
            quote_signature: [0; MAX_SIGNATURE],
            quote_signature_len: 0,
            pcr_values: [0; MAX_PCR_DATA],
            pcr_values_len: 0,
        }
    }

    fn validate(&self) -> Result<(), Status> {
        if self.dongle_signature_len == 0
            || self.dongle_signature_len > self.dongle_signature.len()
            || self.quote_message_len == 0
            || self.quote_message_len > self.quote_message.len()
            || self.quote_signature_len == 0
            || self.quote_signature_len > self.quote_signature.len()
            || self.pcr_values_len == 0
            || self.pcr_values_len > self.pcr_values.len()
        {
            return Err(Status::SECURITY_VIOLATION);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeRequest<'a> {
    user_id: &'a str,
    dongle_id: &'a str,
    asset_id: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    challenge_id: String,
    nonce_hex: String,
    signing_payload_b64: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeRequest<'a> {
    challenge_id: &'a str,
    user_id: &'a str,
    dongle_id: &'a str,
    asset_id: &'a str,
    dongle_signature_b64: String,
    quote_message_b64: String,
    quote_signature_b64: String,
    pcr_values_b64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeResponse {
    allowed: bool,
    reason: String,
}

fn config_value(value: Option<&'static str>) -> Result<&'static str, Status> {
    match value {
        Some(text) if !text.trim().is_empty() => Ok(text),
        _ => Err(Status::INVALID_PARAMETER),
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Status> {
    if input.is_empty() || input.len() % 2 != 0 {
        return Err(Status::SECURITY_VIOLATION);
    }

    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or(Status::SECURITY_VIOLATION)?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or(Status::SECURITY_VIOLATION)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn has_protocol(guid: &Guid) -> bool {
    boot::locate_handle_buffer(boot::SearchType::ByProtocol(guid)).is_ok()
}

fn configure_dhcp() -> Result<Vec<Handle>, Status> {
    let nics = boot::find_handles::<SimpleNetwork>().map_err(|_| Status::NOT_FOUND)?;
    if nics.is_empty() {
        return Err(Status::NOT_FOUND);
    }

    let mut configured = false;
    for nic in &nics {
        if let Ok(mut ip4) = Ip4Config2::new(*nic) {
            // One NIC may be unplugged or lack DHCP; try every firmware NIC.
            // Authorization remains blocked unless at least one obtains IPv4.
            if ip4.ifup().is_ok() {
                configured = true;
            }
        }
    }
    if !configured {
        return Err(Status::UNSUPPORTED);
    }

    Ok(nics)
}

fn check_tpm2_sha256() -> Result<(), Status> {
    let handles = boot::find_handles::<Tcg>().map_err(|_| Status::NOT_FOUND)?;
    let handle = *handles.first().ok_or(Status::NOT_FOUND)?;
    let mut tcg =
        boot::open_protocol_exclusive::<Tcg>(handle).map_err(|_| Status::UNSUPPORTED)?;
    let capability = tcg.get_capability().map_err(|_| Status::DEVICE_ERROR)?;
    if !capability.tpm_present() || !capability.active_pcr_banks.contains(HashAlgorithm::SHA256) {
        return Err(Status::UNSUPPORTED);
    }
    Ok(())
}

fn connect_https() -> Result<HttpHelper, Status> {
    // EFI_HTTP_PROTOCOL only provides HTTPS when the firmware HTTP/TLS stack
    // and TLS trust configuration are installed.
    if !has_protocol(&TLS_SERVICE_BINDING) || !has_protocol(&TLS_CONFIGURATION) {
        return Err(Status::UNSUPPORTED);
    }

    let nics = boot::find_handles::<SimpleNetwork>().map_err(|_| Status::NOT_FOUND)?;
    for nic in nics {
        if let Ok(mut http) = HttpHelper::new(nic) {
            if http.configure().is_ok() {
                return Ok(http);
            }
        }
    }
    Err(Status::UNSUPPORTED)
}

fn post_json<T: DeserializeOwned>(
    http: &mut HttpHelper,
    url: &str,
    request: &[u8],
) -> Result<T, Status> {
    let mut body = request.to_vec();
    http.request(HttpMethod::POST, url, Some(&mut body))
        .map_err(|_| Status::DEVICE_ERROR)?;
    let response = http
        .response_first(true)
        .map_err(|_| Status::DEVICE_ERROR)?;

    // Non-2xx policy-service responses contain an error object instead of the
    // expected response schema and therefore fail deserialization closed.
    serde_json::from_slice(&response.body).map_err(|_| Status::SECURITY_VIOLATION)
}

fn collect_evidence(
    challenge: &ChallengeResponse,
    provider_handle: Handle,
) -> Result<AttestationEvidence, Status> {
    let nonce = decode_hex(&challenge.nonce_hex)?;
    let transcript = STANDARD
        .decode(challenge.signing_payload_b64.as_bytes())
        .map_err(|_| Status::SECURITY_VIOLATION)?;
    if nonce.len() != 32 || transcript.is_empty() {
        return Err(Status::SECURITY_VIOLATION);
    }

    let mut provider = boot::open_protocol_exclusive::<DongleAttestationProtocol>(provider_handle)
        .map_err(|_| Status::UNSUPPORTED)?;
    if provider.revision != 1 {
        return Err(Status::INCOMPATIBLE_VERSION);
    }

    let mut evidence = AttestationEvidence::new();
    let protocol = &mut *provider;
    // The protocol is supplied by a separately installed, signed platform
    // driver. It must validate all pointer lengths and return only evidence
    // produced by the enrolled key and TPM; no private material is exported.
    let status = unsafe {
        (protocol.attest)(
            protocol,
            nonce.as_ptr(),
            nonce.len(),
            transcript.as_ptr(),
            transcript.len(),
            &mut evidence,
        )
    };
    if status != Status::SUCCESS {
        return Err(Status::SECURITY_VIOLATION);
    }
    evidence.validate()?;
    Ok(evidence)
}

fn authorize() -> Result<(), Status> {
    let server = config_value(option_env!("DONGLE_UEFI_SERVER"))?;
    let user_id = config_value(option_env!("DONGLE_UEFI_USER_ID"))?;
    let dongle_id = config_value(option_env!("DONGLE_UEFI_DONGLE_ID"))?;
    let asset_id = config_value(option_env!("DONGLE_UEFI_ASSET_ID"))?;

    if !server.starts_with("https://") {
        return Err(Status::INVALID_PARAMETER);
    }

    uefi::println!("Dongle UEFI pre-OS authorization");
    uefi::println!("Configuring network with firmware DHCP...");
    let _nics = configure_dhcp()?;

    uefi::println!("Checking TPM 2.0 and SHA-256 PCR bank...");
    check_tpm2_sha256()?;

    let provider_handle = boot::get_handle_for_protocol::<DongleAttestationProtocol>()
        .map_err(|_| Status::NOT_FOUND)?;

    uefi::println!("Checking firmware HTTPS/TLS support...");
    let mut http = connect_https()?;

    let base = server.trim_end_matches('/');
    let challenge_url = format!("{base}/v1/uefi/challenge");
    let challenge_body = serde_json::to_vec(&ChallengeRequest {
        user_id,
        dongle_id,
        asset_id,
    })
    .map_err(|_| Status::OUT_OF_RESOURCES)?;

    uefi::println!("Requesting a one-time authorization challenge...");
    let challenge: ChallengeResponse = post_json(&mut http, &challenge_url, &challenge_body)?;

    uefi::println!("Requesting dongle signature and TPM quote...");
    let evidence = collect_evidence(&challenge, provider_handle)?;

    let authorize_url = format!("{base}/v1/uefi/authorize");
    let authorization_body = serde_json::to_vec(&AuthorizeRequest {
        challenge_id: &challenge.challenge_id,
        user_id,
        dongle_id,
        asset_id,
        dongle_signature_b64: STANDARD
            .encode(&evidence.dongle_signature[..evidence.dongle_signature_len]),
        quote_message_b64: STANDARD.encode(&evidence.quote_message[..evidence.quote_message_len]),
        quote_signature_b64: STANDARD
            .encode(&evidence.quote_signature[..evidence.quote_signature_len]),
        pcr_values_b64: STANDARD.encode(&evidence.pcr_values[..evidence.pcr_values_len]),
    })
    .map_err(|_| Status::OUT_OF_RESOURCES)?;

    uefi::println!("Submitting hardware and measured-boot evidence...");
    let decision: AuthorizeResponse = post_json(&mut http, &authorize_url, &authorization_body)?;
    if !decision.allowed {
        uefi::println!("Authorization denied: {}", decision.reason);
        return Err(Status::ACCESS_DENIED);
    }

    uefi::println!("Authorization granted for asset {}.", asset_id);
    Ok(())
}

fn chainload_next_stage() -> Result<(), Status> {
    let device_path_text = config_value(option_env!("DONGLE_UEFI_NEXT_BOOT_DEVICE_PATH"))?;
    let device_path_text =
        uefi::CString16::try_from(device_path_text).map_err(|_| Status::INVALID_PARAMETER)?;

    let parser_handle =
        boot::get_handle_for_protocol::<DevicePathFromText>().map_err(|_| Status::UNSUPPORTED)?;
    let device_path = {
        let parser = boot::open_protocol_exclusive::<DevicePathFromText>(parser_handle)
            .map_err(|_| Status::UNSUPPORTED)?;
        parser
            .convert_text_to_device_path(&device_path_text)
            .map_err(|_| Status::INVALID_PARAMETER)?
    };

    uefi::println!("Loading the configured next-stage bootloader...");
    let image = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromDevicePath {
            device_path: &device_path,
            boot_policy: BootPolicy::BootSelection,
        },
    )
    .map_err(|_| Status::SECURITY_VIOLATION)?;

    // UEFI LoadImage enforces the platform Secure Boot image policy.
    // If the next loader unexpectedly returns, do not hand control back to
    // Boot Manager, which might try an unauthenticated fallback Boot#### entry.
    boot::start_image(image).map_err(|_| Status::ABORTED)?;
    Err(Status::ABORTED)
}

fn halt_on_denial() -> ! {
    // Keep control in the authenticated stage. Returning an error to firmware
    // can cause some Boot Managers to attempt the next Boot#### option.
    loop {
        boot::stall(Duration::from_secs(5));
    }
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::LOAD_ERROR;
    }

    if let Err(status) = authorize() {
        uefi::println!("Dongle pre-OS gate denied boot: {}", status);
        halt_on_denial();
    }

    if let Err(status) = chainload_next_stage() {
        uefi::println!("Unable to start approved next boot stage: {}", status);
        halt_on_denial();
    }

    halt_on_denial()
}
