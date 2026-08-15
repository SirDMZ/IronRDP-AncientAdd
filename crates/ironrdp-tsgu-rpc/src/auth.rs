//! NTLM authentication driver over `sspi` - the HTTP-layer auth for the RPC
//! transport (and, later, the same context provides RPC packet sign/seal).
//!
//! Standard connection-oriented HTTP NTLM: the client sends the Type-1 token in
//! `Authorization: NTLM ...`, the server replies `401` with the Type-2 challenge in
//! `WWW-Authenticate: NTLM ...`, and the client answers with the Type-3 token on the
//! same connection.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, EncryptionFlags, Ntlm,
    SecurityBuffer, SecurityBufferFlags, SecurityBufferRef, SecurityStatus, Sspi as _, SspiImpl, Username,
};
use tracing::{debug, trace};

use crate::GatewayError;
use crate::http::{Channel, Response};

/// Drives NTLM for one RPC channel: owns the `sspi` context and credentials.
///
/// The same type serves both NTLM roles in the transport: the HTTP-layer auth on
/// each channel ([`NtlmAuth::new`]) and the RPC-layer bind ([`NtlmAuth::new_dce`],
/// which requests the DCE-style, sign-capable context the secure bind needs).
pub struct NtlmAuth {
    ntlm: Ntlm,
    creds: <Ntlm as SspiImpl>::CredentialsHandle,
    flags: ClientRequestFlags,
    complete: bool,
}

impl NtlmAuth {
    /// Build an HTTP-layer NTLM context for `username`(`@domain`)/`password`.
    pub fn new(username: &str, domain: Option<&str>, password: &str) -> Result<Self, GatewayError> {
        Self::build(
            username,
            domain,
            password,
            ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
        )
    }

    /// Build the DCE/RPC-style NTLM context for the secure bind: sign-capable
    /// (sequence/replay detected) DCE-style, matching FreeRDP's ISC flags. This
    /// context also produces the per-request signatures at PKT_INTEGRITY (Layer 4).
    pub fn new_dce(username: &str, domain: Option<&str>, password: &str) -> Result<Self, GatewayError> {
        Self::build(
            username,
            domain,
            password,
            ClientRequestFlags::USE_DCE_STYLE
                | ClientRequestFlags::DELEGATE
                | ClientRequestFlags::REPLAY_DETECT
                | ClientRequestFlags::SEQUENCE_DETECT
                | ClientRequestFlags::ALLOCATE_MEMORY,
        )
    }

    fn build(
        username: &str,
        domain: Option<&str>,
        password: &str,
        flags: ClientRequestFlags,
    ) -> Result<Self, GatewayError> {
        let mut ntlm = Ntlm::new();
        let identity = AuthIdentity {
            username: Username::new(username, domain).map_err(|e| GatewayError::Invalid(format!("username: {e}")))?,
            password: password.to_owned().into(),
        };
        let creds = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)
            .map_err(|e| GatewayError::Protocol(format!("NTLM acquire_credentials: {e}")))?
            .credentials_handle;
        Ok(NtlmAuth {
            ntlm,
            creds,
            flags,
            complete: false,
        })
    }

    /// One `InitializeSecurityContext` step. `input` is the server's challenge
    /// (Type-2) on the second call, `None` on the first. Returns the token to send.
    pub(crate) fn step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, GatewayError> {
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let mut input_bufs = input.map(|t| vec![SecurityBuffer::new(t.to_vec(), BufferType::Token)]);

        let flags = self.flags;
        let mut builder = self
            .ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut self.creds)
            .with_context_requirements(flags)
            .with_target_data_representation(DataRepresentation::Native)
            .with_output(&mut output);
        if let Some(bufs) = input_bufs.as_mut() {
            builder = builder.with_input(bufs);
        }

        let status = self
            .ntlm
            .initialize_security_context_impl(&mut builder)
            .map_err(|e| GatewayError::Protocol(format!("NTLM initialize_security_context: {e}")))?
            .resolve_to_result()
            .map_err(|e| GatewayError::Protocol(format!("NTLM resolve: {e}")))?
            .status;

        self.complete = matches!(status, SecurityStatus::Ok | SecurityStatus::CompleteNeeded);
        let token = output.remove(0).buffer;
        trace!(?status, token_len = token.len(), "NTLM step");
        Ok(token)
    }

    /// The `sspi` context, for later RPC-layer `encrypt_message`/`decrypt_message`.
    pub fn context(&mut self) -> &mut Ntlm {
        &mut self.ntlm
    }

    /// Whether the handshake has completed.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Produce the 16-byte NTLM signature over `to_sign` for a PKT_INTEGRITY RPC
    /// request. The data is passed READONLY, so `encrypt_message` signs it without
    /// sealing (the stub stays cleartext); sspi tracks the send sequence number.
    pub(crate) fn sign(&mut self, to_sign: &[u8]) -> Result<Vec<u8>, GatewayError> {
        // encrypt_message needs mutable slices even for READONLY data.
        let mut data = to_sign.to_vec();
        let mut token = vec![0u8; RPC_SIGNATURE_SIZE];
        {
            let mut msg = [
                SecurityBufferRef::data_buf(&mut data).with_flags(SecurityBufferFlags::SECBUFFER_READONLY),
                SecurityBufferRef::token_buf(&mut token),
            ];
            self.ntlm
                .encrypt_message(EncryptionFlags::empty(), &mut msg)
                .map_err(|e| GatewayError::Protocol(format!("RPC request sign: {e}")))?;
        }
        Ok(token)
    }
}

/// NTLM message-signature length (version + checksum + seq num).
pub(crate) const RPC_SIGNATURE_SIZE: usize = 16;

/// Run the NTLM handshake for `method` (`RPC_IN_DATA`/`RPC_OUT_DATA`) on `channel`,
/// returning the final response. `final_content_length` is declared on the Type-3
/// request (the auth probe uses 0; the real transport declares the data-channel
/// size). Extra `headers` (e.g. the RPC connection cookies) ride every request.
pub async fn authenticate(
    channel: &mut Channel,
    method: &str,
    auth: &mut NtlmAuth,
    final_content_length: u64,
    extra: &[(&str, String)],
) -> Result<Response, GatewayError> {
    // Type-1
    let type1 = auth.step(None)?;
    let mut headers = vec![("Authorization", format!("NTLM {}", B64.encode(&type1)))];
    headers.extend(extra.iter().cloned());
    channel.send(method, 0, &headers, &[]).await?;
    let resp = channel.recv().await?;
    debug!(status = resp.status, "NTLM: sent Type-1");

    if resp.status != 401 {
        // No challenge - either already authorized or an outright rejection.
        return Ok(resp);
    }
    let type2 = resp
        .www_authenticate_ntlm()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GatewayError::Protocol("gateway 401 without an NTLM challenge".into()))?;
    let type2 = B64
        .decode(type2)
        .map_err(|e| GatewayError::Protocol(format!("bad NTLM challenge base64: {e}")))?;

    // Type-3
    let type3 = auth.step(Some(&type2))?;
    let mut headers = vec![("Authorization", format!("NTLM {}", B64.encode(&type3)))];
    headers.extend(extra.iter().cloned());
    channel.send(method, final_content_length, &headers, &[]).await?;
    let resp = channel.recv().await?;
    debug!(status = resp.status, complete = auth.is_complete(), "NTLM: sent Type-3");
    Ok(resp)
}

/// Drive NTLM up to and including the Type-3 request *head* - with the channel's
/// real `final_content_length` - but do **not** read any post-Type-3 response.
///
/// The RPC channels can't use [`authenticate`]: after the Type-3 the caller must
/// stream the channel payload (the OUT channel's body is the CONN/A1 PDU; the IN
/// channel's is a 1 GiB request body that stays open). So this returns with the
/// Type-3 head on the wire and the stream ready for the caller to write the PDU.
pub async fn authenticate_streaming(
    channel: &mut Channel,
    method: &str,
    auth: &mut NtlmAuth,
    final_content_length: u64,
    extra: &[(&str, String)],
) -> Result<(), GatewayError> {
    // Type-1 (Content-Length 0) -> expect a 401 with the Type-2 challenge.
    let type1 = auth.step(None)?;
    let mut headers = vec![("Authorization", format!("NTLM {}", B64.encode(&type1)))];
    headers.extend(extra.iter().cloned());
    channel.send_head(method, 0, &headers).await?;
    let resp = channel.recv().await?;
    debug!(status = resp.status, %method, "NTLM(stream): sent Type-1");
    if resp.status != 401 {
        return Err(GatewayError::Protocol(format!(
            "{method}: expected 401 NTLM challenge, got {} {}",
            resp.status, resp.reason
        )));
    }
    let type2 = resp
        .www_authenticate_ntlm()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GatewayError::Protocol("gateway 401 without an NTLM challenge".into()))?;
    let type2 = B64
        .decode(type2)
        .map_err(|e| GatewayError::Protocol(format!("bad NTLM challenge base64: {e}")))?;

    // Type-3 head with the channel's real Content-Length; caller streams the body.
    let type3 = auth.step(Some(&type2))?;
    let mut headers = vec![("Authorization", format!("NTLM {}", B64.encode(&type3)))];
    headers.extend(extra.iter().cloned());
    channel.send_head(method, final_content_length, &headers).await?;
    debug!(
        %method, final_content_length, complete = auth.is_complete(),
        "NTLM(stream): sent Type-3 head"
    );
    Ok(())
}
