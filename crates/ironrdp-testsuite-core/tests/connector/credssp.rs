use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::sspi::credssp::TsRequest;
use ironrdp_connector::{ClientConnector, ConnectorErrorKind, Credentials};
use ironrdp_pdu::nego::SecurityProtocol;
use rstest::rstest;

fn sequence() -> CredsspSequence {
    let (sequence, _) = CredsspSequence::init(
        Credentials::UsernamePassword {
            username: "user".to_owned(),
            password: "secret".to_owned(),
        },
        None,
        SecurityProtocol::HYBRID,
        "server.example.com".to_owned().into(),
        vec![0x42; 32],
        None,
    )
    .expect("CredSSP sequence");
    sequence
}

fn server_message(version: u32) -> Vec<u8> {
    let request = TsRequest {
        version,
        ..TsRequest::default()
    };
    let mut encoded = Vec::new();
    request.encode_ts_request(&mut encoded).expect("encode TsRequest");
    encoded
}

// oracle: spec MS-CSSP §2.2.1 (versions 4 and lower bind the TLS key by encrypting it rather than hashing it)
#[rstest]
#[case::version_2(2)]
#[case::version_3(3)]
#[case::version_4(4)]
fn server_versions_below_5_are_refused(#[case] version: u32) {
    let error = sequence()
        .decode_server_message(&server_message(version))
        .expect_err("a version below 5 must be refused");

    assert!(
        matches!(error.kind(), ConnectorErrorKind::InsecureCredsspVersion(refused) if *refused == version),
        "unexpected error: {error}"
    );
}

// oracle: spec MS-CSSP §2.2.1 (versions 5 and higher bind the TLS key with a hash)
#[rstest]
#[case::version_5(5)]
#[case::version_6(6)]
fn server_versions_5_and_6_are_accepted(#[case] version: u32) {
    let message = sequence()
        .decode_server_message(&server_message(version))
        .expect("versions 5 and 6 are accepted")
        .expect("a TsRequest");

    assert_eq!(message.version, version);
}

// oracle: spec MS-CSSP §2.2.1 (version 4 uses the encrypted-key binding the opt-in exists for)
#[test]
fn opt_in_accepts_version_4() {
    let mut sequence = sequence();
    sequence.set_allow_insecure_versions(true);

    let message = sequence
        .decode_server_message(&server_message(4))
        .expect("the opt-in accepts version 4")
        .expect("a TsRequest");

    assert_eq!(message.version, 4);
}

// oracle: spec MS-CSSP §2.2.1 (the version floor applies to every server TsRequest, not only the first)
#[test]
fn a_later_server_message_cannot_lower_the_version() {
    let mut sequence = sequence();
    sequence
        .decode_server_message(&server_message(6))
        .expect("version 6 is accepted");

    let error = sequence
        .decode_server_message(&server_message(4))
        .expect_err("a later version 4 must be refused");

    assert!(matches!(error.kind(), ConnectorErrorKind::InsecureCredsspVersion(4)));
}

// oracle: reference mstsc (its default Encryption Oracle Remediation policy refuses the vulnerable CredSSP versions)
#[test]
fn connector_refuses_insecure_credssp_unless_opted_in() {
    let connector = ClientConnector::new(super::test_config(), "127.0.0.1:3389".parse().unwrap());
    assert!(!connector.allows_insecure_credssp());
    assert!(connector.with_insecure_credssp(true).allows_insecure_credssp());
}
