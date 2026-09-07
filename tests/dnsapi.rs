use acmeproxy::{
    provider::{Worker, WorkerState},
    security,
};
use std::{collections::BTreeMap, time::Duration};

#[tokio::test]
#[ignore = "requires the pinned bundle: sh scripts/install-dnsapi.sh"]
async fn pinned_cloudflare_adapter_runs_with_real_acmesh_helpers() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("adapters");
    let scratch = directory.path().join("scratch");
    std::fs::create_dir_all(home.join("dnsapi")).unwrap();
    std::fs::create_dir(&scratch).unwrap();
    let mut core = std::fs::read_to_string(".local/acme.sh/acme.sh")
        .expect("install pinned DNS adapters first");
    // Override only network transport. All actual acme.sh helpers and the Cloudflare
    // provider implementation run unchanged; no request can reach Cloudflare.
    core.push_str(r#"
_get() {
  [ "$_H2" = 'Authorization: Bearer fixture-cloudflare-token' ] || return 1
  case "$1" in
    */zones/fixture-zone) printf '%s' '{"success":true,"result":{"id":"fixture-zone","name":"example.com"}}' ;;
    *dns_records*) printf '%s' '{"success":true,"result":[{"id":"fixture-record"}],"result_info":{"count":1}}' ;;
    *) return 1 ;;
  esac
}
_post() {
  [ "$_H2" = 'Authorization: Bearer fixture-cloudflare-token' ] || return 1
  printf '%s %s\n' "$4" "$2" >> "$MOCK_CALLS"
  if [ "$4" = 'POST' ]; then printf '{"success":true,"result":%s}' "$1";
  elif [ "$4" = 'DELETE' ]; then printf '%s' '{"success":true}';
  else return 1; fi
}
"#);
    std::fs::write(home.join("acme.sh"), core).unwrap();
    std::fs::copy(
        ".local/acme.sh/dnsapi/dns_cf.sh",
        home.join("dnsapi/dns_cf.sh"),
    )
    .unwrap();
    let calls = directory.path().join("calls");
    let credentials = BTreeMap::from([
        ("CF_Token".into(), "fixture-cloudflare-token".into()),
        ("CF_Zone_ID".into(), "fixture-zone".into()),
        ("MOCK_CALLS".into(), calls.to_string_lossy().into_owned()),
    ]);
    let worker = Worker {
        home,
        scratch,
        timeout: Duration::from_secs(5),
    };
    let value = security::random_secret();
    let result = worker
        .run(
            "dns_cf",
            "add",
            "_acme-challenge.example.com",
            &value,
            &credentials,
            WorkerState::default(),
        )
        .await
        .unwrap();
    assert_eq!(result.error, None);
    assert!(String::from_utf8_lossy(&result.state.domain).contains("CF_Token"));
    let result = worker
        .run(
            "dns_cf",
            "rm",
            "_acme-challenge.example.com",
            &value,
            &credentials,
            result.state,
        )
        .await
        .unwrap();
    assert_eq!(result.error, None);
    let calls = std::fs::read_to_string(calls).unwrap();
    assert!(
        calls.contains("POST https://api.cloudflare.com/client/v4/zones/fixture-zone/dns_records")
    );
    assert!(calls.contains(
        "DELETE https://api.cloudflare.com/client/v4/zones/fixture-zone/dns_records/fixture-record"
    ));
}
