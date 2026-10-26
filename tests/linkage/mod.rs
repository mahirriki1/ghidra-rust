//! Exercise bounded metadata pages through the actual worker transport.
use ghidra_rust::linkage::{
    Linkage, LinkageFetch, MAX_LINKAGE_PAGE_BYTES, MAX_LINKAGE_PAGE_RECORDS,
};
use ghidra_rust::model::{BinaryInfo, Request, Response};

pub fn read(mut request: impl FnMut(Request) -> Response, info: &BinaryInfo) -> Linkage {
    let mut fetch: Option<LinkageFetch> = None;
    let mut cursor = 0;
    let mut digest = None;
    loop {
        let response = request(Request::Linkage {
            cursor,
            digest: digest.clone(),
        });
        assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_LINKAGE_PAGE_BYTES);
        let Response::Linkage { summary, page } = response else {
            panic!("Expected linkage metadata: {response:?}");
        };
        assert!(page.entries.len() <= MAX_LINKAGE_PAGE_RECORDS);
        if let Some(fetch) = &fetch {
            assert_eq!(fetch.summary(), &summary);
        }
        let fetch = fetch.get_or_insert_with(|| LinkageFetch::new(summary, &info.sha256).unwrap());
        assert_eq!(page.digest, fetch.summary().digest);
        assert_eq!(page.cursor, cursor);
        digest = Some(page.digest.clone());
        if !page.entries.is_empty() {
            fetch.accept(page, info).unwrap();
        } else {
            assert_eq!(fetch.summary().records(), 0);
            assert_eq!(page.next, None);
        }
        if let Some(next) = fetch.cursor() {
            cursor = next;
        } else {
            break;
        }
    }
    assert!(matches!(
        request(Request::Linkage {
            cursor: 0,
            digest: Some("f".repeat(64))
        }),
        Response::Error { .. }
    ));
    fetch.unwrap().finish().unwrap()
}
