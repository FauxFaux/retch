#[test]
fn ssl() {
    let resp = retch::get(&url::Url::parse("https://retch.goeswhere.com/").unwrap()).unwrap();
    assert!(resp.status().is_success());
}
