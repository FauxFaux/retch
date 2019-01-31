#[test]
fn ssl() {
    retch::single(&url::Url::parse("https://retch.goeswhere.com/").unwrap()).unwrap()
}
