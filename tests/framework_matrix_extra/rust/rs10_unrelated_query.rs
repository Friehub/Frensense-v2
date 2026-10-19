use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

struct Cache;
impl Cache {
    fn query(&self, k: &str) -> String {
        k.to_string()
    }
}

async fn h(Query(p): Query<P>) -> String {
    Cache.query(&p.id)
}
