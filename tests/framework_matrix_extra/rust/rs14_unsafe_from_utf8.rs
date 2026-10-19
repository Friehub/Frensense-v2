use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(Query(p): Query<P>) -> String {
    unsafe { std::str::from_utf8_unchecked(p.id.as_bytes()) }.to_string()
}
