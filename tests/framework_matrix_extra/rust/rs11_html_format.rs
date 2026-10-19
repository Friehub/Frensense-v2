use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(Query(p): Query<P>) -> axum::response::Html<String> {
    axum::response::Html(format!("<h1>{}</h1>", p.id))
}
