use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(Query(p): Query<P>) -> axum::response::Redirect {
    axum::response::Redirect::to(&p.id)
}
