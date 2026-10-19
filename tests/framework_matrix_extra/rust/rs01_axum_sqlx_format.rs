use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(State(pool): State<sqlx::PgPool>, Query(p): Query<P>) -> String {
    let rows = sqlx::query(&format!("SELECT * FROM users WHERE id = '{}'", p.id))
        .fetch_all(&pool)
        .await
        .unwrap();
    rows.len().to_string()
}
