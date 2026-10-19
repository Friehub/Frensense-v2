use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(State(pool): State<sqlx::PgPool>, Query(p): Query<P>) -> String {
    let n: i64 = p.id.parse().unwrap();
    let rows = sqlx::query(&format!("SELECT * FROM users WHERE id = {}", n))
        .fetch_all(&pool)
        .await
        .unwrap();
    rows.len().to_string()
}
