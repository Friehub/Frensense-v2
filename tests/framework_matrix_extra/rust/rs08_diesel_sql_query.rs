use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(Query(p): Query<P>) -> String {
    let mut conn = establish();
    let q = diesel::sql_query(format!("SELECT * FROM users WHERE id = '{}'", p.id));
    q.execute(&mut conn).unwrap().to_string()
}
