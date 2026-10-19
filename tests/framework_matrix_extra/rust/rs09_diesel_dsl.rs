use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(Query(p): Query<P>) -> String {
    let mut conn = establish();
    users::table.filter(users::id.eq(&p.id)).load::<User>(&mut conn).unwrap().len().to_string()
}
