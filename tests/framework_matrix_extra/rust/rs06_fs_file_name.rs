use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(Query(p): Query<P>) -> String {
    let name = std::path::Path::new(&p.id).file_name().unwrap();
    std::fs::read_to_string(std::path::Path::new("/data").join(name)).unwrap()
}
