use axum::extract::{Query, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    id: String,
}

async fn h(Query(p): Query<P>) -> String {
    let out = std::process::Command::new("ls").arg(&p.id).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}
