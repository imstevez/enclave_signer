use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Res<T> {
    Data(T),
    Err { error: String },
}

impl<T> Res<T> {
    pub fn internal_err(e: impl Into<anyhow::Error>) -> (StatusCode, Json<Res<T>>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Res::<T>::Err {
                error: e.into().to_string(),
            }),
        )
    }

    pub fn ok(data: T) -> (StatusCode, Json<Res<T>>) {
        (StatusCode::OK, Json(Res::Data(data)))
    }
}
