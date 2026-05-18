use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::WebviewWindow;
use tokio::sync::Semaphore;

use super::single::{verify_single_file_streaming, IntegrityError};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParallelBatchVerifyRequest {
    pub paths: Vec<PathBuf>,
    pub concurrency_limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVerifyResult {
    pub path: String,
    pub success: bool,
    pub hash: Option<String>,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn verify_batch_parallel(
    window: WebviewWindow,
    req: ParallelBatchVerifyRequest,
) -> Result<Vec<BatchVerifyResult>, IntegrityError> {
    if req.paths.is_empty() {
        return Ok(vec![]);
    }

    // Clamp to ≥1: Semaphore(0) deadlocks every acquire() forever.
    let limit = req.concurrency_limit.unwrap_or_else(num_cpus::get).max(1);
    let semaphore = Arc::new(Semaphore::new(limit));
    let mut tasks = tokio::task::JoinSet::new();

    for path in req.paths {
        let window_clone = window.clone();
        let sem_clone = Arc::clone(&semaphore);
        let path_clone = path.clone();

        tasks.spawn(async move {
            let path_str = path_clone.to_string_lossy().into_owned();

            // Acquire permit asynchronously before dispatching to the blocking OS thread pool.
            let permit = match sem_clone.acquire().await {
                Ok(p) => p,
                Err(e) => {
                    return BatchVerifyResult {
                        path: path_str,
                        success: false,
                        hash: None,
                        error: Some(format!("Semaphore acquisition failure: {e}")),
                    }
                }
            };

            let compute_result = tokio::task::spawn_blocking(move || {
                verify_single_file_streaming(&window_clone, path_clone)
            })
            .await;

            // Release permit after computation so the next queued task can proceed.
            drop(permit);

            match compute_result {
                Ok(Ok(hash)) => BatchVerifyResult {
                    path: path_str,
                    success: true,
                    hash: Some(hash),
                    error: None,
                },
                Ok(Err(e)) => BatchVerifyResult {
                    path: path_str,
                    success: false,
                    hash: None,
                    error: Some(e.to_string()),
                },
                Err(e) => BatchVerifyResult {
                    path: path_str,
                    success: false,
                    hash: None,
                    error: Some(format!("Thread join failure: {e}")),
                },
            }
        });
    }

    let mut results = Vec::with_capacity(tasks.len());
    while let Some(task_res) = tasks.join_next().await {
        match task_res {
            Ok(verify_res) => results.push(verify_res),
            Err(e) => {
                return Err(IntegrityError::CryptoFailure(format!("Task pool panic: {e}")))
            }
        }
    }

    Ok(results)
}
