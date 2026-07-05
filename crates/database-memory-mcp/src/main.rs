use database_memory_mcp::DatabaseMemoryMcp;
use rmcp::{transport::stdio, ServiceExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = DatabaseMemoryMcp::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
