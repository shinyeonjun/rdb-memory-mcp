use database_memory_mcp::DatabaseMemoryMcp;
use rmcp::{transport::stdio, ServiceExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = DatabaseMemoryMcp::try_new()?.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
