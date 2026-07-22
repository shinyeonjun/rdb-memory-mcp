# Database Memory MCP Install

Database Memory MCP indexes relational database schema metadata into a local graph and exposes that graph through a CLI and an MCP stdio server. It is metadata-focused: the default adapters introspect catalogs/schema objects, not user table rows.

## Build From Source

Prerequisites:

- Rust toolchain with Cargo installed.
- A C compiler/toolchain available to Cargo, because some adapter dependencies build native code.
- On Windows, use the MSVC Rust toolchain with Visual Studio Build Tools or another working MSVC C/C++ build environment.
- On macOS or Linux, a normal system C compiler such as clang or gcc is expected.
- Oracle only: Oracle Client 11.2 or later must also be available at runtime. Building the vendored ODPI-C sources does not bundle Oracle Client libraries.

Build the whole workspace in release mode:

```powershell
cargo build --release
```

The generic ODBC entrypoint is intentionally optional. Build it explicitly and
install a matching 64-bit driver on the host:

```powershell
cargo build --release --features database-memory-core/odbc
```

ODBC driver presence is not a completeness claim. The current ODBC strategy
certifies only the SQL Server bridge for the same native-certified SQL Server
versions; every other product fails closed until it has its own live-certified
strategy.

Release binaries are written under `target/release/`:

- CLI: `target/release/database-memory` on macOS/Linux, `target/release/database-memory.exe` on Windows.
- MCP stdio server: `target/release/database-memory-mcp` on macOS/Linux, `target/release/database-memory-mcp.exe` on Windows.

## Platform Notes

Windows:

- This project has been built with the MSVC Rust toolchain.
- Install Rust with rustup and make sure an MSVC C/C++ build environment is available before running the release build.
- Native/build-heavy dependencies include bundled SQLite through `rusqlite`, SQL Server and MySQL TLS through the platform-native TLS stack, and Oracle support through `odpic-sys` vendored C sources.
- To use Oracle, install an Oracle Instant Client matching the binary architecture and put the directory containing `oci.dll` on `PATH` before starting the CLI, MCP server, or desktop app.

macOS:

- Install Rust with rustup.
- Ensure Xcode Command Line Tools or another clang-based C toolchain is installed.
- The same native adapter dependencies are compiled during `cargo build --release`.

Linux:

- Install Rust with rustup or your distribution package manager.
- Ensure gcc or clang plus typical build tooling is installed.
- The same native adapter dependencies are compiled during `cargo build --release`.

For Oracle on macOS or Linux, install Oracle Client 11.2 or later and make its shared libraries discoverable according to the Instant Client installation instructions before starting the process.

## MCP Client Configuration

Register `database-memory-mcp` as a stdio MCP server. The server does not need command-line arguments for stdio mode.

MCP local-file access is fail-closed. By default, schema sources and graph caches
must stay under the server process working directory. Set
`DATABASE_MEMORY_MCP_ALLOWED_ROOTS` when the client starts the server to declare
additional trusted project/cache roots. Use `;` between roots on Windows and `:`
on macOS/Linux. Existing symlinks are resolved before the boundary check.

Claude Code / Claude Desktop-style clients commonly use an `mcpServers` map:

```json
{
  "mcpServers": {
    "database-memory": {
      "command": "/absolute/path/to/target/release/database-memory-mcp",
      "args": [],
      "env": {
        "DATABASE_MEMORY_MCP_ALLOWED_ROOTS": "/absolute/project:/absolute/cache"
      }
    }
  }
}
```

Some MCP clients use a `servers` map instead:

```json
{
  "servers": {
    "database-memory": {
      "command": "/absolute/path/to/target/release/database-memory-mcp",
      "args": []
    }
  }
}
```

On Windows, point `command` at the built `.exe`, for example `C:\path\to\target\release\database-memory-mcp.exe`. Keep the path specific to your local checkout or copied release binary.

On Windows, an allowed-root value can look like
`D:\projects\backend;D:\database-memory-cache`. Grant only the roots the MCP
host needs; this setting is the filesystem boundary for semi-trusted tool calls.
