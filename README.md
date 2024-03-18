# ODBC Tracer
This is a simple ODBC tracer that can be used to trace ODBC calls. It can be easily modified for custom ODBC tracing needs.

## Building
1. ```shell
   cargo build --release --profile release --lib --target x86_64-pc-windows-msvc 
   ```
2. Copy the resulting `target/x86_64-pc-windows-msvc/release/odbc_tracer.dll` to `C:\Windows\System32`.
3. Select the new dll in the ODBC tracing settings.
4. Select the desired trace location in the ODBC tracing settings.
5. Start tracing and apply.