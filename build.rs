// protox compiles the .proto files in Rust, so building needs no protoc.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(["proto/service.proto"], ["proto"])?;
    tonic_prost_build::configure().build_server(false).compile_fds(fds)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
