fn main() {
    const CLI_STACK_SIZE_BYTES: usize = 64 * 1024 * 1024;

    let handle = std::thread::Builder::new()
        .name("tapchat-cli".into())
        .stack_size(CLI_STACK_SIZE_BYTES)
        .spawn(|| -> anyhow::Result<()> {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(tapchat_core::cli::run())
        });

    match handle {
        Ok(handle) => match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
            Err(_) => {
                eprintln!("tapchat CLI worker thread panicked");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("failed to start tapchat CLI worker thread: {error}");
            std::process::exit(1);
        }
    }
}
