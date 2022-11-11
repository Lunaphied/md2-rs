use std::io::Read;

use md2::MD2;

fn main() -> Result<(), std::io::Error> {
    // Read data from stdin and compute it's MD2 hash
    let mut stdin = std::io::stdin();
    let mut buf = vec![];
    stdin.read_to_end(&mut buf)?;

    // Now compute the MD2 over the input data and display it
    let md2 = MD2::with_input(&buf);
    println!("{}", md2);
    Ok(())
}
