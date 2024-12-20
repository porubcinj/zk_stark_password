use std::sync::{Arc, Mutex};
use zk_stark::{Client, Server};

fn main() {
    let server = Arc::new(Mutex::new(Server::new()));
    let mut client = Client::new(Arc::clone(&server));
    client.run();
}
