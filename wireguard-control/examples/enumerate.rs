use wireguard_control::{Backend, Device};

const BACKEND: Backend = Backend::Kernel;

fn main() {
    let devices = Device::list(BACKEND).unwrap();
    println!("{devices:?}");
}
