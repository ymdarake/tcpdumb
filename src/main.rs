pub mod net;

fn main() {
    let interfaces = net::list_interfaces();
    let target = interfaces.get(1).unwrap();
    net::monitor(target);
}
