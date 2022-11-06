use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use std::net::IpAddr;

fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) -> String {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        format!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        )
    } else {
        format!("[{}]: Malformed UDP Packet", interface_name)
    }
}

fn handle_icmp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) -> String {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                format!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                )
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                format!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                )
            }
            _ => format!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        format!("[{}]: Malformed ICMP Packet", interface_name)
    }
}

fn handle_icmpv6_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) -> String {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        format!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        format!("[{}]: Malformed ICMPv6 Packet", interface_name)
    }
}

fn handle_tcp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) -> String {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        format!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        )
    } else {
        format!("[{}]: Malformed TCP Packet", interface_name)
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) -> String {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet)
        }
        _ => format!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            interface_name,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) -> String {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        )
    } else {
        format!("[{}]: Malformed IPv4 Packet", interface_name)
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) -> String {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        )
    } else {
        format!("[{}]: Malformed IPv6 Packet", interface_name)
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) -> String {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        format!(
            "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
            interface_name,
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        )
    } else {
        format!("[{}]: Malformed ARP Packet", interface_name)
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) -> String {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
        _ => format!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

pub fn list_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
}

pub fn new_receiver(interface: &NetworkInterface) -> Option<Box<dyn DataLinkReceiver>> {
    use pnet::datalink::Channel::Ethernet;
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(_, rx)) => Some(rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    }
}

pub fn read_packet(interface: &NetworkInterface, packet: &[u8]) -> String {
    let mut buf: [u8; 1600] = [0u8; 1600];
    let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();

    let payload_offset;
    if cfg!(any(target_os = "macos", target_os = "ios"))
        && interface.is_up()
        && !interface.is_broadcast()
        && ((!interface.is_loopback() && interface.is_point_to_point()) || interface.is_loopback())
    {
        if interface.is_loopback() {
            // The pnet code for BPF loopback adds a zero'd out Ethernet header
            payload_offset = 14;
        } else {
            // Maybe is TUN interface
            payload_offset = 0;
        }
        if packet.len() > payload_offset {
            let version = Ipv4Packet::new(&packet[payload_offset..])
                .unwrap()
                .get_version();
            if version == 4 {
                fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                return handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
            }
            if version == 6 {
                fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                return handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
            }
        }
    }
    return handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
}
