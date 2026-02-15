/// Packet capture and protocol decoding.
///
/// `PacketCapture` opens a live NIC via libpcap. `PcapReplaySource` reads
/// from a `.pcap` file. Both yield decoded `Packet` values via `PacketSource`.
/// `ProtocolParser` handles the Ethernet → IP → TCP/UDP layer walk.
use std::net::Ipv4Addr;

use chrono::Utc;
use pcap::{Capture, Active, Offline};

use crate::models::{
    Packet, PacketSource, Protocol, Result, TcpFlags, VigilError,
};

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_MIN_HEADER_LEN: usize = 20;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

// ---------------------------------------------------------------------------
// ProtocolParser
// ---------------------------------------------------------------------------

pub struct ProtocolParser;

impl ProtocolParser {
    pub fn parse(frame: &[u8]) -> Option<Packet> {
        if frame.len() < ETHERNET_HEADER_LEN {
            return None;
        }

        let ethertype = &frame[12..14];
        if ethertype != ETHERTYPE_IPV4 {
            return None;
        }

        Self::parse_ipv4(&frame[ETHERNET_HEADER_LEN..], Utc::now())
    }

    fn parse_ipv4(data: &[u8], timestamp: chrono::DateTime<Utc>) -> Option<Packet> {
        if data.len() < IPV4_MIN_HEADER_LEN {
            return None;
        }

        let ihl = ((data[0] & 0x0F) as usize) * 4;
        if ihl < IPV4_MIN_HEADER_LEN || data.len() < ihl {
            return None;
        }

        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let ttl = data[8];
        let proto_byte = data[9];
        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        let protocol = match proto_byte {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            other => Protocol::Other(other),
        };

        let transport_data = &data[ihl..];
        let ip_payload_len = total_len.saturating_sub(ihl);

        let (src_port, dst_port, flags, payload_len) = match protocol {
            Protocol::Tcp => {
                let (sp, dp, f, pl) = Self::parse_tcp(transport_data, ip_payload_len)?;
                (sp, dp, f, pl)
            }
            Protocol::Udp => {
                let (sp, dp, pl) = Self::parse_udp(transport_data, ip_payload_len)?;
                (sp, dp, TcpFlags::default(), pl)
            }
            _ => (0, 0, TcpFlags::default(), ip_payload_len as u32),
        };

        Some(Packet {
            timestamp,
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            src_port,
            dst_port,
            protocol,
            flags,
            payload_len,
            ttl,
        })
    }

    fn parse_tcp(data: &[u8], ip_payload_len: usize) -> Option<(u16, u16, TcpFlags, u32)> {
        if data.len() < TCP_MIN_HEADER_LEN {
            return None;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let data_offset = ((data[12] >> 4) as usize) * 4;
        let flag_byte = data[13];

        let flags = TcpFlags {
            urg: flag_byte & 0x20 != 0,
            ack: flag_byte & 0x10 != 0,
            psh: flag_byte & 0x08 != 0,
            rst: flag_byte & 0x04 != 0,
            syn: flag_byte & 0x02 != 0,
            fin: flag_byte & 0x01 != 0,
        };

        let payload_len = ip_payload_len.saturating_sub(data_offset) as u32;
        Some((src_port, dst_port, flags, payload_len))
    }

    fn parse_udp(data: &[u8], _ip_payload_len: usize) -> Option<(u16, u16, u32)> {
        if data.len() < UDP_HEADER_LEN {
            return None;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let udp_len = u16::from_be_bytes([data[4], data[5]]) as u32;
        let payload_len = udp_len.saturating_sub(UDP_HEADER_LEN as u32);

        Some((src_port, dst_port, payload_len))
    }
}

// ---------------------------------------------------------------------------
// PacketCapture
// ---------------------------------------------------------------------------

pub struct PacketCapture {
    cap: Capture<Active>,
}

impl PacketCapture {
    pub fn open(interface: &str) -> Result<Self> {
        let cap = Capture::from_device(interface)
            .map_err(|e| VigilError::Capture(e.to_string()))?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()
            .map_err(|e| VigilError::Capture(e.to_string()))?;

        Ok(Self { cap })
    }
}

impl PacketSource for PacketCapture {
    async fn next_packet(&mut self) -> Result<Option<Packet>> {
        loop {
            match self.cap.next_packet() {
                Ok(packet) => {
                    if let Some(pkt) = ProtocolParser::parse(packet.data) {
                        return Ok(Some(pkt));
                    }
                    // Non-IPv4 frame (ARP, IPv6, etc.) — skip
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(VigilError::Capture(e.to_string())),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PcapReplaySource
// ---------------------------------------------------------------------------

pub struct PcapReplaySource {
    cap: Capture<Offline>,
}

impl PcapReplaySource {
    pub fn open(path: &str) -> Result<Self> {
        let cap = Capture::from_file(path)
            .map_err(|e| VigilError::Capture(e.to_string()))?;
        Ok(Self { cap })
    }
}

impl PacketSource for PcapReplaySource {
    async fn next_packet(&mut self) -> Result<Option<Packet>> {
        match self.cap.next_packet() {
            Ok(packet) => Ok(ProtocolParser::parse(packet.data)),
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(VigilError::Capture(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Frame builders (pub for integration tests)
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub mod frame_builders {
    use super::{ETHERTYPE_IPV4, UDP_HEADER_LEN};

    pub fn build_tcp_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();

        // Ethernet header (14 bytes)
        frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        frame.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02]);
        frame.extend_from_slice(&ETHERTYPE_IPV4);

        // IPv4 header (20 bytes)
        let tcp_header_len = 20u16;
        let total_len = 20 + tcp_header_len + payload.len() as u16;
        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.push(64);
        frame.push(6); // TCP
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);

        // TCP header (20 bytes)
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        frame.push(0x50);
        frame.push(flags);
        frame.extend_from_slice(&[0xFF, 0xFF]);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0x00, 0x00]);

        frame.extend_from_slice(payload);
        frame
    }

    pub fn build_udp_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = Vec::new();

        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&[0x00; 6]);
        frame.extend_from_slice(&ETHERTYPE_IPV4);

        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
        let total_len = 20 + udp_len;
        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00; 4]);
        frame.push(128);
        frame.push(17); // UDP
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&src_ip);
        frame.extend_from_slice(&dst_ip);

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);

        frame.extend_from_slice(payload);
        frame
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::frame_builders::*;
    use std::net::IpAddr;

    #[test]
    fn parse_tcp_syn_packet() {
        let frame = build_tcp_frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            0x02, // SYN
            b"",
        );

        let pkt = ProtocolParser::parse(&frame).expect("should parse TCP SYN");
        assert_eq!(pkt.src_ip, IpAddr::from([10, 0, 0, 1]));
        assert_eq!(pkt.dst_ip, IpAddr::from([10, 0, 0, 2]));
        assert_eq!(pkt.src_port, 12345);
        assert_eq!(pkt.dst_port, 80);
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert!(pkt.flags.syn);
        assert!(!pkt.flags.ack);
        assert_eq!(pkt.payload_len, 0);
        assert_eq!(pkt.ttl, 64);
    }

    #[test]
    fn parse_tcp_with_payload() {
        let payload = b"GET / HTTP/1.1\r\n";
        let frame = build_tcp_frame(
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            54321,
            443,
            0x18, // PSH + ACK
            payload,
        );

        let pkt = ProtocolParser::parse(&frame).expect("should parse TCP with payload");
        assert_eq!(pkt.src_port, 54321);
        assert_eq!(pkt.dst_port, 443);
        assert!(pkt.flags.psh);
        assert!(pkt.flags.ack);
        assert!(!pkt.flags.syn);
        assert_eq!(pkt.payload_len, payload.len() as u32);
    }

    #[test]
    fn parse_udp_dns_query() {
        let dns_payload = vec![0xAA; 32];
        let frame = build_udp_frame(
            [10, 0, 0, 5],
            [8, 8, 8, 8],
            49152,
            53,
            &dns_payload,
        );

        let pkt = ProtocolParser::parse(&frame).expect("should parse UDP");
        assert_eq!(pkt.src_ip, IpAddr::from([10, 0, 0, 5]));
        assert_eq!(pkt.dst_ip, IpAddr::from([8, 8, 8, 8]));
        assert_eq!(pkt.src_port, 49152);
        assert_eq!(pkt.dst_port, 53);
        assert_eq!(pkt.protocol, Protocol::Udp);
        assert_eq!(pkt.payload_len, 32);
        assert_eq!(pkt.ttl, 128);
    }

    #[test]
    fn parse_rejects_non_ipv4() {
        let mut frame = vec![0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP
        assert!(ProtocolParser::parse(&frame).is_none());
    }

    #[test]
    fn parse_rejects_truncated_frame() {
        assert!(ProtocolParser::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn parse_rejects_truncated_ip_header() {
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + 10];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[ETHERNET_HEADER_LEN] = 0x45; // ihl=5 but only 10 bytes of IP data

        assert!(ProtocolParser::parse(&frame).is_none());
    }

    #[test]
    fn parse_tcp_all_flags() {
        let frame = build_tcp_frame(
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            1000,
            2000,
            0x3F, // all 6 flags set
            b"",
        );

        let pkt = ProtocolParser::parse(&frame).unwrap();
        assert!(pkt.flags.syn);
        assert!(pkt.flags.ack);
        assert!(pkt.flags.fin);
        assert!(pkt.flags.rst);
        assert!(pkt.flags.psh);
        assert!(pkt.flags.urg);
    }

    #[tokio::test]
    async fn replay_source_reads_pcap_file() {
        let dir = tempfile::tempdir().unwrap();
        let pcap_path = dir.path().join("test.pcap");

        // Write a pcap file with 3 SYN packets
        {
            let dead_cap = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
            let mut savefile = dead_cap.savefile(&pcap_path).unwrap();
            for port in [80, 443, 8080] {
                let frame = build_tcp_frame(
                    [10, 0, 0, 1], [10, 0, 0, 2], 12345, port, 0x02, b"",
                );
                savefile.write(&pcap::Packet {
                    header: &pcap::PacketHeader {
                        ts: libc::timeval { tv_sec: 1000, tv_usec: 0 },
                        caplen: frame.len() as u32,
                        len: frame.len() as u32,
                    },
                    data: &frame,
                });
            }
            savefile.flush().unwrap();
        }

        let mut source = PcapReplaySource::open(pcap_path.to_str().unwrap()).unwrap();

        let mut count = 0;
        while let Ok(Some(_pkt)) = source.next_packet().await {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn replay_source_returns_none_at_eof() {
        let dir = tempfile::tempdir().unwrap();
        let pcap_path = dir.path().join("empty.pcap");

        // Write a pcap with 1 packet
        {
            let dead_cap = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
            let mut savefile = dead_cap.savefile(&pcap_path).unwrap();
            let frame = build_tcp_frame(
                [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x02, b"",
            );
            savefile.write(&pcap::Packet {
                header: &pcap::PacketHeader {
                    ts: libc::timeval { tv_sec: 1000, tv_usec: 0 },
                    caplen: frame.len() as u32,
                    len: frame.len() as u32,
                },
                data: &frame,
            });
            savefile.flush().unwrap();
        }

        let mut source = PcapReplaySource::open(pcap_path.to_str().unwrap()).unwrap();

        assert!(source.next_packet().await.unwrap().is_some());
        assert!(source.next_packet().await.unwrap().is_none());
    }
}
