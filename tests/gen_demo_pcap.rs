/// Generates a demo pcap file that triggers all 5 Vigil signature rules.
///
/// Run: cargo test --test gen_demo_pcap -- --ignored --nocapture
/// Output: tests/fixtures/demo_alerts.pcap
use vigil::capture::frame_builders::{build_tcp_frame, build_udp_frame};

fn write_packet(
    savefile: &mut pcap::Savefile,
    frame: &[u8],
    ts_sec: i64,
    ts_usec: i64,
) {
    savefile.write(&pcap::Packet {
        header: &pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: ts_sec,
                tv_usec: ts_usec,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        },
        data: frame,
    });
}

#[test]
#[ignore]
fn generate_demo_pcap() {
    let path = "tests/fixtures/demo_alerts.pcap";
    let dead_cap = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = dead_cap.savefile(path).unwrap();

    let mut ts: i64 = 1_700_000_000;

    // =========================================================================
    // 1. SYN Flood (Critical)
    //    Rule: tcp && syn_count > 50 && fin_count == 0 && syn_ratio > 0.8
    //    Need avg_packet_len >= 10 to avoid matching Port Scan first.
    //    Flow: 192.168.1.100:44444 → 10.0.0.1:80
    // =========================================================================
    let syn_padding = vec![0x00; 20]; // 20-byte payload → avg_pkt_len = 20, skips Port Scan
    for i in 0..80 {
        let frame = build_tcp_frame(
            [192, 168, 1, 100],
            [10, 0, 0, 1],
            44444,
            80,
            0x02, // SYN only
            &syn_padding,
        );
        write_packet(&mut savefile, &frame, ts, i * 10_000);
    }
    ts += 2;

    // =========================================================================
    // 2. Brute Force (High)
    //    Rule: tcp && dst_port in [22,23,3389] && packet_count >= 30 && avg_pkt < 100
    //    payload = 50 bytes → avg_pkt_len = 50 (> 10 skips Port Scan, < 100 hits Brute Force)
    //    Flow: 10.0.0.1:55555 → 10.0.0.2:22
    //    src_ip:src_port (10.0.0.1:55555) < dst_ip:dst_port (10.0.0.2:22)
    //    so canonical preserves direction and dst_port stays 22.
    // =========================================================================
    let ssh_payload = vec![0x41; 50];
    for i in 0..40 {
        let frame = build_tcp_frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            55555,
            22,
            0x02, // SYN
            &ssh_payload,
        );
        write_packet(&mut savefile, &frame, ts, i * 25_000);
    }
    ts += 2;

    // =========================================================================
    // 3. Port Scan (Medium)
    //    Rule: packet_count >= 20 && avg_packet_len < 10.0
    //    Zero-payload probes.
    //    Flow: 172.16.0.5:33333 → 10.0.0.3:8080
    // =========================================================================
    for i in 0..25 {
        let frame = build_tcp_frame(
            [172, 16, 0, 5],
            [10, 0, 0, 3],
            33333,
            8080,
            0x02, // SYN
            b"",  // no payload → avg_packet_len = 0
        );
        write_packet(&mut savefile, &frame, ts, i * 40_000);
    }
    ts += 2;

    // =========================================================================
    // 4. Data Exfiltration (Critical)
    //    Rule: byte_count > 10_000_000 (10 MB)
    //    1400 bytes × 7200 packets = ~10.08 MB (just over threshold)
    //    Need avg_pkt_len >= 10 to skip Port Scan, and pkt_count >= 20 happens fast.
    //    Flow: 10.0.0.10:60000 → 203.0.113.50:443
    // =========================================================================
    let exfil_payload = vec![0xAA; 1400];
    for i in 0..7200 {
        let frame = build_tcp_frame(
            [10, 0, 0, 10],
            [203, 0, 113, 50],
            60000,
            443,
            0x10, // ACK
            &exfil_payload,
        );
        write_packet(
            &mut savefile,
            &frame,
            ts + (i / 1000) as i64,
            (i % 1000) as i64 * 1_000,
        );
    }
    ts += 10;

    // =========================================================================
    // 5. DNS Tunneling (High)
    //    Rule: udp && port == 53 && avg_packet_len > 200
    //    300-byte payloads to DNS port.
    //    Flow: 10.0.0.20:51000 → 8.8.8.8:53
    // =========================================================================
    let dns_payload = vec![0x42; 300];
    for i in 0..20 {
        let frame = build_udp_frame(
            [10, 0, 0, 20],
            [8, 8, 8, 8],
            51000,
            53,
            &dns_payload,
        );
        write_packet(&mut savefile, &frame, ts, i * 50_000);
    }
    ts += 2;

    // =========================================================================
    // 6. Normal background traffic (no alerts — gives the TUI more flows)
    // =========================================================================

    // HTTPS browsing
    for i in 0..15 {
        let frame = build_tcp_frame(
            [10, 0, 0, 100],
            [142, 250, 80, 46],
            49000,
            443,
            0x10,
            &vec![0x00; 500],
        );
        write_packet(&mut savefile, &frame, ts, i * 100_000);
    }
    ts += 2;

    // Normal DNS lookups (each from a different source port = separate flow)
    for i in 0..10 {
        let frame = build_udp_frame(
            [10, 0, 0, 100],
            [8, 8, 4, 4],
            52000 + i,
            53,
            &vec![0x00; 40],
        );
        write_packet(&mut savefile, &frame, ts, i as i64 * 200_000);
    }
    ts += 2;

    // HTTP traffic
    for i in 0..12 {
        let frame = build_tcp_frame(
            [10, 0, 0, 101],
            [93, 184, 216, 34],
            48500,
            80,
            0x18, // PSH+ACK
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        write_packet(&mut savefile, &frame, ts, i * 80_000);
    }

    savefile.flush().unwrap();
    println!("Wrote demo pcap to: {path}");
    println!("Run with: VIGIL_TUI=1 VIGIL_PCAP={path} cargo run");
}
