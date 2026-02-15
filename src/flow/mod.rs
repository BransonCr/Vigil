/// Flow tracking — groups packets into bidirectional flows by 5-tuple
/// and maintains running statistics (counters, timing, averages).
use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use crate::models::{FiveTuple, Flow, FlowSnapshot, Packet, Protocol};

pub struct FlowTracker {
    flows: HashMap<FiveTuple, Flow>,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    pub fn update(&mut self, pkt: &Packet) -> FlowSnapshot {
        let key = FiveTuple::from(pkt).canonical();

        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            flow_id: Uuid::new_v4(),
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            protocol: key.protocol,
            started_at: pkt.timestamp,
            last_seen_at: pkt.timestamp,
            packet_count: 0,
            byte_count: 0,
            avg_packet_len: 0.0,
            avg_inter_arrival_ms: 0.0,
            syn_count: 0,
            fin_count: 0,
        });

        // Inter-arrival time (skip for the first packet in the flow)
        if flow.packet_count > 0 {
            let delta_ms = (pkt.timestamp - flow.last_seen_at)
                .num_milliseconds()
                .max(0) as f64;
            // Incremental mean: avg += (value - avg) / n
            // n here is the number of inter-arrival gaps = packet_count (before increment)
            let gap_count = flow.packet_count as f64;
            flow.avg_inter_arrival_ms +=
                (delta_ms - flow.avg_inter_arrival_ms) / gap_count;
        }

        flow.last_seen_at = pkt.timestamp;
        flow.packet_count += 1;
        flow.byte_count += pkt.payload_len as u64;

        // Incremental mean for packet length
        let n = flow.packet_count as f64;
        flow.avg_packet_len +=
            (pkt.payload_len as f64 - flow.avg_packet_len) / n;

        if pkt.protocol == Protocol::Tcp {
            if pkt.flags.syn {
                flow.syn_count += 1;
            }
            if pkt.flags.fin {
                flow.fin_count += 1;
            }
        }

        FlowSnapshot {
            flow: flow.clone(),
            captured_at: Utc::now(),
        }
    }

    pub fn get(&self, id: Uuid) -> Option<&Flow> {
        self.flows.values().find(|f| f.flow_id == id)
    }

    pub fn flows(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TcpFlags;
    use chrono::{Duration, TimeZone, Utc};
    use std::net::IpAddr;

    fn make_packet(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        flags: TcpFlags,
        payload_len: u32,
        timestamp: chrono::DateTime<Utc>,
    ) -> Packet {
        Packet {
            timestamp,
            src_ip: IpAddr::from(src),
            dst_ip: IpAddr::from(dst),
            src_port,
            dst_port,
            protocol,
            flags,
            payload_len,
            ttl: 64,
        }
    }

    fn base_time() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn first_packet_creates_flow() {
        let mut tracker = FlowTracker::new();
        let pkt = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80,
            Protocol::Tcp, TcpFlags::default(), 100, base_time(),
        );

        let snap = tracker.update(&pkt);

        assert_eq!(tracker.flow_count(), 1);
        assert_eq!(snap.flow.packet_count, 1);
        assert_eq!(snap.flow.byte_count, 100);
        assert_eq!(snap.flow.avg_packet_len, 100.0);
        assert_eq!(snap.flow.avg_inter_arrival_ms, 0.0);
    }

    #[test]
    fn second_packet_updates_counters() {
        let mut tracker = FlowTracker::new();
        let t0 = base_time();
        let t1 = t0 + Duration::milliseconds(50);

        let pkt1 = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80,
            Protocol::Tcp, TcpFlags::default(), 100, t0,
        );
        let pkt2 = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80,
            Protocol::Tcp, TcpFlags::default(), 200, t1,
        );

        tracker.update(&pkt1);
        let snap = tracker.update(&pkt2);

        assert_eq!(tracker.flow_count(), 1);
        assert_eq!(snap.flow.packet_count, 2);
        assert_eq!(snap.flow.byte_count, 300);
        assert_eq!(snap.flow.avg_packet_len, 150.0);
        assert_eq!(snap.flow.avg_inter_arrival_ms, 50.0);
    }

    #[test]
    fn reverse_direction_maps_to_same_flow() {
        let mut tracker = FlowTracker::new();
        let t0 = base_time();

        let pkt_fwd = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80,
            Protocol::Tcp, TcpFlags::default(), 100, t0,
        );
        let pkt_rev = make_packet(
            [10, 0, 0, 2], [10, 0, 0, 1], 80, 12345,
            Protocol::Tcp, TcpFlags::default(), 200, t0 + Duration::milliseconds(10),
        );

        tracker.update(&pkt_fwd);
        tracker.update(&pkt_rev);

        assert_eq!(tracker.flow_count(), 1);
    }

    #[test]
    fn different_tuples_create_separate_flows() {
        let mut tracker = FlowTracker::new();
        let t0 = base_time();

        let pkt_a = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80,
            Protocol::Tcp, TcpFlags::default(), 100, t0,
        );
        let pkt_b = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 3], 12345, 443,
            Protocol::Tcp, TcpFlags::default(), 100, t0,
        );

        tracker.update(&pkt_a);
        tracker.update(&pkt_b);

        assert_eq!(tracker.flow_count(), 2);
    }

    #[test]
    fn syn_and_fin_flags_counted() {
        let mut tracker = FlowTracker::new();
        let t0 = base_time();
        let syn = TcpFlags { syn: true, ..Default::default() };
        let fin = TcpFlags { fin: true, ack: true, ..Default::default() };

        let pkt1 = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80,
            Protocol::Tcp, syn, 0, t0,
        );
        let pkt2 = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80,
            Protocol::Tcp, fin, 0, t0 + Duration::milliseconds(100),
        );

        tracker.update(&pkt1);
        let snap = tracker.update(&pkt2);

        assert_eq!(snap.flow.syn_count, 1);
        assert_eq!(snap.flow.fin_count, 1);
    }

    #[test]
    fn udp_flags_not_counted() {
        let mut tracker = FlowTracker::new();
        let t0 = base_time();

        let pkt = make_packet(
            [10, 0, 0, 5], [8, 8, 8, 8], 49152, 53,
            Protocol::Udp, TcpFlags::default(), 64, t0,
        );

        let snap = tracker.update(&pkt);
        assert_eq!(snap.flow.syn_count, 0);
        assert_eq!(snap.flow.fin_count, 0);
        assert_eq!(snap.flow.protocol, Protocol::Udp);
    }

    #[test]
    fn inter_arrival_averages_correctly_over_three_packets() {
        let mut tracker = FlowTracker::new();
        let t0 = base_time();
        // Gaps: 100ms, 200ms → avg = 150ms
        let times = [t0, t0 + Duration::milliseconds(100), t0 + Duration::milliseconds(300)];

        for t in &times {
            let pkt = make_packet(
                [10, 0, 0, 1], [10, 0, 0, 2], 1000, 2000,
                Protocol::Tcp, TcpFlags::default(), 50, *t,
            );
            tracker.update(&pkt);
        }

        let flow = tracker.flows().next().unwrap();
        assert_eq!(flow.packet_count, 3);
        assert!((flow.avg_inter_arrival_ms - 150.0).abs() < 0.01);
    }

    #[test]
    fn get_returns_flow_by_id() {
        let mut tracker = FlowTracker::new();
        let pkt = make_packet(
            [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80,
            Protocol::Tcp, TcpFlags::default(), 100, base_time(),
        );

        let snap = tracker.update(&pkt);
        let found = tracker.get(snap.flow.flow_id);

        assert!(found.is_some());
        assert_eq!(found.unwrap().flow_id, snap.flow.flow_id);
    }

    #[test]
    fn get_returns_none_for_unknown_id() {
        let tracker = FlowTracker::new();
        assert!(tracker.get(Uuid::new_v4()).is_none());
    }
}
