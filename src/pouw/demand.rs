//! Demand Tracker for NUW Work
//!
//! Tracks and predicts NUW task demand to help miners manage CPU allocation
//! between BOINC (background) and NUW (consensus-critical) work.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      DEMAND TRACKER                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Time Windows: 1min | 5min | 15min | 1hr | 24hr            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Per Bucket Metrics:                                        │
//! │    - tasks_enqueued / tasks_dequeued                        │
//! │    - avg_wait_time, queue_depth                             │
//! │    - estimated_time_to_empty                                │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Predictions:                                               │
//! │    - incoming_rate, processing_rate                         │
//! │    - saturation_level (0-100%)                              │
//! │    - recommendation (low/medium/high/critical)              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Miner Usage
//!
//! ```text
//! GET /v1/demand → { recommendation: "medium", saturation: 45, ... }
//!
//! if recommendation == "low":    boinc_cpu = 80%
//! if recommendation == "medium": boinc_cpu = 50%
//! if recommendation == "high":   boinc_cpu = 20%
//! if recommendation == "critical": boinc_cpu = 0%
//! ```

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::nuw::priority_queue::PriorityBucket;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DemandLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl DemandLevel {
    pub fn boinc_cpu_limit(&self) -> f64 {
        match self {
            DemandLevel::Low => 0.80,
            DemandLevel::Medium => 0.50,
            DemandLevel::High => 0.20,
            DemandLevel::Critical => 0.0,
        }
    }
    
    pub fn from_saturation(saturation: u8) -> Self {
        match saturation {
            0..=25 => DemandLevel::Low,
            26..=50 => DemandLevel::Medium,
            51..=75 => DemandLevel::High,
            _ => DemandLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeWindow {
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
    OneHour,
    TwentyFourHours,
}

impl TimeWindow {
    pub fn duration_secs(&self) -> u64 {
        match self {
            TimeWindow::OneMinute => 60,
            TimeWindow::FiveMinutes => 300,
            TimeWindow::FifteenMinutes => 900,
            TimeWindow::OneHour => 3600,
            TimeWindow::TwentyFourHours => 86400,
        }
    }
    
    pub fn all() -> &'static [TimeWindow] {
        &[
            TimeWindow::OneMinute,
            TimeWindow::FiveMinutes,
            TimeWindow::FifteenMinutes,
            TimeWindow::OneHour,
            TimeWindow::TwentyFourHours,
        ]
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BucketMetrics {
    pub enqueued: u64,
    pub dequeued: u64,
    pub avg_wait_ms: f64,
    pub queue_depth: usize,
    pub total_wait_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WindowMetrics {
    pub p0: BucketMetrics,
    pub p1: BucketMetrics,
    pub p2: BucketMetrics,
    pub special: BucketMetrics,
    pub timestamp: DateTime<Utc>,
}

impl WindowMetrics {
    pub fn total_enqueued(&self) -> u64 {
        self.p0.enqueued + self.p1.enqueued + self.p2.enqueued + self.special.enqueued
    }
    
    pub fn total_dequeued(&self) -> u64 {
        self.p0.dequeued + self.p1.dequeued + self.p2.dequeued + self.special.dequeued
    }
    
    pub fn total_depth(&self) -> usize {
        self.p0.queue_depth + self.p1.queue_depth + self.p2.queue_depth + self.special.queue_depth
    }
    
    pub fn nuw_depth(&self) -> usize {
        self.p0.queue_depth + self.p1.queue_depth + self.p2.queue_depth
    }
    
    pub fn get_bucket(&self, bucket: PriorityBucket) -> &BucketMetrics {
        match bucket {
            PriorityBucket::P0 => &self.p0,
            PriorityBucket::P1 => &self.p1,
            PriorityBucket::P2 => &self.p2,
            PriorityBucket::Special => &self.special,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemandSnapshot {
    pub current: CurrentDemand,
    pub saturation: u8,
    pub recommendation: DemandLevel,
    pub eta_empty_seconds: Option<u64>,
    pub historical: HistoricalDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentDemand {
    pub p0: BucketDemand,
    pub p1: BucketDemand,
    pub p2: BucketDemand,
    pub special: BucketDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketDemand {
    pub depth: usize,
    pub rate_in: f64,
    pub rate_out: f64,
    pub avg_wait_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalDemand {
    pub avg_hourly_demand: f64,
    pub peak_hourly_demand: f64,
    pub typical_peak_hour: u8,
    pub total_tasks_24h: u64,
    pub total_tasks_7d: u64,
}

#[derive(Debug, Clone)]
struct EventRecord {
    timestamp: DateTime<Utc>,
    bucket: PriorityBucket,
    event_type: EventType,
    wait_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
enum EventType {
    Enqueued,
    Dequeued,
}

pub struct DemandTracker {
    events: Arc<RwLock<VecDeque<EventRecord>>>,
    max_events: usize,
    current_depth: Arc<RwLock<[usize; 4]>>,
    historical_stats: Arc<RwLock<HistoricalStats>>,
}

#[derive(Debug, Clone, Default)]
struct HistoricalStats {
    hourly_counts: VecDeque<(DateTime<Utc>, u64)>,
    daily_counts: VecDeque<(DateTime<Utc>, u64)>,
    peak_hourly: u64,
    peak_hour: u8,
}

impl DemandTracker {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(100_000))),
            max_events: 100_000,
            current_depth: Arc::new(RwLock::new([0; 4])),
            historical_stats: Arc::new(RwLock::new(HistoricalStats::default())),
        }
    }
    
    pub async fn record_enqueue(&self, bucket: PriorityBucket) {
        let record = EventRecord {
            timestamp: Utc::now(),
            bucket,
            event_type: EventType::Enqueued,
            wait_ms: None,
        };
        
        {
            let mut events = self.events.write().await;
            if events.len() >= self.max_events {
                events.pop_front();
            }
            events.push_back(record);
        }
        
        {
            let mut depth = self.current_depth.write().await;
            depth[bucket as usize] += 1;
        }
        
        debug!(bucket = ?bucket, "Recorded enqueue event");
    }
    
    pub async fn record_dequeue(&self, bucket: PriorityBucket, wait_ms: u64) {
        let record = EventRecord {
            timestamp: Utc::now(),
            bucket,
            event_type: EventType::Dequeued,
            wait_ms: Some(wait_ms),
        };
        
        {
            let mut events = self.events.write().await;
            if events.len() >= self.max_events {
                events.pop_front();
            }
            events.push_back(record);
        }
        
        {
            let mut depth = self.current_depth.write().await;
            depth[bucket as usize] = depth[bucket as usize].saturating_sub(1);
        }
        
        debug!(bucket = ?bucket, wait_ms, "Recorded dequeue event");
    }
    
    pub async fn update_queue_depth(&self, bucket: PriorityBucket, depth: usize) {
        let mut current = self.current_depth.write().await;
        current[bucket as usize] = depth;
    }
    
    pub async fn get_demand_snapshot(&self) -> DemandSnapshot {
        let window_metrics = self.calculate_window_metrics().await;
        let historical = self.calculate_historical().await;
        
        let current = CurrentDemand {
            p0: self.calculate_bucket_demand(&window_metrics, PriorityBucket::P0).await,
            p1: self.calculate_bucket_demand(&window_metrics, PriorityBucket::P1).await,
            p2: self.calculate_bucket_demand(&window_metrics, PriorityBucket::P2).await,
            special: self.calculate_bucket_demand(&window_metrics, PriorityBucket::Special).await,
        };
        
        let saturation = self.calculate_saturation(&current).await;
        let recommendation = DemandLevel::from_saturation(saturation);
        let eta_empty = self.calculate_eta_empty(&current).await;
        
        DemandSnapshot {
            current,
            saturation,
            recommendation,
            eta_empty_seconds: eta_empty,
            historical,
        }
    }
    
    async fn calculate_window_metrics(&self) -> std::collections::HashMap<TimeWindow, WindowMetrics> {
        let events = self.events.read().await;
        let depth = self.current_depth.read().await;
        let now = Utc::now();
        
        let mut result = std::collections::HashMap::new();
        
        for window in TimeWindow::all() {
            let cutoff = now - chrono::Duration::seconds(window.duration_secs() as i64);
            
            let mut metrics = WindowMetrics {
                timestamp: now,
                ..Default::default()
            };
            
            metrics.p0.queue_depth = depth[PriorityBucket::P0 as usize];
            metrics.p1.queue_depth = depth[PriorityBucket::P1 as usize];
            metrics.p2.queue_depth = depth[PriorityBucket::P2 as usize];
            metrics.special.queue_depth = depth[PriorityBucket::Special as usize];
            
            for event in events.iter().rev() {
                if event.timestamp < cutoff {
                    break;
                }
                
                let bucket_metrics = match event.bucket {
                    PriorityBucket::P0 => &mut metrics.p0,
                    PriorityBucket::P1 => &mut metrics.p1,
                    PriorityBucket::P2 => &mut metrics.p2,
                    PriorityBucket::Special => &mut metrics.special,
                };
                
                match event.event_type {
                    EventType::Enqueued => bucket_metrics.enqueued += 1,
                    EventType::Dequeued => {
                        bucket_metrics.dequeued += 1;
                        if let Some(wait) = event.wait_ms {
                            bucket_metrics.total_wait_ms += wait;
                        }
                    }
                }
            }
            
            for bucket in &[
                PriorityBucket::P0,
                PriorityBucket::P1,
                PriorityBucket::P2,
                PriorityBucket::Special,
            ] {
                let bm = match bucket {
                    PriorityBucket::P0 => &mut metrics.p0,
                    PriorityBucket::P1 => &mut metrics.p1,
                    PriorityBucket::P2 => &mut metrics.p2,
                    PriorityBucket::Special => &mut metrics.special,
                };
                
                if bm.dequeued > 0 {
                    bm.avg_wait_ms = bm.total_wait_ms as f64 / bm.dequeued as f64;
                }
            }
            
            result.insert(*window, metrics);
        }
        
        result
    }
    
    async fn calculate_bucket_demand(
        &self,
        window_metrics: &std::collections::HashMap<TimeWindow, WindowMetrics>,
        bucket: PriorityBucket,
    ) -> BucketDemand {
        let one_min = window_metrics.get(&TimeWindow::OneMinute);
        let five_min = window_metrics.get(&TimeWindow::FiveMinutes);
        
        let (depth, rate_in, rate_out, avg_wait) = if let (Some(m1), Some(m5)) = (one_min, five_min) {
            let bm1 = m1.get_bucket(bucket);
            let bm5 = m5.get_bucket(bucket);
            
            let depth = bm1.queue_depth;
            
            let rate_in = (bm5.enqueued as f64 / 5.0).min(bm1.enqueued as f64);
            let rate_out = (bm5.dequeued as f64 / 5.0).min(bm1.dequeued as f64);
            
            let avg_wait = if bm5.dequeued > 0 {
                bm5.avg_wait_ms
            } else {
                0.0
            };
            
            (depth, rate_in, rate_out, avg_wait)
        } else {
            (0, 0.0, 0.0, 0.0)
        };
        
        BucketDemand {
            depth,
            rate_in,
            rate_out,
            avg_wait_ms: avg_wait,
        }
    }
    
    async fn calculate_saturation(&self, current: &CurrentDemand) -> u8 {
        let nuw_depth = current.p0.depth + current.p1.depth + current.p2.depth;
        
        let rate_factor = {
            let total_in = current.p0.rate_in + current.p1.rate_in + current.p2.rate_in;
            let total_out = current.p0.rate_out + current.p1.rate_out + current.p2.rate_out;
            
            if total_out > 0.0 {
                ((total_in / total_out) * 50.0).min(100.0)
            } else if total_in > 0.0 {
                100.0
            } else {
                0.0
            }
        };
        
        let depth_factor = {
            let depth_score = match nuw_depth {
                0..=5 => 0.0,
                6..=15 => 20.0,
                16..=30 => 40.0,
                31..=50 => 60.0,
                51..=100 => 80.0,
                _ => 100.0,
            };
            depth_score
        };
        
        let p0_weight = if current.p0.depth > 0 { 1.5 } else { 1.0 };
        
        let saturation = (rate_factor * 0.6 + depth_factor * 0.4) * p0_weight;
        
        saturation.min(100.0) as u8
    }
    
    async fn calculate_eta_empty(&self, current: &CurrentDemand) -> Option<u64> {
        let total_depth = current.p0.depth + current.p1.depth + current.p2.depth;
        
        if total_depth == 0 {
            return Some(0);
        }
        
        let total_rate_out = current.p0.rate_out + current.p1.rate_out + current.p2.rate_out;
        
        if total_rate_out <= 0.0 {
            return None;
        }
        
        let eta_seconds = (total_depth as f64 / total_rate_out) * 60.0;
        
        Some(eta_seconds as u64)
    }
    
    async fn calculate_historical(&self) -> HistoricalDemand {
        let stats = self.historical_stats.read().await;
        
        let avg_hourly = if stats.hourly_counts.is_empty() {
            0.0
        } else {
            stats.hourly_counts.iter().map(|(_, c)| *c as f64).sum::<f64>()
                / stats.hourly_counts.len() as f64
        };
        
        HistoricalDemand {
            avg_hourly_demand: avg_hourly,
            peak_hourly_demand: stats.peak_hourly as f64,
            typical_peak_hour: stats.peak_hour,
            total_tasks_24h: stats.hourly_counts.iter().map(|(_, c)| *c).sum(),
            total_tasks_7d: stats.daily_counts.iter().map(|(_, c)| *c).sum(),
        }
    }
    
    pub async fn record_hourly_count(&self, count: u64) {
        let mut stats = self.historical_stats.write().await;
        let now = Utc::now();
        
        let hour = now.time().hour() as u8;
        
        stats.hourly_counts.push_back((now, count));
        
        while stats.hourly_counts.len() > 168 {
            stats.hourly_counts.pop_front();
        }
        
        if count > stats.peak_hourly {
            stats.peak_hourly = count;
            stats.peak_hour = hour;
        }
        
        debug!(hour, count, peak_hourly = stats.peak_hourly, "Recorded hourly count");
    }
    
    pub async fn record_daily_count(&self, count: u64) {
        let mut stats = self.historical_stats.write().await;
        let now = Utc::now();
        
        stats.daily_counts.push_back((now, count));
        
        while stats.daily_counts.len() > 30 {
            stats.daily_counts.pop_front();
        }
        
        debug!(count, "Recorded daily count");
    }
    
    pub async fn get_current_depth(&self, bucket: PriorityBucket) -> usize {
        let depth = self.current_depth.read().await;
        depth[bucket as usize]
    }
    
    pub async fn cleanup_old_events(&self) {
        let cutoff = Utc::now() - chrono::Duration::hours(25);
        
        let mut events = self.events.write().await;
        let before = events.len();
        
        while events.front().map(|e| e.timestamp < cutoff).unwrap_or(false) {
            events.pop_front();
        }
        
        let removed = before - events.len();
        if removed > 0 {
            debug!(removed, remaining = events.len(), "Cleaned up old events");
        }
    }
}

impl Default for DemandTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_demand_level_cpu_limit() {
        assert_eq!(DemandLevel::Low.boinc_cpu_limit(), 0.80);
        assert_eq!(DemandLevel::Medium.boinc_cpu_limit(), 0.50);
        assert_eq!(DemandLevel::High.boinc_cpu_limit(), 0.20);
        assert_eq!(DemandLevel::Critical.boinc_cpu_limit(), 0.0);
    }
    
    #[test]
    fn test_demand_level_from_saturation() {
        assert_eq!(DemandLevel::from_saturation(10), DemandLevel::Low);
        assert_eq!(DemandLevel::from_saturation(30), DemandLevel::Medium);
        assert_eq!(DemandLevel::from_saturation(60), DemandLevel::High);
        assert_eq!(DemandLevel::from_saturation(90), DemandLevel::Critical);
    }
    
    #[test]
    fn test_time_window_durations() {
        assert_eq!(TimeWindow::OneMinute.duration_secs(), 60);
        assert_eq!(TimeWindow::FiveMinutes.duration_secs(), 300);
        assert_eq!(TimeWindow::OneHour.duration_secs(), 3600);
        assert_eq!(TimeWindow::TwentyFourHours.duration_secs(), 86400);
    }
    
    #[tokio::test]
    async fn test_demand_tracker_creation() {
        let tracker = DemandTracker::new();
        let snapshot = tracker.get_demand_snapshot().await;
        
        assert_eq!(snapshot.saturation, 0);
        assert_eq!(snapshot.recommendation, DemandLevel::Low);
    }
    
    #[tokio::test]
    async fn test_record_enqueue() {
        let tracker = DemandTracker::new();
        
        tracker.record_enqueue(PriorityBucket::P1).await;
        
        let depth = tracker.get_current_depth(PriorityBucket::P1).await;
        assert_eq!(depth, 1);
    }
    
    #[tokio::test]
    async fn test_record_dequeue() {
        let tracker = DemandTracker::new();
        
        tracker.record_enqueue(PriorityBucket::P1).await;
        tracker.record_dequeue(PriorityBucket::P1, 100).await;
        
        let depth = tracker.get_current_depth(PriorityBucket::P1).await;
        assert_eq!(depth, 0);
    }
    
    #[tokio::test]
    async fn test_saturation_calculation() {
        let tracker = DemandTracker::new();
        
        for _ in 0..50 {
            tracker.record_enqueue(PriorityBucket::P1).await;
        }
        
        let snapshot = tracker.get_demand_snapshot().await;
        
        assert!(snapshot.current.p1.depth >= 50);
    }
}
