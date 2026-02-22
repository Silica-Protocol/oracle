//! Priority Queue for NUW Tasks
//!
//! Implements FIFO impact-based queueing with three priority buckets:
//! - P0: Critical (RecursiveSNARK only) - network halt if uncompleted
//! - P1: High (batched operations) - significant degradation if uncompleted
//! - P2: Best-effort - no consensus impact
//! - Special: BOINC tasks - long-running, async from consensus
//!
//! ## Queue Semantics
//!
//! - Each bucket is strictly FIFO within its priority
//! - P0 tasks are always processed first
//! - P1 tasks processed when no P0 pending
//! - P2 tasks processed when no P0/P1 pending
//! - Special bucket handled separately (async)

use crate::pouw::nuw::{NuwTask, TaskPriority};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityBucket {
    P0,
    P1,
    P2,
    Special,
}

impl From<TaskPriority> for PriorityBucket {
    fn from(priority: TaskPriority) -> Self {
        match priority {
            TaskPriority::P0 => PriorityBucket::P0,
            TaskPriority::P1 => PriorityBucket::P1,
            TaskPriority::P2 => PriorityBucket::P2,
            TaskPriority::Special => PriorityBucket::Special,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueuedTask {
    pub task: NuwTask,
    pub enqueued_at: DateTime<Utc>,
    pub retry_count: usize,
    pub last_error: Option<String>,
}

impl QueuedTask {
    pub fn new(task: NuwTask) -> Self {
        Self {
            task,
            enqueued_at: Utc::now(),
            retry_count: 0,
            last_error: None,
        }
    }

    pub fn age_ms(&self) -> i64 {
        Utc::now()
            .signed_duration_since(self.enqueued_at)
            .num_milliseconds()
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.task.expires_at
    }
}

#[derive(Debug, Clone, Default)]
pub struct BucketStats {
    pub total_enqueued: u64,
    pub total_dequeued: u64,
    pub total_expired: u64,
    pub current_size: usize,
    pub avg_wait_ms: f64,
}

#[derive(Debug)]
pub struct PriorityQueue {
    p0_queue: VecDeque<QueuedTask>,
    p1_queue: VecDeque<QueuedTask>,
    p2_queue: VecDeque<QueuedTask>,
    special_queue: VecDeque<QueuedTask>,
    stats: [BucketStats; 4],
    max_bucket_size: usize,
}

impl Default for PriorityQueue {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl PriorityQueue {
    pub fn new(max_bucket_size: usize) -> Self {
        Self {
            p0_queue: VecDeque::new(),
            p1_queue: VecDeque::new(),
            p2_queue: VecDeque::new(),
            special_queue: VecDeque::new(),
            stats: [
                BucketStats::default(),
                BucketStats::default(),
                BucketStats::default(),
                BucketStats::default(),
            ],
            max_bucket_size,
        }
    }

    pub fn enqueue(&mut self, task: NuwTask) -> Result<(), String> {
        let bucket: PriorityBucket = task.task_type.priority().into();
        let queued = QueuedTask::new(task);

        let current_size = match bucket {
            PriorityBucket::P0 => self.p0_queue.len(),
            PriorityBucket::P1 => self.p1_queue.len(),
            PriorityBucket::P2 => self.p2_queue.len(),
            PriorityBucket::Special => self.special_queue.len(),
        };

        if current_size >= self.max_bucket_size {
            return Err(format!("Queue {:?} is full", bucket));
        }

        let (queue, stats) = self.get_bucket_mut(bucket);

        stats.total_enqueued += 1;
        stats.current_size = queue.len() + 1;

        queue.push_back(queued);

        debug!(
            bucket = ?bucket,
            queue_size = queue.len(),
            "Task enqueued"
        );

        Ok(())
    }

    pub fn dequeue(&mut self) -> Option<QueuedTask> {
        self.dequeue_from_bucket(PriorityBucket::P0)
            .or_else(|| self.dequeue_from_bucket(PriorityBucket::P1))
            .or_else(|| self.dequeue_from_bucket(PriorityBucket::P2))
    }

    pub fn dequeue_special(&mut self) -> Option<QueuedTask> {
        self.dequeue_from_bucket(PriorityBucket::Special)
    }

    pub fn dequeue_by_priority(&mut self, bucket: PriorityBucket) -> Option<QueuedTask> {
        self.dequeue_from_bucket(bucket)
    }

    fn dequeue_from_bucket(&mut self, bucket: PriorityBucket) -> Option<QueuedTask> {
        let (queue, stats) = self.get_bucket_mut(bucket);

        while let Some(task) = queue.pop_front() {
            stats.current_size = queue.len();

            if task.is_expired() {
                stats.total_expired += 1;
                debug!(
                    task_id = %task.task.task_id,
                    "Task expired, skipping"
                );
                continue;
            }

            stats.total_dequeued += 1;
            stats.current_size = queue.len();

            return Some(task);
        }

        None
    }

    pub fn requeue(&mut self, mut task: QueuedTask, error: String) -> Result<(), String> {
        task.retry_count += 1;
        task.last_error = Some(error);

        const MAX_RETRIES: usize = 3;
        if task.retry_count > MAX_RETRIES {
            warn!(
                task_id = %task.task.task_id,
                retries = task.retry_count,
                "Task exceeded max retries, dropping"
            );
            return Err("Max retries exceeded".to_string());
        }

        let bucket: PriorityBucket = task.task.task_type.priority().into();
        let (queue, stats) = self.get_bucket_mut(bucket);

        queue.push_front(task);
        stats.current_size = queue.len();

        Ok(())
    }

    pub fn peek(&self) -> Option<&QueuedTask> {
        self.p0_queue
            .front()
            .or_else(|| self.p1_queue.front())
            .or_else(|| self.p2_queue.front())
    }

    pub fn peek_bucket(&self, bucket: PriorityBucket) -> Option<&QueuedTask> {
        match bucket {
            PriorityBucket::P0 => self.p0_queue.front(),
            PriorityBucket::P1 => self.p1_queue.front(),
            PriorityBucket::P2 => self.p2_queue.front(),
            PriorityBucket::Special => self.special_queue.front(),
        }
    }

    pub fn len(&self) -> usize {
        self.p0_queue.len() + self.p1_queue.len() + self.p2_queue.len() + self.special_queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bucket_size(&self, bucket: PriorityBucket) -> usize {
        match bucket {
            PriorityBucket::P0 => self.p0_queue.len(),
            PriorityBucket::P1 => self.p1_queue.len(),
            PriorityBucket::P2 => self.p2_queue.len(),
            PriorityBucket::Special => self.special_queue.len(),
        }
    }

    pub fn stats(&self, bucket: PriorityBucket) -> &BucketStats {
        &self.stats[bucket as usize]
    }

    pub fn cleanup_expired(&mut self) -> usize {
        let mut expired_count = 0;

        for bucket in [
            PriorityBucket::P0,
            PriorityBucket::P1,
            PriorityBucket::P2,
            PriorityBucket::Special,
        ] {
            let (queue, stats) = self.get_bucket_mut(bucket);
            let before = queue.len();
            queue.retain(|t| !t.is_expired());
            let removed = before - queue.len();
            stats.total_expired += removed as u64;
            stats.current_size = queue.len();
            expired_count += removed;
        }

        if expired_count > 0 {
            debug!(expired_count, "Cleaned up expired tasks");
        }

        expired_count
    }

    fn get_bucket_mut(
        &mut self,
        bucket: PriorityBucket,
    ) -> (&mut VecDeque<QueuedTask>, &mut BucketStats) {
        let stats_idx = bucket as usize;
        match bucket {
            PriorityBucket::P0 => (&mut self.p0_queue, &mut self.stats[stats_idx]),
            PriorityBucket::P1 => (&mut self.p1_queue, &mut self.stats[stats_idx]),
            PriorityBucket::P2 => (&mut self.p2_queue, &mut self.stats[stats_idx]),
            PriorityBucket::Special => (&mut self.special_queue, &mut self.stats[stats_idx]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pouw::nuw::TaskType;
    use chrono::Duration;

    fn create_test_task(task_type: TaskType) -> NuwTask {
        NuwTask {
            task_id: format!("task_{}", Utc::now().timestamp_millis()),
            task_type,
            payload: vec![],
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            difficulty_multiplier: 1.0,
        }
    }

    #[test]
    fn test_enqueue_dequeue_order() {
        let mut queue = PriorityQueue::new(100);

        let p1_task = create_test_task(TaskType::SigBatchVerify);
        let p0_task = create_test_task(TaskType::RecursiveSnark);
        let p2_task = create_test_task(TaskType::MerkleVerify);

        queue.enqueue(p1_task).unwrap();
        queue.enqueue(p0_task).unwrap();
        queue.enqueue(p2_task).unwrap();

        let first = queue.dequeue().unwrap();
        assert_eq!(first.task.task_type, TaskType::RecursiveSnark);

        let second = queue.dequeue().unwrap();
        assert_eq!(second.task.task_type, TaskType::SigBatchVerify);

        let third = queue.dequeue().unwrap();
        assert_eq!(third.task.task_type, TaskType::MerkleVerify);
    }

    #[test]
    fn test_fifo_within_bucket() {
        let mut queue = PriorityQueue::new(100);

        let task1 = create_test_task(TaskType::SigBatchVerify);
        let task2 = create_test_task(TaskType::ZkBatchVerify);

        queue.enqueue(task1.clone()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        queue.enqueue(task2).unwrap();

        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.task.task_id, task1.task_id);
    }

    #[test]
    fn test_expired_task_skipped() {
        let mut queue = PriorityQueue::new(100);

        let expired_task = NuwTask {
            task_id: "expired".to_string(),
            task_type: TaskType::SigBatchVerify,
            payload: vec![],
            created_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::hours(1),
            difficulty_multiplier: 1.0,
        };

        let valid_task = create_test_task(TaskType::SigBatchVerify);

        queue.enqueue(expired_task).unwrap();
        queue.enqueue(valid_task.clone()).unwrap();

        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.task.task_id, valid_task.task_id);
    }

    #[test]
    fn test_requeue_with_retry_count() {
        let mut queue = PriorityQueue::new(100);

        let task = create_test_task(TaskType::SigBatchVerify);
        queue.enqueue(task).unwrap();

        let queued = queue.dequeue().unwrap();
        assert_eq!(queued.retry_count, 0);

        queue.requeue(queued, "test error".to_string()).unwrap();

        let retried = queue.dequeue().unwrap();
        assert_eq!(retried.retry_count, 1);
        assert_eq!(retried.last_error, Some("test error".to_string()));
    }

    #[test]
    fn test_max_retries_exceeded() {
        let mut queue = PriorityQueue::new(100);

        let task = create_test_task(TaskType::SigBatchVerify);
        queue.enqueue(task).unwrap();

        for _ in 0..3 {
            let queued = queue.dequeue().unwrap();
            queue.requeue(queued, "error".to_string()).unwrap();
        }

        let queued = queue.dequeue().unwrap();
        let result = queue.requeue(queued, "final error".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_bucket_size_limits() {
        let mut queue = PriorityQueue::new(2);

        queue
            .enqueue(create_test_task(TaskType::SigBatchVerify))
            .unwrap();
        queue
            .enqueue(create_test_task(TaskType::ZkBatchVerify))
            .unwrap();

        let result = queue.enqueue(create_test_task(TaskType::MerkleBatch));
        assert!(result.is_err());
    }

    #[test]
    fn test_special_bucket_separate() {
        let mut queue = PriorityQueue::new(100);

        let boinc_task = create_test_task(TaskType::BoincRosetta);
        queue.enqueue(boinc_task).unwrap();

        assert!(queue.dequeue().is_none());

        let special = queue.dequeue_special();
        assert!(special.is_some());
    }
}
