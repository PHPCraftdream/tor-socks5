use crate::probe::*;
use crate::*;
use tokio_util::sync::CancellationToken;

// TS4-04: the DoH wave race must return at the first usable answer instead
// of draining the whole wave, while every completing provider still records
// its statistics from inside its own attempt future.

fn winner_outcome(index: usize, ttl: Duration) -> DohAttemptOutcome {
    (
        index,
        Duration::ZERO,
        Some((vec!["203.0.113.77".parse().unwrap()], ttl)),
    )
}

type BoxedAttempt = std::pin::Pin<Box<dyn std::future::Future<Output = DohAttemptOutcome> + Send>>;
type BoxedFactory = Box<dyn FnOnce(CancellationToken) -> BoxedAttempt + Send>;

#[tokio::test]
async fn race_first_answer_returns_before_slow_losers_finish() {
    let losers: [BoxedFactory; 2] = [0usize, 1].map(|i| {
        Box::new(move |_admission: CancellationToken| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                (i, Duration::ZERO, None)
            }) as BoxedAttempt
        }) as BoxedFactory
    });
    let winner: BoxedFactory = Box::new(|_admission: CancellationToken| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            winner_outcome(2, Duration::from_secs(300))
        }) as BoxedAttempt
    });
    let attempts = losers.into_iter().chain(std::iter::once(winner));
    let started = std::time::Instant::now();
    let answer = race_first_answer("", attempts).await;
    let elapsed = started.elapsed();

    assert_eq!(
        answer,
        Some((
            vec!["203.0.113.77".parse().unwrap()],
            Duration::from_secs(300)
        )),
        "the first non-empty answer must win the race"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "must not wait for the 5-second losers; took {elapsed:?}"
    );
}

#[tokio::test]
async fn losing_attempts_still_record_after_the_race_returns() {
    let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));

    let make = |index: usize,
                delay: Duration,
                wins: bool,
                recorded: std::sync::Arc<std::sync::Mutex<Vec<usize>>>| {
        move |_admission: CancellationToken| async move {
            tokio::time::sleep(delay).await;
            // Mimics note_doh_result's placement inside doh_provider_attempt.
            recorded.lock().expect("recorded lock").push(index);
            if wins {
                winner_outcome(index, Duration::from_secs(300))
            } else {
                (index, Duration::ZERO, None)
            }
        }
    };

    let attempts = vec![
        make(
            0,
            Duration::from_millis(100),
            true,
            std::sync::Arc::clone(&recorded),
        ),
        make(
            1,
            Duration::from_millis(400),
            false,
            std::sync::Arc::clone(&recorded),
        ),
        make(
            2,
            Duration::from_millis(400),
            false,
            std::sync::Arc::clone(&recorded),
        ),
    ];

    let answer = race_first_answer("", attempts).await;
    assert!(
        answer.is_some(),
        "the winner's answer must be returned by the race"
    );

    // The losers are detached after the win; give their side effects a hard
    // deadline so a regression fails instead of hanging forever.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while *recorded.lock().expect("recorded lock") != vec![0, 1, 2] {
        assert!(
            std::time::Instant::now() < deadline,
            "detached losers must still record their statistics after the race returns"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn race_is_not_delayed_by_a_loser_queued_on_a_permit() {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));

    let holder_slots = std::sync::Arc::clone(&slots);
    let holder: BoxedFactory = Box::new(move |_admission: CancellationToken| {
        Box::pin(async move {
            let _permit = holder_slots.acquire_owned().await.ok();
            tokio::time::sleep(Duration::from_secs(10)).await;
            (0usize, Duration::ZERO, None)
        }) as BoxedAttempt
    });
    let queued_slots = std::sync::Arc::clone(&slots);
    let queued: BoxedFactory = Box::new(move |_admission: CancellationToken| {
        Box::pin(async move {
            let _permit = queued_slots.acquire_owned().await.ok();
            (1usize, Duration::ZERO, None)
        }) as BoxedAttempt
    });
    let winner: BoxedFactory = Box::new(|_admission: CancellationToken| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            winner_outcome(2, Duration::from_secs(300))
        }) as BoxedAttempt
    });
    let attempts = [holder, queued, winner];

    let started = std::time::Instant::now();
    let answer = race_first_answer("", attempts).await;
    let elapsed = started.elapsed();

    assert_eq!(
        answer,
        Some((
            vec!["203.0.113.77".parse().unwrap()],
            Duration::from_secs(300)
        )),
        "the permit-free winner must answer"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "a loser queued on the only permit must not delay the race; took {elapsed:?}"
    );
}

// TS5-02: the race owns an admission token. An attempt still queued on a
// semaphore permit when the owner stops waiting must never start its lookup,
// while an attempt that already holds its permit must still finish and record.
//
// These mocks mirror `doh_provider_attempt`'s admission contract: wait for the
// permit racing the token, and only once the permit is held do real work.

#[tokio::test]
async fn stopping_the_race_never_starts_a_queued_attempt() {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    // Hold the only permit: the attempt stays queued until we release it.
    let held = slots.clone().acquire_owned().await.unwrap();

    let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let attempt_slots = std::sync::Arc::clone(&slots);
    let started_flag = std::sync::Arc::clone(&started);
    let attempts = [move |admission: CancellationToken| {
        let attempt_slots = std::sync::Arc::clone(&attempt_slots);
        let started_flag = std::sync::Arc::clone(&started_flag);
        async move {
            let _permit = tokio::select! {
                biased;
                _ = admission.cancelled() => return (0usize, Duration::ZERO, None),
                p = attempt_slots.acquire_owned() => p.expect("semaphore is not closed"),
            };
            // First step after the permit: prove the lookup really started.
            started_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            (0usize, Duration::ZERO, None)
        }
    }];

    // The owner gives up while the permit is still held: the outer timeout
    // drops the race future, which must cancel the queued attempt.
    let raced =
        tokio::time::timeout(Duration::from_millis(100), race_first_answer("", attempts)).await;
    assert!(
        raced.is_err(),
        "the race must still be queued on the permit when the owner gives up"
    );

    // Only NOW release the permit. A cancelled attempt must not wake up,
    // acquire it, and start a lookup nobody will consume.
    drop(held);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !started.load(std::sync::atomic::Ordering::SeqCst),
        "an attempt queued on a permit must not start its lookup after the race's owner stopped waiting"
    );
}

#[tokio::test]
async fn a_started_attempt_still_finishes_after_the_race_is_cancelled() {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let recorded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let attempt_slots = std::sync::Arc::clone(&slots);
    let recorded_flag = std::sync::Arc::clone(&recorded);
    let attempts = [move |admission: CancellationToken| {
        let attempt_slots = std::sync::Arc::clone(&attempt_slots);
        let recorded_flag = std::sync::Arc::clone(&recorded_flag);
        async move {
            let _permit = tokio::select! {
                biased;
                _ = admission.cancelled() => return (0usize, Duration::ZERO, None),
                p = attempt_slots.acquire_owned() => p.expect("semaphore is not closed"),
            };
            // Started: the owner cancelling must not stop this attempt from
            // finishing and recording (mirrors doh_provider_attempt, whose
            // bounded lookup and note_doh_result stay untouched).
            tokio::time::sleep(Duration::from_millis(150)).await;
            recorded_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            (0usize, Duration::ZERO, None)
        }
    }];

    let raced = tokio::spawn(race_first_answer("", attempts));
    // Let the attempt acquire the free permit, then cancel the race mid-flight.
    tokio::time::sleep(Duration::from_millis(50)).await;
    raced.abort();

    // The started attempt must still complete its work on its own schedule.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !recorded.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "a started attempt must finish and record even after the race's owner was cancelled"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn race_doh_wave_with_no_valid_pool_indices_is_none() {
    let started = std::time::Instant::now();
    let answer = race_doh_wave(&[usize::MAX], "wave-empty.test.invalid").await;
    let elapsed = started.elapsed();

    assert_eq!(answer, None, "no pool index means no attempt and no answer");
    assert!(
        elapsed < Duration::from_secs(2),
        "filtering everything out must return promptly; took {elapsed:?}"
    );
}
