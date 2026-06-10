"""Prediction math: linear trends, disk-fill ETA, latency anomalies."""
from netwatch.predict import fill_eta_days, latency_anomaly, linear_fit, mean_std

T0 = 1_750_000_000.0
DAY = 86400.0


def make_series(hours: int, start: float, per_hour: float, step_h: float = 1.0):
    return [(T0 + i * step_h * 3600, start + i * step_h * per_hour)
            for i in range(int(hours / step_h) + 1)]


def test_linear_fit_recovers_slope():
    pts = make_series(48, 100.0, 10.0)  # +10/hour
    slope, intercept, r2 = linear_fit(pts)
    assert abs(slope * 3600 - 10.0) < 1e-6
    assert abs(intercept - 100.0) < 1e-6
    assert r2 > 0.999


def test_linear_fit_flat_series():
    pts = [(T0 + i * 60, 5.0) for i in range(10)]
    slope, _, r2 = linear_fit(pts)
    assert slope == 0
    assert r2 == 1.0  # perfectly explained


def test_fill_eta_simple():
    # 1 GB/day growth, 10 GB headroom -> ~10 days
    gb = 1024 ** 3
    pts = make_series(72, 50 * gb, gb / 24)
    eta = fill_eta_days(pts, capacity=pts[-1][1] + 10 * gb)
    assert eta is not None
    assert 9.5 < eta < 10.5


def test_fill_eta_rejects_shrinking_and_flat():
    gb = 1024 ** 3
    shrinking = make_series(72, 50 * gb, -gb / 24)
    assert fill_eta_days(shrinking, capacity=100 * gb) is None
    flat = [(T0 + i * 3600, 50 * gb) for i in range(80)]
    assert fill_eta_days(flat, capacity=100 * gb) is None


def test_fill_eta_needs_enough_data():
    gb = 1024 ** 3
    few = make_series(72, 50 * gb, gb / 24)[:5]
    assert fill_eta_days(few, capacity=100 * gb) is None
    short_span = make_series(6, 50 * gb, gb / 24, step_h=0.25)
    assert fill_eta_days(short_span, capacity=100 * gb) is None


def test_fill_eta_noisy_data_low_r2_rejected():
    gb = 1024 ** 3
    pts = []
    for i in range(60):
        # oscillation dominates trend -> poor linear fit
        value = 50 * gb + (gb * 20 if i % 2 else 0) + i * 1e5
        pts.append((T0 + i * 3600, value))
    assert fill_eta_days(pts, capacity=200 * gb) is None


def test_mean_std():
    m, s = mean_std([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
    assert m == 5.0
    assert abs(s - 2.0) < 1e-9


def test_latency_anomaly_detects_jump():
    baseline = [20.0 + (i % 5) for i in range(200)]  # ~20-24 ms
    recent = [80.0, 85.0, 90.0, 78.0, 82.0, 88.0]
    elevated, msg = latency_anomaly(baseline, recent, z_threshold=3.0)
    assert elevated
    assert "z=" in msg


def test_latency_anomaly_ignores_normal_variation():
    baseline = [20.0 + (i % 10) for i in range(200)]
    recent = [24.0, 25.0, 23.0, 26.0, 22.0]
    elevated, _ = latency_anomaly(baseline, recent)
    assert not elevated


def test_latency_anomaly_needs_data():
    assert latency_anomaly([1.0] * 10, [50.0] * 10)[0] is False
    assert latency_anomaly([1.0] * 100, [50.0])[0] is False
