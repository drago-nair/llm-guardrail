import math

import pytest

from benchmarks.profile_semantic_shield import (
    calculate_percentile,
    format_mib,
)


def test_calculate_percentile_with_ordered_measurements():
    measurements = [float(value) for value in range(1, 101)]

    assert calculate_percentile(measurements, 50) == 50.0
    assert calculate_percentile(measurements, 95) == 95.0
    assert calculate_percentile(measurements, 99) == 99.0


def test_calculate_percentile_sorts_measurements():
    measurements = [40.0, 10.0, 30.0, 20.0]

    assert calculate_percentile(measurements, 50) == 20.0
    assert calculate_percentile(measurements, 100) == 40.0


def test_calculate_percentile_rejects_empty_measurements():
    with pytest.raises(
        ValueError,
        match="At least one latency value is required",
    ):
        calculate_percentile([], 95)


def test_format_mib_formats_numbers_and_unavailable_values():
    assert format_mib(845.984) == "845.98 MiB"
    assert format_mib(math.nan) == "unavailable"