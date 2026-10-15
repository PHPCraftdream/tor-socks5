//! Range checks for numeric [`crate::Settings`] fields.

pub(crate) fn validate_min_bandwidth_percentile(pct: u8) -> std::result::Result<(), String> {
    if pct <= 100 {
        Ok(())
    } else {
        Err(format!(
            "min_bandwidth_percentile must be in 0..=100, got {pct}"
        ))
    }
}

pub(crate) fn validate_circuit_hops(hops: u8) -> std::result::Result<(), String> {
    if matches!(hops, 2 | 3) {
        Ok(())
    } else {
        Err(format!("tor.circuit_hops must be 2 or 3, got {hops}"))
    }
}

pub(crate) fn validate_service_circuit_hops(hops: u8) -> std::result::Result<(), String> {
    if (2..=4).contains(&hops) {
        Ok(())
    } else {
        Err(format!(
            "service_circuit_hops (onion_services circuit_hops) must be 2, 3 or 4, got {hops}"
        ))
    }
}
