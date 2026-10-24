use super::models::EntropyMetricsData;

pub fn round_to(val: f64, decimals: u32) -> f64 {
    let factor = 10_f64.powi(decimals as i32);
    (val * factor).round() / factor
}

pub fn classify_obfuscation(
    high_entropy_classes: usize,
    high_entropy_strings: usize,
    short_ratio: f64,
) -> &'static str {
    if high_entropy_classes > 0 {
        "packed"
    } else if high_entropy_strings >= 5 {
        "encrypted"
    } else if short_ratio >= 0.35 {
        "renamed"
    } else {
        "none"
    }
}

pub fn build_entropy_metrics(
    entropies: &[f64],
    total_classes: usize,
    short_names: usize,
    high_entropy_strings: usize,
    total_methods: usize,
    switch_methods: usize,
) -> EntropyMetricsData {
    let total_len = entropies.len();
    let avg_entropy = if total_len > 0 {
        round_to(entropies.iter().sum::<f64>() / total_len as f64, 2)
    } else {
        0.0
    };
    let max_entropy = if total_len > 0 {
        let max_val = entropies.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        round_to(max_val, 2)
    } else {
        0.0
    };
    let high_entropy_classes = entropies.iter().filter(|&&e| e >= 7.0).count();
    let short_ratio = if total_classes > 0 {
        round_to(short_names as f64 / total_classes as f64, 3)
    } else {
        0.0
    };
    let switch_density = if total_methods > 0 {
        round_to(switch_methods as f64 / total_methods as f64, 3)
    } else {
        0.0
    };

    let obfuscation_type =
        classify_obfuscation(high_entropy_classes, high_entropy_strings, short_ratio);

    EntropyMetricsData {
        byte_entropy_avg: avg_entropy,
        byte_entropy_max: max_entropy,
        high_entropy_classes,
        high_entropy_strings,
        short_name_ratio: short_ratio,
        switch_density,
        obfuscation_type: obfuscation_type.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_obfuscation_logic() {
        assert_eq!(classify_obfuscation(1, 0, 0.1), "packed");
        assert_eq!(classify_obfuscation(0, 5, 0.1), "encrypted");
        assert_eq!(classify_obfuscation(0, 2, 0.4), "renamed");
        assert_eq!(classify_obfuscation(0, 2, 0.1), "none");
    }
}
