#!/usr/bin/env python3
# Behavioral timing detection using distribution-agnostic metrics
# Detects: (1) Steady randomized traffic vs bursty user behavior
#          (2) Evasive delayed processes vs normal baseline

import json
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
from collections import Counter

class BehavioralTimingDetector:
    """
    Detect timing anomalies without assuming normal distribution
    Uses: IQR, burstiness coefficient, clustering metrics
    """

    def __init__(self):
        self.events = []
        self.intervals = []

    def load_events(self, events):
        """Load events from list of dicts with 'timestamp' field"""
        self.events = sorted(events, key=lambda x: datetime.fromisoformat(x['timestamp']))

        # Calculate intervals in minutes
        timestamps = [datetime.fromisoformat(e['timestamp']) for e in self.events]
        self.intervals = []
        for i in range(1, len(timestamps)):
            interval_minutes = (timestamps[i] - timestamps[i-1]).total_seconds() / 60.0
            self.intervals.append(interval_minutes)

    def calculate_burstiness(self):
        """
        Burstiness coefficient: measures clustering vs uniformity
        B = (std - mean) / (std + mean)

        B ~ 1: Bursty (clustered events)
        B ~ 0: Random/Poisson
        B ~ -1: Periodic/regular

        Does NOT assume normal distribution
        """
        if not self.intervals:
            return None

        mean = np.mean(self.intervals)
        std = np.std(self.intervals)

        if std + mean == 0:
            return 0

        burstiness = (std - mean) / (std + mean)
        return burstiness

    def calculate_iqr_ratio(self):
        """
        IQR (Interquartile Range) ratio: distribution-agnostic spread metric
        IQR_ratio = IQR / median

        High ratio = high variability
        Low ratio = consistent timing

        More robust than std deviation for non-normal distributions
        """
        if not self.intervals:
            return None

        q1 = np.percentile(self.intervals, 25)
        q3 = np.percentile(self.intervals, 75)
        iqr = q3 - q1
        median = np.median(self.intervals)

        if median == 0:
            return 0

        iqr_ratio = iqr / median
        return iqr_ratio

    def calculate_gini_coefficient(self):
        """
        Gini coefficient: measures inequality in interval distribution
        0 = perfect equality (all intervals same)
        1 = maximum inequality (huge variance)

        Distribution-agnostic inequality measure
        """
        if not self.intervals:
            return None

        sorted_intervals = np.sort(self.intervals)
        n = len(sorted_intervals)
        cumsum = np.cumsum(sorted_intervals)

        # Gini formula
        gini = (2 * np.sum((np.arange(1, n+1)) * sorted_intervals)) / (n * np.sum(sorted_intervals)) - (n + 1) / n
        return gini

    def detect_clustering(self):
        """
        Detect if intervals form distinct clusters (bursts)
        vs evenly distributed (randomized evasion)

        Returns: number of clusters, cluster sizes
        """
        if len(self.intervals) < 5:
            return None, None

        # Simple clustering: group intervals within 30% of each other
        sorted_intervals = sorted(self.intervals)
        clusters = []
        current_cluster = [sorted_intervals[0]]

        for i in range(1, len(sorted_intervals)):
            # If within 30% of cluster median, add to cluster
            cluster_median = np.median(current_cluster)
            if abs(sorted_intervals[i] - cluster_median) / cluster_median < 0.3:
                current_cluster.append(sorted_intervals[i])
            else:
                # Start new cluster
                clusters.append(current_cluster)
                current_cluster = [sorted_intervals[i]]

        clusters.append(current_cluster)

        cluster_sizes = [len(c) for c in clusters]
        return len(clusters), cluster_sizes

    def analyze_network_traffic(self):
        """
        Detect: Steady randomized (evasion) vs Bursty user behavior (legitimate)

        Evasive: Low burstiness, high IQR ratio, evenly distributed
        Legitimate: High burstiness, multiple clusters, variable gaps
        """
        if not self.intervals:
            return {"error": "No intervals to analyze"}

        burstiness = self.calculate_burstiness()
        iqr_ratio = self.calculate_iqr_ratio()
        gini = self.calculate_gini_coefficient()
        num_clusters, cluster_sizes = self.detect_clustering()

        # Detection logic (distribution-agnostic)
        # Key insight: Burstiness is primary indicator for network traffic
        # Negative burstiness = regular/steady (evasive randomization)
        # Positive burstiness = clustered/bursty (legitimate user behavior)
        anomalies = []
        risk_score = 0

        # 1. Negative or near-zero burstiness = steady randomized (PRIMARY INDICATOR)
        if burstiness is not None and burstiness < 0.1:
            confidence = 0.90 if burstiness < -0.2 else 0.75
            anomalies.append({
                "type": "steady_randomized_traffic",
                "confidence": confidence,
                "evidence": f"Burstiness={burstiness:.2f} (steady/regular pattern, not bursty user)"
            })
            risk_score += 60 if burstiness < -0.2 else 45

        # 2. Low Gini = equality in intervals (evenly distributed)
        if gini is not None and gini < 0.35:
            anomalies.append({
                "type": "evenly_distributed_intervals",
                "confidence": 0.80,
                "evidence": f"Gini={gini:.2f} (low inequality, even distribution not user behavior)"
            })
            risk_score += 40

        # Legitimate indicators (reduce score)
        # High burstiness = clustered activity (user researching in bursts)
        if burstiness is not None and burstiness > 0.25:
            risk_score = max(0, risk_score - 50)  # Strong legitimate signal

        # High Gini = inequality (big gaps between bursts, typical user)
        if gini is not None and gini > 0.6:
            risk_score = max(0, risk_score - 35)  # User has work gaps

        classification = "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 40 else "LOW"

        return {
            "scenario": "network_traffic",
            "event_count": len(self.events),
            "interval_count": len(self.intervals),
            "burstiness": round(burstiness, 3) if burstiness is not None else None,
            "iqr_ratio": round(iqr_ratio, 3) if iqr_ratio is not None else None,
            "gini_coefficient": round(gini, 3) if gini is not None else None,
            "num_clusters": num_clusters,
            "cluster_sizes": cluster_sizes,
            "anomalies": anomalies,
            "risk_score": min(100, risk_score),
            "classification": classification
        }

    def analyze_process_behavior(self, baseline_intervals=None):
        """
        Detect: Evasive delayed process vs Normal scheduled baseline

        Evasive: Irregular delays, high Gini, no pattern
        Normal: Regular pattern or predictable bursts
        """
        if not self.intervals:
            return {"error": "No intervals to analyze"}

        burstiness = self.calculate_burstiness()
        iqr_ratio = self.calculate_iqr_ratio()
        gini = self.calculate_gini_coefficient()

        anomalies = []
        risk_score = 0

        # 1. Compare to baseline if provided
        if baseline_intervals:
            baseline_median = np.median(baseline_intervals)
            test_median = np.median(self.intervals)
            deviation = abs(test_median - baseline_median) / baseline_median

            if deviation > 0.5:
                anomalies.append({
                    "type": "baseline_deviation",
                    "confidence": 0.80,
                    "evidence": f"Median interval {deviation*100:.0f}% different from baseline"
                })
                risk_score += 45

        # 2. High Gini = inequality in timing (randomization)
        if gini is not None and gini > 0.4:
            anomalies.append({
                "type": "irregular_timing",
                "confidence": 0.75,
                "evidence": f"Gini={gini:.2f} (high inequality, randomized delays)"
            })
            risk_score += 35

        # 3. IQR ratio check
        if iqr_ratio is not None and iqr_ratio > 0.7:
            anomalies.append({
                "type": "high_variability",
                "confidence": 0.70,
                "evidence": f"IQR ratio={iqr_ratio:.2f} (inconsistent execution pattern)"
            })
            risk_score += 25

        classification = "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 40 else "LOW"

        return {
            "scenario": "process_behavior",
            "event_count": len(self.events),
            "interval_count": len(self.intervals),
            "burstiness": round(burstiness, 3) if burstiness is not None else None,
            "iqr_ratio": round(iqr_ratio, 3) if iqr_ratio is not None else None,
            "gini_coefficient": round(gini, 3) if gini is not None else None,
            "anomalies": anomalies,
            "risk_score": min(100, risk_score),
            "classification": classification
        }

    def plot_comparison(self, other_detector, title_self, title_other, output_file):
        """
        Create visual comparison plots (PNG)
        Shows: interval distribution, timeline, histogram
        """
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Timing Pattern Analysis', fontsize=16, weight='bold')

        # Plot 1: Timeline visualization (self)
        ax = axes[0, 0]
        timestamps = [datetime.fromisoformat(e['timestamp']) for e in self.events]
        relative_times = [(t - timestamps[0]).total_seconds() / 3600 for t in timestamps]
        ax.scatter(relative_times, [1]*len(relative_times), alpha=0.6, s=50, color='red')
        ax.set_yticks([])
        ax.set_xlabel('Time (hours from start)')
        ax.set_title(f'{title_self}\nEvent Timeline', fontsize=12)
        ax.grid(True, alpha=0.3)

        # Plot 2: Timeline visualization (other)
        ax = axes[0, 1]
        timestamps_other = [datetime.fromisoformat(e['timestamp']) for e in other_detector.events]
        relative_times_other = [(t - timestamps_other[0]).total_seconds() / 3600 for t in timestamps_other]
        ax.scatter(relative_times_other, [1]*len(relative_times_other), alpha=0.6, s=50, color='blue')
        ax.set_yticks([])
        ax.set_xlabel('Time (hours from start)')
        ax.set_title(f'{title_other}\nEvent Timeline', fontsize=12)
        ax.grid(True, alpha=0.3)

        # Plot 3: Interval histogram (self)
        ax = axes[1, 0]
        ax.hist(self.intervals, bins=15, alpha=0.7, color='red', edgecolor='black')
        ax.axvline(np.median(self.intervals), color='darkred', linestyle='--', linewidth=2, label=f'Median: {np.median(self.intervals):.1f}m')
        ax.set_xlabel('Interval (minutes)')
        ax.set_ylabel('Frequency')
        ax.set_title(f'{title_self}\nInterval Distribution', fontsize=12)
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Plot 4: Interval histogram (other)
        ax = axes[1, 1]
        ax.hist(other_detector.intervals, bins=15, alpha=0.7, color='blue', edgecolor='black')
        ax.axvline(np.median(other_detector.intervals), color='darkblue', linestyle='--', linewidth=2, label=f'Median: {np.median(other_detector.intervals):.1f}m')
        ax.set_xlabel('Interval (minutes)')
        ax.set_ylabel('Frequency')
        ax.set_title(f'{title_other}\nInterval Distribution', fontsize=12)
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"[INFO] Visualization saved: {output_file}")
        plt.close()


if __name__ == "__main__":
    print("[DETECTION] Behavioral Timing Detector")
    print("[INFO] Using distribution-agnostic metrics (IQR, burstiness, Gini)\n")

    # Load realistic logs
    with open('realistic_timing_logs.json', 'r') as f:
        data = json.load(f)

    print("="*70)
    print("SCENARIO A: NETWORK TRAFFIC ANALYSIS")
    print("="*70)

    # Analyze randomized (evasive) traffic
    detector_randomized = BehavioralTimingDetector()
    detector_randomized.load_events(data['scenario_a_network']['randomized_evasive'])
    result_random = detector_randomized.analyze_network_traffic()

    print("\n[TEST 1] Randomized Traffic (Evasive):")
    print(f"  Events: {result_random['event_count']}")
    print(f"  Burstiness: {result_random['burstiness']} (0=random, 1=bursty)")
    print(f"  IQR Ratio: {result_random['iqr_ratio']}")
    print(f"  Gini Coefficient: {result_random['gini_coefficient']}")
    print(f"  Clusters: {result_random['num_clusters']}")
    print(f"  Risk Score: {result_random['risk_score']}/100 - {result_random['classification']}")

    if result_random['anomalies']:
        print(f"\n  [ALERT] Anomalies detected ({len(result_random['anomalies'])}):")
        for a in result_random['anomalies']:
            print(f"    - {a['type']}: {a['evidence']}")

    # Analyze bursty (legitimate) traffic
    detector_bursty = BehavioralTimingDetector()
    detector_bursty.load_events(data['scenario_a_network']['bursty_legitimate'])
    result_bursty = detector_bursty.analyze_network_traffic()

    print("\n[TEST 2] Bursty User Traffic (Legitimate):")
    print(f"  Events: {result_bursty['event_count']}")
    print(f"  Burstiness: {result_bursty['burstiness']} (0=random, 1=bursty)")
    print(f"  IQR Ratio: {result_bursty['iqr_ratio']}")
    print(f"  Gini Coefficient: {result_bursty['gini_coefficient']}")
    print(f"  Clusters: {result_bursty['num_clusters']}")
    print(f"  Risk Score: {result_bursty['risk_score']}/100 - {result_bursty['classification']}")

    if result_bursty['anomalies']:
        print(f"\n  [ALERT] Anomalies detected ({len(result_bursty['anomalies'])}):")
        for a in result_bursty['anomalies']:
            print(f"    - {a['type']}: {a['evidence']}")

    # Generate comparison plot
    detector_randomized.plot_comparison(
        detector_bursty,
        "Randomized (Evasive)",
        "Bursty User (Legitimate)",
        "network_traffic_comparison.png"
    )

    print("\n" + "="*70)
    print("SCENARIO B: PROCESS BEHAVIOR ANALYSIS")
    print("="*70)

    # Analyze evasive process
    detector_evasive = BehavioralTimingDetector()
    detector_evasive.load_events(data['scenario_b_process']['evasive_delayed'])

    # Get baseline from normal process
    detector_normal = BehavioralTimingDetector()
    detector_normal.load_events(data['scenario_b_process']['normal_scheduled'])
    baseline_intervals = detector_normal.intervals

    result_evasive = detector_evasive.analyze_process_behavior(baseline_intervals)

    print("\n[TEST 3] Evasive Process (Delayed):")
    print(f"  Events: {result_evasive['event_count']}")
    print(f"  Burstiness: {result_evasive['burstiness']}")
    print(f"  IQR Ratio: {result_evasive['iqr_ratio']}")
    print(f"  Gini Coefficient: {result_evasive['gini_coefficient']}")
    print(f"  Risk Score: {result_evasive['risk_score']}/100 - {result_evasive['classification']}")

    if result_evasive['anomalies']:
        print(f"\n  [ALERT] Anomalies detected ({len(result_evasive['anomalies'])}):")
        for a in result_evasive['anomalies']:
            print(f"    - {a['type']}: {a['evidence']}")

    # Analyze normal process
    result_normal = detector_normal.analyze_process_behavior()

    print("\n[TEST 4] Normal Process (Scheduled):")
    print(f"  Events: {result_normal['event_count']}")
    print(f"  Burstiness: {result_normal['burstiness']}")
    print(f"  IQR Ratio: {result_normal['iqr_ratio']}")
    print(f"  Gini Coefficient: {result_normal['gini_coefficient']}")
    print(f"  Risk Score: {result_normal['risk_score']}/100 - {result_normal['classification']}")

    # Generate comparison plot
    detector_evasive.plot_comparison(
        detector_normal,
        "Evasive Delayed Process",
        "Normal Scheduled Process",
        "process_behavior_comparison.png"
    )

    print("\n" + "="*70)
    print("DETECTION SUMMARY")
    print("="*70)
    print("\nNetwork Traffic:")
    print(f"  Randomized (evasive): {result_random['risk_score']}/100 - {result_random['classification']}")
    print(f"  Bursty user (legit):  {result_bursty['risk_score']}/100 - {result_bursty['classification']}")
    print("\nProcess Behavior:")
    print(f"  Evasive delayed:      {result_evasive['risk_score']}/100 - {result_evasive['classification']}")
    print(f"  Normal scheduled:     {result_normal['risk_score']}/100 - {result_normal['classification']}")
    print("\n[SUCCESS] Analysis complete. Visual comparisons saved as PNG files.")
