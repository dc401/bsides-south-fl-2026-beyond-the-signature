#!/usr/bin/env python3
# Timing evasion using dynamic seeding and randomized intervals
# Source: Evasion Engineering (Chow & LaSalvia) - Chapter 2
# https://nostarch.com/evasion-engineering

import time
import random
import os

def dynamic_seed():
    """Generate time-based seed for randomization"""
    seed = int(time.time() * 1000) ^ os.getpid()
    random.seed(seed)
    return seed

def get_random_interval(min_minutes=16, max_minutes=77):
    """Return random interval in seconds between min and max minutes"""
    return random.randint(min_minutes * 60, max_minutes * 60)

def simulate_operation(op_name):
    """Simulate an operation that would normally be detected"""
    print(f"[{time.strftime('%H:%M:%S')}] Executing: {op_name}")
    return True

if __name__ == "__main__":
    # Initialize with dynamic seed
    seed = dynamic_seed()
    print(f"[INFO] Seed: {seed}")
    print(f"[DEMO MODE] Using shortened delays (2-5sec) for demonstration")
    print(f"[DEMO MODE] Production: Remove demo_delay, use actual 'delay' value\n")

    # Simulate 3 operations with randomized timing
    operations = ["reconnaissance", "enumeration", "execution"]

    for i, op in enumerate(operations):
        simulate_operation(op)

        if i < len(operations) - 1:
            # Calculate real delay (16-77 minutes)
            delay = get_random_interval(16, 77)
            delay_minutes = delay / 60
            print(f"[PRODUCTION] Real delay: {delay_minutes:.2f} minutes ({delay}sec)")

            # Demo mode: Use short delay for presentation
            demo_delay = random.randint(2, 5)
            print(f"[DEMO MODE] Actually sleeping: {demo_delay} seconds\n")
            time.sleep(demo_delay)
            # Production: Use this instead: time.sleep(delay)
