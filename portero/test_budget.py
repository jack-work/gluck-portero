#!/usr/bin/env python3
"""Budget tests.

The properties the rate limit rests on:

  a key spends only its own allowance
  the window slides, so a quiet minute restores the allowance
  memory is bounded even when the key space is not
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from budget import Budget  # noqa: E402


class Window(unittest.TestCase):
    def test_limit_is_the_count_inside_the_window(self):
        b = Budget(3, 60)
        self.assertEqual([b.spend(now=t) for t in (0, 1, 2, 3, 4)],
                         [True, True, True, False, False])

    def test_window_slides(self):
        b = Budget(2, 60)
        self.assertTrue(b.spend(now=0))
        self.assertTrue(b.spend(now=1))
        self.assertFalse(b.spend(now=2))
        self.assertTrue(b.spend(now=61), "an hour-old hit must not still count")

    def test_a_refused_request_does_not_extend_the_block(self):
        b = Budget(1, 10)
        self.assertTrue(b.spend(now=0))
        for t in range(1, 10):
            self.assertFalse(b.spend(now=t))
        self.assertTrue(b.spend(now=10.1))

    def test_zero_limit_refuses_everything_and_holds_no_key(self):
        b = Budget(0, 60)
        self.assertFalse(b.spend("k", now=0))
        self.assertEqual(b.keys_held(), 0)


class Keys(unittest.TestCase):
    def test_keys_are_independent(self):
        b = Budget(1, 60)
        self.assertTrue(b.spend("a", now=0))
        self.assertFalse(b.spend("a", now=1))
        self.assertTrue(b.spend("b", now=1), "one key must not spend another's")

    def test_memory_is_bounded_by_max_keys(self):
        b = Budget(5, 600, max_keys=16)
        for i in range(10_000):
            b.spend(f"key-{i}", now=i * 0.001)
        self.assertLessEqual(b.keys_held(), 16)

    def test_expired_keys_are_dropped(self):
        b = Budget(5, 10)
        for i in range(100):
            b.spend(f"key-{i}", now=0)
        self.assertEqual(b.keys_held(), 100)
        b.spend("fresh", now=100)
        self.assertEqual(b.keys_held(), 1, "a key with no live hits must be freed")

    def test_eviction_is_least_recently_used(self):
        b = Budget(5, 600, max_keys=2)
        b.spend("old", now=0)
        b.spend("mid", now=1)
        b.spend("new", now=2)
        self.assertEqual(b.spent("old"), 0)
        self.assertEqual(b.spent("new"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
