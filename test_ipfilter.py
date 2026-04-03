#!/usr/bin/env python3
"""
Unit tests for ipfilter.py
Tests IP validation, conversion, merging, and file parsing logic.
"""
import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock
import ipfilter


class TestIPValidation(unittest.TestCase):
    """Test IP address validation functions."""

    def test_is_valid_ip_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        self.assertTrue(ipfilter.is_valid_ip("192.168.1.1"))
        self.assertTrue(ipfilter.is_valid_ip("10.0.0.1"))
        self.assertTrue(ipfilter.is_valid_ip("255.255.255.255"))
        self.assertTrue(ipfilter.is_valid_ip("0.0.0.0"))

    def test_is_valid_ip_invalid_ipv4(self):
        """Test invalid IPv4 addresses."""
        self.assertFalse(ipfilter.is_valid_ip("256.1.1.1"))
        self.assertFalse(ipfilter.is_valid_ip("192.168.1"))
        self.assertFalse(ipfilter.is_valid_ip("192.168.1.1.1"))
        self.assertFalse(ipfilter.is_valid_ip("not.an.ip.address"))
        self.assertFalse(ipfilter.is_valid_ip(""))

    def test_is_valid_ip_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        self.assertTrue(ipfilter.is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertTrue(ipfilter.is_valid_ip("::1"))
        self.assertTrue(ipfilter.is_valid_ip("fe80::"))


class TestIPConversion(unittest.TestCase):
    """Test IP to integer conversion functions."""

    def test_ip_to_int(self):
        """Test IP address to integer conversion."""
        self.assertEqual(ipfilter.ip_to_int("0.0.0.0"), 0)
        self.assertEqual(ipfilter.ip_to_int("0.0.0.1"), 1)
        self.assertEqual(ipfilter.ip_to_int("192.168.1.1"), 3232235777)
        self.assertEqual(ipfilter.ip_to_int("255.255.255.255"), 4294967295)

    def test_int_to_ip(self):
        """Test integer to IP address conversion."""
        self.assertEqual(ipfilter.int_to_ip(0), "0.0.0.0")
        self.assertEqual(ipfilter.int_to_ip(1), "0.0.0.1")
        self.assertEqual(ipfilter.int_to_ip(3232235777), "192.168.1.1")
        self.assertEqual(ipfilter.int_to_ip(4294967295), "255.255.255.255")

    def test_ip_conversion_roundtrip(self):
        """Test that IP conversion is reversible."""
        test_ips = ["10.0.0.1", "172.16.0.1", "192.168.1.100", "8.8.8.8"]
        for ip in test_ips:
            self.assertEqual(ipfilter.int_to_ip(ipfilter.ip_to_int(ip)), ip)


class TestIPRangeMerging(unittest.TestCase):
    """Test IP range merging logic."""

    def test_merge_ip_ranges_empty(self):
        """Test merging with no ranges."""
        merged, stats = ipfilter.merge_ip_ranges([])
        self.assertEqual(merged, [])
        self.assertEqual(stats['raw_count'], 0)
        self.assertEqual(stats['merged_count'], 0)
        self.assertEqual(stats['reduction_percent'], 0)

    def test_merge_ip_ranges_single(self):
        """Test merging with a single range."""
        ranges = [("10.0.0.1", "10.0.0.10", "test")]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0], ("10.0.0.1", "10.0.0.10", "test"))
        self.assertEqual(stats['raw_count'], 1)
        self.assertEqual(stats['merged_count'], 1)

    def test_merge_ip_ranges_overlapping(self):
        """Test merging overlapping ranges."""
        ranges = [
            ("10.0.0.1", "10.0.0.10", "range1"),
            ("10.0.0.5", "10.0.0.15", "range2")
        ]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0][0], "10.0.0.1")
        self.assertEqual(merged[0][1], "10.0.0.15")
        self.assertEqual(stats['raw_count'], 2)
        self.assertEqual(stats['merged_count'], 1)

    def test_merge_ip_ranges_adjacent(self):
        """Test merging adjacent ranges (differ by 1)."""
        ranges = [
            ("10.0.0.1", "10.0.0.10", "range1"),
            ("10.0.0.11", "10.0.0.20", "range2")
        ]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        # Adjacent ranges should be merged
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0][0], "10.0.0.1")
        self.assertEqual(merged[0][1], "10.0.0.20")

    def test_merge_ip_ranges_separate(self):
        """Test merging separate non-overlapping ranges."""
        ranges = [
            ("10.0.0.1", "10.0.0.10", "range1"),
            ("10.0.0.20", "10.0.0.30", "range2")
        ]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        self.assertEqual(len(merged), 2)
        self.assertEqual(stats['raw_count'], 2)
        self.assertEqual(stats['merged_count'], 2)

    def test_merge_ip_ranges_unsorted(self):
        """Test that unsorted ranges are handled correctly."""
        ranges = [
            ("10.0.0.20", "10.0.0.30", "range2"),
            ("10.0.0.1", "10.0.0.10", "range1"),
            ("10.0.0.5", "10.0.0.15", "range3")
        ]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        # Should merge into two ranges
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0][0], "10.0.0.1")
        self.assertEqual(merged[0][1], "10.0.0.15")
        self.assertEqual(merged[1][0], "10.0.0.20")
        self.assertEqual(merged[1][1], "10.0.0.30")

    def test_merge_ip_ranges_identical(self):
        """Test merging identical ranges."""
        ranges = [
            ("10.0.0.1", "10.0.0.10", "range1"),
            ("10.0.0.1", "10.0.0.10", "range2")
        ]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        self.assertEqual(len(merged), 1)
        self.assertEqual(stats['raw_count'], 2)
        self.assertEqual(stats['merged_count'], 1)

    def test_merge_ip_ranges_contained(self):
        """Test merging when one range is contained within another."""
        ranges = [
            ("10.0.0.1", "10.0.0.100", "large"),
            ("10.0.0.10", "10.0.0.20", "small")
        ]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0], ("10.0.0.1", "10.0.0.100", "large"))

    def test_merge_ip_ranges_invalid_range(self):
        """Test that invalid ranges (start > end) are skipped."""
        ranges = [
            ("10.0.0.10", "10.0.0.1", "invalid"),  # start > end
            ("10.0.0.1", "10.0.0.10", "valid")
        ]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0][0], "10.0.0.1")

    def test_merge_ip_ranges_reduction_stats(self):
        """Test that reduction statistics are calculated correctly."""
        ranges = [
            ("10.0.0.1", "10.0.0.10", "range1"),
            ("10.0.0.5", "10.0.0.15", "range2"),
            ("10.0.0.8", "10.0.0.20", "range3"),
            ("10.0.0.30", "10.0.0.40", "range4")
        ]
        merged, stats = ipfilter.merge_ip_ranges(ranges)
        self.assertEqual(stats['raw_count'], 4)
        self.assertEqual(stats['merged_count'], 2)
        self.assertEqual(stats['reduction_percent'], 50)


class TestParseIPRanges(unittest.TestCase):
    """Test IP range parsing from files."""

    def test_parse_ip_ranges_valid_format(self):
        """Test parsing valid IP range lines."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.p2p') as f:
            f.write("Test Range:10.0.0.1-10.0.0.10\n")
            f.write("Another Range:192.168.1.1-192.168.1.255\n")
            temp_path = f.name

        try:
            log_lines = []
            ranges = ipfilter.parse_ip_ranges_from_file(temp_path, log_lines, "test_list")
            self.assertEqual(len(ranges), 2)
            self.assertEqual(ranges[0][0], "10.0.0.1")
            self.assertEqual(ranges[0][1], "10.0.0.10")
            self.assertEqual(ranges[1][0], "192.168.1.1")
            self.assertEqual(ranges[1][1], "192.168.1.255")
        finally:
            os.unlink(temp_path)

    def test_parse_ip_ranges_skip_comments(self):
        """Test that comment lines are skipped."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.p2p') as f:
            f.write("# This is a comment\n")
            f.write("Valid Range:10.0.0.1-10.0.0.10\n")
            f.write("# Another comment\n")
            temp_path = f.name

        try:
            log_lines = []
            ranges = ipfilter.parse_ip_ranges_from_file(temp_path, log_lines)
            self.assertEqual(len(ranges), 1)
        finally:
            os.unlink(temp_path)

    def test_parse_ip_ranges_skip_empty_lines(self):
        """Test that empty lines are skipped."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.p2p') as f:
            f.write("\n")
            f.write("Valid Range:10.0.0.1-10.0.0.10\n")
            f.write("\n\n")
            temp_path = f.name

        try:
            log_lines = []
            ranges = ipfilter.parse_ip_ranges_from_file(temp_path, log_lines)
            self.assertEqual(len(ranges), 1)
        finally:
            os.unlink(temp_path)

    def test_parse_ip_ranges_invalid_format(self):
        """Test that invalid format lines are logged and skipped."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.p2p') as f:
            f.write("Not a valid IP range line\n")
            f.write("Valid Range:10.0.0.1-10.0.0.10\n")
            temp_path = f.name

        try:
            log_lines = []
            ranges = ipfilter.parse_ip_ranges_from_file(temp_path, log_lines, "test")
            self.assertEqual(len(ranges), 1)
            # Check that error was logged
            self.assertTrue(any("ERROR" in line for line in log_lines))
        finally:
            os.unlink(temp_path)

    def test_parse_ip_ranges_invalid_ip(self):
        """Test that lines with invalid IP addresses are skipped."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.p2p') as f:
            f.write("Invalid:256.0.0.1-10.0.0.10\n")
            f.write("Valid:10.0.0.1-10.0.0.10\n")
            temp_path = f.name

        try:
            log_lines = []
            ranges = ipfilter.parse_ip_ranges_from_file(temp_path, log_lines, "test")
            self.assertEqual(len(ranges), 1)
            self.assertTrue(any("ERROR" in line for line in log_lines))
        finally:
            os.unlink(temp_path)

    def test_parse_ip_ranges_default_description(self):
        """Test that ranges without description use list name."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.p2p') as f:
            f.write("10.0.0.1-10.0.0.10\n")
            temp_path = f.name

        try:
            log_lines = []
            ranges = ipfilter.parse_ip_ranges_from_file(temp_path, log_lines, "default_name")
            self.assertEqual(len(ranges), 1)
            self.assertEqual(ranges[0][2], "default_name")
        finally:
            os.unlink(temp_path)


class TestWriteMergedRanges(unittest.TestCase):
    """Test writing merged ranges to file."""

    def test_write_merged_ranges(self):
        """Test that merged ranges are written in correct format."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.dat') as f:
            temp_path = f.name

        try:
            ranges = [
                ("10.0.0.1", "10.0.0.10", "test1"),
                ("192.168.1.1", "192.168.1.255", "test2")
            ]
            log_lines = []
            ipfilter.write_merged_ranges(ranges, temp_path, log_lines)

            # Verify file content
            with open(temp_path, 'r') as f:
                lines = f.readlines()

            self.assertEqual(len(lines), 2)
            self.assertIn("10.0.0.1 - 10.0.0.10 , 000 , test1", lines[0])
            self.assertIn("192.168.1.1 - 192.168.1.255 , 000 , test2", lines[1])

            # Verify log entry
            self.assertTrue(any("Written" in line for line in log_lines))
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestDownloadWithRetry(unittest.TestCase):
    """Test download retry logic."""

    @patch('ipfilter.requests.get')
    def test_download_success_first_try(self, mock_get):
        """Test successful download on first attempt."""
        mock_response = MagicMock()
        mock_response.headers.get.return_value = '1024'
        mock_response.iter_content.return_value = [b'data']
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_get.return_value = mock_response

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            success, error = ipfilter.download_with_retry(
                "http://example.com/list.gz",
                temp_path,
                "test_list",
                max_retries=1
            )
            self.assertTrue(success)
            self.assertIsNone(error)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    @patch('ipfilter.requests.get')
    @patch('ipfilter.time.sleep')
    def test_download_retry_on_timeout(self, mock_sleep, mock_get):
        """Test retry logic on timeout."""
        mock_get.side_effect = ipfilter.requests.exceptions.Timeout("Timeout")

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            success, error = ipfilter.download_with_retry(
                "http://example.com/list.gz",
                temp_path,
                "test_list",
                max_retries=2
            )
            self.assertFalse(success)
            self.assertIsNotNone(error)
            self.assertIn("Timeout", error)
            # Should have retried once (max_retries-1)
            self.assertEqual(mock_sleep.call_count, 1)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    @patch('ipfilter.requests.get')
    def test_download_http_404_error(self, mock_get):
        """Test handling of HTTP 404 error."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = ipfilter.requests.exceptions.HTTPError(response=mock_response)
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_get.return_value = mock_response

        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            success, error = ipfilter.download_with_retry(
                "http://example.com/list.gz",
                temp_path,
                "test_list",
                max_retries=1
            )
            self.assertFalse(success)
            self.assertIn("404", error)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
