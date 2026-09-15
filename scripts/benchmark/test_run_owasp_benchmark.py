import unittest
import xml.etree.ElementTree as ET

from run_owasp_benchmark import _build_request


class BuildRequestTest(unittest.TestCase):
    def test_servlet_without_query_parameters_is_post(self) -> None:
        test = ET.fromstring(
            '<benchmarkTest URL="https://localhost:8443/benchmark/x/Test00001">'
            '<cookie name="Test00001" value="hello world" />'
            "</benchmarkTest>"
        )

        request = _build_request(test, "http://127.0.0.1:9000")

        self.assertEqual("POST", request.get_method())
        self.assertEqual("http://127.0.0.1:9000/benchmark/x/Test00001", request.full_url)
        self.assertEqual(b"", request.data)
        self.assertEqual("Test00001=hello%20world", request.get_header("Cookie"))

    def test_servlet_with_query_parameters_is_get(self) -> None:
        test = ET.fromstring(
            '<benchmarkTest URL="https://localhost:8443/benchmark/x/Test00002">'
            '<getparam name="Test00002" value="hello world" />'
            "</benchmarkTest>"
        )

        request = _build_request(test, "http://127.0.0.1:9000")

        self.assertEqual("GET", request.get_method())
        self.assertEqual(
            "http://127.0.0.1:9000/benchmark/x/Test00002?Test00002=hello+world",
            request.full_url,
        )
        self.assertIsNone(request.data)


if __name__ == "__main__":
    unittest.main()
