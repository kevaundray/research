import unittest
import hashlib
from bandersnatch import Point
from crs import get_crs


class TestCRS(unittest.TestCase):

    def test_crs_is_consistent(self):
        """
            Test that the CRS is consistent with https://hackmd.io/1RcGSMQgT4uREaq1CCx_cg#Methodology
        """
        crs = get_crs()

        self.assertEqual(256, len(crs))

        got_first_point = crs[0].serialize().hex()
        expected_fist_point = "22ac968a98ab6c50379fc8b039abc8fd9aca259f4746a05bfbdf12c86463c208"
        self.assertEqual(got_first_point, expected_fist_point)

        got_256th_point = crs[255].serialize().hex()
        expected_256th_point = "c8b4968a98ab6c50379fc8b039abc8fd9aca259f4746a05bfbdf12c86463c208"
        self.assertEqual(got_256th_point, expected_256th_point)

        hasher = hashlib.sha256()
        for point in crs:
            hasher.update(point.serialize())
        result = hasher.digest().hex()

        self.assertEqual(
            "c390cbb4bc42019685d5a01b2fb8a536d4332ea4e128934d0ae7644163089e76", result)

    def test_crs_not_generator(self):
        """
            We use the generator point as the point `Q`, corresponding to the inner product
            so we check if the generated point is one of these
        """
        crs = get_crs()

        generator = Point(True)

        for point in crs:
            self.assertNotEqual(generator, point)


if __name__ == '__main__':
    unittest.main()
