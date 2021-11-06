import unittest
from verkle_trie import VERKLE_TRIE_NODE_TYPE_INNER, verkle_add_missing_commitments, update_verkle_tree_nocommitmentupdate, update_verkle_tree


class TestVerkle(unittest.TestCase):

    def test_empty_trie(self):
        """
            Test the root when the trie is empty, should be 0
        """
        root_node = {"node_type": VERKLE_TRIE_NODE_TYPE_INNER}
        verkle_add_missing_commitments(root_node)
        self.assertEqual(
            "0000000000000000000000000000000000000000000000000000000000000000", root_node["commitment"].serialize().hex())

    # def test_update_bug(self):
    #     """
    #     This produces a panic, because update assumes that nodes have their commitments already set
    #     However, the function comments say that it can be used for insertion
    #     """
    #     root_node = {"node_type": VERKLE_TRIE_NODE_TYPE_INNER}
    #     key = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    #                  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
    #     update_verkle_tree(root_node, key, key)

    def test_simple_insert_consistency(self):
        """
        Test a simple key insert
        """
        root_node = {"node_type": VERKLE_TRIE_NODE_TYPE_INNER}
        key = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
        update_verkle_tree_nocommitmentupdate(root_node, key, key)
        verkle_add_missing_commitments(root_node)
        self.assertEqual("d949e1bb56100d77923a642d080c26775b85f9bc457cec7f3234d140ced15e0d", root_node["commitment_field"].to_bytes(
            32, "little").hex())

    def test_simple_update_consistency(self):
        """
        Test a simple key update
        """
        root_node = {"node_type": VERKLE_TRIE_NODE_TYPE_INNER}
        key = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
        all_zeroes = int(0).to_bytes(32, "little")
        update_verkle_tree_nocommitmentupdate(root_node, key, all_zeroes)
        verkle_add_missing_commitments(root_node)

        update_verkle_tree(root_node, key, key)
        self.assertEqual("d949e1bb56100d77923a642d080c26775b85f9bc457cec7f3234d140ced15e0d", root_node["commitment_field"].to_bytes(
            32, "little").hex())

    def test_insert_longest_path(self):
        """
        Test where keys create the longest path
        """
        root_node = {"node_type": VERKLE_TRIE_NODE_TYPE_INNER}

        key_zero = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        key_zero_except_30 = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0])

        update_verkle_tree_nocommitmentupdate(root_node, key_zero, key_zero)
        update_verkle_tree_nocommitmentupdate(
            root_node, key_zero_except_30, key_zero_except_30)
        verkle_add_missing_commitments(root_node)

        self.assertEqual("ab124cd04cdb4e18f797d826969537b5f0c0037fd167a5f2eafbc6206d2d1b02", root_node["commitment_field"].to_bytes(
            32, "little").hex())

    def test_traverse_longest_path(self):
        """
        Test where keys create the longest path and the new key traverses that path
        """
        root_node = {"node_type": VERKLE_TRIE_NODE_TYPE_INNER}

        key_zero = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        key_zero_except_30 = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0])
        key_zero_except_29 = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0])

        update_verkle_tree_nocommitmentupdate(root_node, key_zero, key_zero)
        update_verkle_tree_nocommitmentupdate(
            root_node, key_zero_except_30, key_zero_except_30)
        verkle_add_missing_commitments(root_node)

        # This update will need to traverse a lot of empty inner nodes, caused
        # by the first two inserts
        update_verkle_tree(root_node, key_zero_except_29, key_zero_except_29)

        self.assertEqual("117ff4b8cb99ae8bce1680dd33a840d49d0d5bea8529f63ea253d9abd985d602", root_node["commitment_field"].to_bytes(
            32, "little").hex())


if __name__ == '__main__':
    unittest.main()
