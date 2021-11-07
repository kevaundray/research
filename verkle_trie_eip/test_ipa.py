import unittest
from transcript import Transcript
from verkle_trie import ipa_utils, MODULUS, make_ipa_multiproof, check_ipa_multiproof


class TestIPA(unittest.TestCase):

    # def test_undefined_output_on_domain(self):
    #     """
    #         Currently the API allows you to commit to a point inside of the domain, using the formula for points outside of the domain

    #     """
    #     # Polynomial in lagrange basis
    #     poly_eval = [9, 1, 3, 8, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    #                  17, 18, 19, 223, 215, 229, 23, 248, 25, 267, 27, 281, 29, 301, 31, 32]*8

    #     # Commit to the polynomial in lagrange basis
    #     C = ipa_utils.pedersen_commit(poly_eval)

    #     prover_transcript = Transcript(MODULUS, b"test")

    #     for input_point in range(256):

    #         output_point, proof = ipa_utils.evaluate_and_compute_ipa_proof(
    #             prover_transcript, C, poly_eval, input_point)
    #         # All points in the domain will produce an output point of 0, in the barycentric formula it is undefined
    #         self.assertEqual(output_point, int(0))

    def test_basic_ipa_proof(self):
        """
            Test a simple IPA proof
        """
        # Polynomial in lagrange basis
        poly_eval = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]*8

        # Commit to the polynomial in lagrange basis
        C = ipa_utils.pedersen_commit(poly_eval)
        self.assertEqual(
            "637bf70491d8a87a5a15a004cfbed28ae94f01bdaa801af034a81e63e0fa7db9", C.serialize().hex())

        prover_transcript = Transcript(MODULUS, b"test")

        # create a opening proof for a point outside of the domain
        input_point = 2101
        output_point, proof = ipa_utils.evaluate_and_compute_ipa_proof(
            prover_transcript, C, poly_eval, input_point)

        # Lets check the state of the transcript by squeezing out another challenge
        p_challenge = prover_transcript.challenge_scalar(b"state")

        self.assertEqual(
            "50d7f61175ffcfefc0dd603943ec8da7568608564d509cd0d1fa71cc48dc3515", p_challenge.to_bytes(32, "little").hex())

        verifier_transcript = Transcript(MODULUS, b"test")

        ok = ipa_utils.check_ipa_proof(
            verifier_transcript, C, input_point, output_point, proof)

    def test_basic_multi_proof(self):
        """
            Test a simple multipoint proof
        """
        # Polynomials in lagrange basis
        poly_eval_a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                       17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]*8
        poly_eval_b = [32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20,
                       19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]*8

        C_a = ipa_utils.pedersen_commit(poly_eval_a)
        C_b = ipa_utils.pedersen_commit(poly_eval_b)
        zs = [0, 0]
        ys = [1, 32]
        fs = [poly_eval_a, poly_eval_b]
        Cs = [C_a, C_b]

        prover_transcript = Transcript(MODULUS, b"test")
        proof = make_ipa_multiproof(prover_transcript,
                                    Cs, fs, zs, ys, False)

        # Lets check the state of the transcript by squeezing out another challenge
        p_challenge = prover_transcript.challenge_scalar(b"state")

        self.assertEqual(
            "f9c48313d1af5e069386805b966ce53a3d95794b82da3aac6d68fd629062a31c", p_challenge.to_bytes(32, "little").hex())

        verifier_transcript = Transcript(MODULUS, b"test")
        ok = check_ipa_multiproof(
            verifier_transcript, Cs, zs, ys, proof, False)

        self.assertTrue(ok)

        v_challenge = verifier_transcript.challenge_scalar(b"state")
        self.assertEqual(v_challenge, p_challenge)


if __name__ == '__main__':
    unittest.main()
