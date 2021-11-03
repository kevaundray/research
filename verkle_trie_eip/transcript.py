import hashlib
from bandersnatch import Point
from random import randint


class Transcript():
    def __init__(self, MODULUS, label):
        self.MODULUS = MODULUS
        self.state = hashlib.sha256()
        self.state.update(label)

    def __bytes_to_field(self, bytes):
        return int.from_bytes(bytes, "little") % self.MODULUS

    def __append_bytes(self, message, label):
        if not isinstance(message, bytes):
            raise TypeError(
                'Expected bytes, but found: {}'.format(type(message)))

        self.state.update(label)
        self.state.update(message)

    # Scalars are represented with the `int` type
    def append_scalar(self, scalar, label):
        if not isinstance(scalar, int):
            raise TypeError(
                'Expected an integer type, but found: {}'.format(type(scalar)))

        # Although it should be the case, we do not assume that the integer
        # has been reduced modulo the prime order, this should not produce bugs when referencing this
        # implementation because in production one would use a Field class.
        reduced_scalar = scalar % self.MODULUS

        # Serialize the scalar in little endian
        bytes = reduced_scalar.to_bytes(32, "little")
        self.__append_bytes(bytes, label)

    def append_point(self, point, label):
        if not isinstance(point, Point):
            raise TypeError(
                'Expected an point type, but found: {}'.format(type(point)))

        bytes = point.serialize()
        self.__append_bytes(bytes, label)

    # Produce a challenge based on what has been seen so far in the transcript
    def challenge_scalar(self, label):
        self.domain_sep(label)

        # hash the transcript to produce the challenge
        hash = self.state.digest()
        challenge = self.__bytes_to_field(hash)

        # Clear the sha256 state
        # This step is not completely necessary
        # This is done so it frees memory
        self.state = hashlib.sha256()

        # Add the produced challenge into the new state
        # This is done for two reasons:
        # - It is now impossible for protocols using this
        # class to forget to add any challenges previously seen
        # - It is now secure to repeatedly call for challenges
        self.append_scalar(challenge, label)

        # Return the new challenge
        return challenge

    # domain_sep is used to:
    # - Separate between adding elements to the transcript and squeezing elements out
    # - Separate sub-protocols
    def domain_sep(self, label):
        self.state.update(label)
