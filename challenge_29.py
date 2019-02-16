# Challenge 29 - Break a SHA-1 keyed MAC using length extension
#
# https://cryptopals.com/sets/4/challenges/29

import challenge_28


def generate_sha1_extension(orig, extension, length):
    digest = challenge_28.SHA1(b"A" * length)
    digest.h0 = int(orig[0:4], 16)
    digest.h1 = int(orig[4:8], 16)
    digest.h2 = int(orig[8:12], 16)
    digest.h3 = int(orig[12:16], 16)

    extension += digest._SHA1__calculate_padding(extension)

    for block in digest._SHA1__prepare_blocks(extension):
        digest._SHA1__process_block(block)

    return digest.hexdigest()
