#!/usr/bin/env python

import argparse
import json
import logging
import pathlib
import sys
from typing import List, Dict

_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(
    logging.Formatter('%(asctime)s: %(levelname)8s: %(message)s'))
_handler.setLevel(logging.INFO)

_logger = logging.Logger(__name__)
_logger.addHandler(_handler)


def find_patterns(file: pathlib.Path, best_only: bool) -> List[Dict]:
    """Parse a raw_data.json file and search it for flip-generating patterns.

    :param file: Path to a file to search for patterns.
    :param best_only: Whether or not to discard all but the best-performing
        pattern.
    :return: If best_only is True, the best-performing pattern (i.e. causing the
        most flips). Otherwise, all patterns causing flips.
    """
    # Recover the DIMM ID. This assumes a typical filename structure: the text
    # preceding the first dot should be DIMM_XXX where XXX is the ID.
    dimm = file.name[:file.name.find('.')]

    with open(file, 'r') as f:
        raw_patterns = f.read()

    patterns = json.loads(raw_patterns)
    _logger.info('[%s] parsed %d patterns' % (dimm, len(patterns)))

    unique_patterns = set()
    good_patterns = []
    best_pattern = None
    best_score = 0

    for pattern in patterns:
        for mapping in pattern['address_mappings']:
            flips = mapping['bit_flips']
            if not flips:
                continue

            unique_patterns.add(pattern['id'])
            good_patterns.append(pattern)

            score = 0
            for flip in flips:
                # More than one flip can occur in a word (and has been observed
                # to occur), so we compute the Hamming weight for the flip
                # bitmask. Probably not the most efficient implementation, but
                # performance seems OK.
                score += bin(flip['bitmask']).count('1')

            _logger.debug(
                '[%s] pattern/mapping %s/%s resulted in %d flips in %d words' % (
                    dimm, pattern['id'], mapping['id'], score, len(flips)))

            if score > best_score:
                best_score = score
                best_pattern = pattern

    if not good_patterns:
        _logger.warning(
            '[%s] file did not contain any flip-generating patterns' % dimm)
        return []

    _logger.info(
        '[%s] found %d unique patterns resulting in flips' % (
            dimm, len(unique_patterns)))
    if best_only:
        _logger.info(
            '[%s] best pattern (%s) resulted in %d flips' % (
                dimm, best_pattern['id'], best_score))

        # By this point, we know that good_patterns is not empty, i.e. there is
        # at least one pattern that caused some bit to flip. Hence, there must
        # also be a best pattern, and best_pattern is not None.
        return [best_pattern]
    else:
        return good_patterns


def run() -> None:
    parser = argparse.ArgumentParser(
        description='Merge raw_data.json files produced by Blacksmith by '
                    'selecting either all flip-generating patterns or only the '
                    'best-performing patterns')
    parser.add_argument('files', metavar='FILE', nargs='+',
                        help='raw_data.json FILEs produced by Blacksmith to '
                             'select patterns from')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='write output to FILE instead of stdout')
    parser.add_argument('--best-only', action='store_true',
                        help='discard all but the best-performing pattern for '
                             'each input file')
    args = parser.parse_args()

    # Check that the provided files exist
    paths = [pathlib.Path(file) for file in args.files]
    for path in list(paths):
        if not path.exists():
            _logger.warning(
                'file does not exist and will be skipped: %s' % path)
            paths.remove(path)

    _logger.info('scanning for flips in %d files/runs' % len(paths))

    best_patterns = []
    for path in paths:
        pattern = find_patterns(path, args.best_only)
        if pattern:
            best_patterns.extend(pattern)

    _logger.info(
        'selected %d patterns from %d runs' % (len(best_patterns), len(paths)))

    output = json.dumps(best_patterns)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)

    pattern_ids = [pattern['id'] for pattern in best_patterns]
    _logger.info('comma-separated list of selected pattern IDs: %s' % ','.join(
        pattern_ids))


if __name__ == '__main__':
    run()
