"""Test runs never read or create the user's real pseudonym key.

The variable is process-wide, so every module instance (modular, generated
standalone, parity bundles) and every child process shares one temporary key.
"""
import atexit
import os
import shutil
import tempfile

if not os.environ.get('WINNETDIFF_PSEUDONYM_KEY_FILE'):
    _directory = tempfile.mkdtemp(prefix='winnetdiff-test-key-')
    os.environ['WINNETDIFF_PSEUDONYM_KEY_FILE'] = os.path.join(_directory, 'pseudonym.key')
    atexit.register(shutil.rmtree, _directory, True)
