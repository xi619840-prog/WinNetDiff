"""Import the immutable independent suite with an explicit generated target."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest


def load_tests(loader, standard_tests, pattern):
    root = Path(__file__).resolve().parents[2]
    previous = os.environ.get('WINNETDIFF_SOURCE')
    os.environ['WINNETDIFF_SOURCE'] = str(root / 'windows_net_diffdiag.py')
    try:
        path = Path(__file__).with_name('test_winnetdiff_redteam_v2.py')
        spec = importlib.util.spec_from_file_location('independent_redteam_v2', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return loader.loadTestsFromModule(module)
    finally:
        if previous is None:
            os.environ.pop('WINNETDIFF_SOURCE', None)
        else:
            os.environ['WINNETDIFF_SOURCE'] = previous
