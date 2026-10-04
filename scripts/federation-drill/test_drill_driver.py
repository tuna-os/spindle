"""Check drill ordering with a fake kubectl; never access a cluster."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


MOCK = r'''#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
with open(os.environ['DRILL_MOCK_LOG'],'a') as log:
 log.write(json.dumps(args)+'\n')
if 'jsonpath={.data.expected-rooms}' in args:
 print('!room:reilly.asia',end='')
elif 'jsonpath={.data.expected-users}' in args:
 print('@drill-b1:reilly.asia,@drill-b2:reilly.asia',end='')
elif 'jsonpath={.spec.clusterIP}' in args:
 print('10.111.63.3',end='')
elif 'psql' in args:
 if 'json_agg' in args[-1]:
  print(json.dumps(['@drill-b1:reilly.asia','@drill-b2:reilly.asia']))
 elif 'SELECT count(*)' in args[-1]:
  print(os.environ.get('DRILL_MOCK_BACKLOG','0'))
elif '/state/passwords.json' in args:
 print(json.dumps({'drill-b1':'synthetic','drill-b2':'synthetic'}))
elif 'run' in args and 'drill-import-proof' in args:
 pod=json.loads(next(a.split('=',1)[1] for a in args if a.startswith('--overrides=')))
 spec=pod['spec']; container=spec['containers'][0]
 assert spec['automountServiceAccountToken'] is False
 assert spec['nodeSelector']=={'kubernetes.io/hostname':'ip-10-20-1-11'}
 assert spec['volumes'][0]['persistentVolumeClaim']['readOnly'] is True
 assert all(m['readOnly'] for m in container['volumeMounts'])
 assert container['command']==['python3','/verify/verify-import.py','/data/spindle/report.json',
                               '!room:reilly.asia','@drill-b1:reilly.asia,@drill-b2:reilly.asia']
 if os.environ.get('DRILL_MOCK_PROOF')=='fail':sys.exit(1)
 print(json.dumps({'passed':True}))
elif 'wait' in args and 'job/drill-b-import' in args:
 if os.environ.get('DRILL_MOCK_IMPORT')=='fail':sys.exit(1)
elif 'create' in args:
 print('{}')
elif 'apply' in args:
 sys.stdin.read()
'''


class DrillDriverTests(unittest.TestCase):
    def run_driver(self, command, **settings):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mock = root / "kubectl"
            mock.write_text(MOCK)
            mock.chmod(0o700)
            sleep = root / "sleep"
            sleep.write_text("#!/bin/sh\nexit 0\n")
            sleep.chmod(0o700)
            log = root / "calls.jsonl"
            env = os.environ.copy()
            env.update(PATH=str(root) + os.pathsep + env["PATH"],
                       KUBECONFIG=str(root / "synthetic-kubeconfig"), DRILL_MOCK_LOG=str(log),
                       **settings)
            result = subprocess.run(["bash", str(Path(__file__).with_name("drill.sh")), *command],
                                    env=env, capture_output=True, text=True, timeout=30)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            return result, calls

    def test_failed_proof_prevents_server_replacement(self):
        result, calls = self.run_driver(["up-b-spindle"], DRILL_MOCK_PROOF="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("deploy/drill-b" in call for call in calls))

    def test_passing_proof_precedes_server_replacement(self):
        result, calls = self.run_driver(["up-b-spindle"])
        self.assertEqual(result.returncode, 0, result.stderr)
        proof = next(i for i, call in enumerate(calls) if "run" in call and "drill-import-proof" in call)
        replace = next(i for i, call in enumerate(calls) if "delete" in call and "deploy/drill-b" in call)
        self.assertLess(proof, replace)

    def test_failed_import_does_not_run_the_proof(self):
        result, calls = self.run_driver(["import", "!room:reilly.asia",
                                        "@drill-b1:reilly.asia,@drill-b2:reilly.asia"],
                                       DRILL_MOCK_IMPORT="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any("run" in call and "drill-import-proof" in call for call in calls))

    def test_undrained_federation_prevents_sealing(self):
        result, calls = self.run_driver(["seal"], DRILL_MOCK_BACKLOG="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("seal refused", result.stderr)
        self.assertFalse(any("scale" in call for call in calls))
        self.assertFalse(any("CREATE DATABASE" in arg or "DROP DATABASE" in arg
                             for call in calls for arg in call))


if __name__ == "__main__":
    unittest.main()
