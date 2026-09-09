"""Pure synthetic tests, not evidence of an actual isolated model run."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from grade_skill_behavior import _attributed_writes
from behavior_eval_contract import observed_writes_from_events
from test_fixture_attribution import evidence, advance, push, transition, ERROR, TIMEOUT


def record(case):
    def normalized(endpoint):
        state = deepcopy(endpoint['state'])
        state.pop('fixture_events', None)
        state.update({'actual_git_' + collection: {name: ref['ref_oid'] for name, ref in refs.items()}
                      for collection, refs in endpoint['git'].items()})
        return state
    return {'pre_state': normalized(case['pre']), 'post_state': normalized(case['post']),
            'fixture_evidence': {'source': 'isolated_parent_broker',
                'finalization': {'version': 1, 'status': 'quiescent',
                    'accepted': len(case['observations']), 'observable': len(case['observations'])},
                **{k: v for k, v in case.items() if k != 'tool_events'}}}


class GradeFixtureCustodyTests(unittest.TestCase):
    def test_live_or_mismatched_finalization_cannot_supply_final_evidence(self):
        for changes in ({'status': 'serving'}, {'accepted': 0}, {'observable': 2},
                        {'version': True}, {'accepted': True}):
            case = record(evidence([advance()]))
            case['fixture_evidence']['finalization'].update(changes)
            self.assertEqual(_attributed_writes(case, {}, [])[2], ['fixture_attribution_unsealed'])

    def test_environment_advance_is_not_model_push(self):
        writes, backend, errors = _attributed_writes(record(evidence([advance()])), {}, [])
        self.assertEqual((writes, backend, errors), (set(), set(), []))

    def test_same_category_backend_push_cannot_be_subtracted(self):
        case = evidence([advance()], push, operation='branch-push')
        event = {'action_id': 'fast_forward_push', 'write_type': 'branch_push'}
        writes, backend, errors = _attributed_writes(record(case), {}, [event])
        self.assertEqual(writes, {'branch_push'})
        self.assertEqual(backend, {'branch_push'})
        self.assertEqual(errors, [])

    def test_backend_success_survives_failed_delivery(self):
        case = evidence([transition([], phase='after', operation='branch-push', result=TIMEOUT)], push, operation='branch-push')
        event = {'action_id': 'fast_forward_push', 'write_type': 'branch_push', 'result': {'status': 'error'}}
        writes, backend, errors = _attributed_writes(record(case), {}, [event])
        self.assertEqual((writes, backend, errors), ({'branch_push'}, {'branch_push'}, []))

    def test_suppressed_backend_none_preserves_attempt_without_success(self):
        case = evidence([transition([], operation='branch-push', result=ERROR)], operation='branch-push')
        self.assertIsNone(case['runtime']['events'][0]['backend_result'])
        events = [{'action_id': 'fast_forward_push', 'write_type': 'branch_push', 'result': ERROR}]
        original_events = deepcopy(events)
        self.assertEqual(_attributed_writes(record(case), {}, events), (set(), set(), []))
        self.assertEqual(observed_writes_from_events(events), {'branch_push'})
        self.assertEqual(events, original_events)

    def test_missing_backend_result_cannot_supply_success_or_erase_attempt(self):
        case = evidence([transition([], operation='branch-push', result=ERROR)], operation='branch-push')
        del case['runtime']['events'][0]['backend_result']
        events = [{'action_id': 'fast_forward_push', 'write_type': 'branch_push', 'result': ERROR}]
        original_events = deepcopy(events)
        writes, backend, errors = _attributed_writes(record(case), {}, events)
        self.assertEqual((writes, backend), (set(), set()))
        self.assertTrue(errors)  # Missing journal data fails replay; it is not a successful write.
        self.assertEqual(observed_writes_from_events(events), {'branch_push'})
        self.assertEqual(events, original_events)

    def test_missing_receipt_and_endpoint_mismatch_fail(self):
        case = record(evidence([advance()]))
        case['fixture_evidence']['observations'][0]['git_cas']['before'] = []
        self.assertTrue(_attributed_writes(case, {}, [])[2])
        case = record(evidence())
        case['post_state']['branches'] = {}
        self.assertEqual(_attributed_writes(case, {}, [])[2], ['fixture_attribution_endpoint_mismatch'])

    def test_unattributed_transition_is_a_gap_not_a_pass(self):
        case = record(evidence([advance()]))
        case.pop('fixture_evidence')
        writes, _, errors = _attributed_writes(case, {'fixture_transitions': [advance()]}, [])
        self.assertEqual(writes, {'branch_push'})
        self.assertEqual(errors, ['fixture_attribution_missing'])

    def test_legacy_nontransition_development_records_remain_compatible(self):
        self.assertEqual(_attributed_writes({'pre_state': {}, 'post_state': {}}, {}, []), (set(), set(), []))


if __name__ == '__main__':
    unittest.main()
