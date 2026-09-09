"""Client-side fixture support for tests written before interactive audits.

This subclass lives ONLY in tests. It constructs miner commitments before intake
and answers published challenges. Production never constructs a client's opening.
Tests of deadlines, signatures, missing roots and restarts use the real class.
"""
from rhonet import ec
from rhonet.coordinator import Coordinator as RealCoordinator


def commit(spec, table, pk, dp):
    a, b, point = ec.derive_start(spec, pk, dp['t'])
    points = [[a, b, *point]] if point else []
    for step in range(1, dp['steps'] + 1):
        result = ec.replay(spec, table, a, b, point, 1)
        if result is None or result[2] is None:
            return dict(dp, checkpoint_root='00' * 32), []
        a, b, point = result
        if step % (1 << spec.v) == 0 or step == dp['steps']:
            points.append([a, b, *point])
    return dict(dp, checkpoint_root=ec.checkpoint_root(points)), points


class Coordinator(RealCoordinator):
    fixtures = {}

    def submit(self, pubkey, dps, *args, **kwargs):
        batch = []
        for dp in dps:
            if 'checkpoint_root' not in dp and all(k in dp for k in ('t','steps','x','y','a','b')):
                try:
                    if 0 < int(dp['steps']) <= ec.MAX_REPLAY_STEPS(self.spec):
                        dp, points = commit(self.spec, self.table, pubkey, dp)
                        self.fixtures[(self.spec.round_id, pubkey, dp['t'])] = points
                except (ValueError, TypeError, OverflowError):
                    pass
            batch.append(dp)
        return super().submit(pubkey, batch, *args, **kwargs)

    def _segment_verify(self, pubkey, dp, segment, opening):
        return ec.verify_segment(self.spec, self.table, pubkey, dp, segment, opening)

    def respond(self):
        for pk, in self.db.execute('SELECT pubkey FROM miners').fetchall():
            for target in self.audit_targets(pk):
                points = self.fixtures.get((self.spec.round_id, pk, target['t']))
                opening = ec.checkpoint_opening(points, target['segment']) if points else {}
                self.answer_audit(pk, target['epoch'], target['t'], opening)

    def close_epoch(self, final=False):
        # Repeat to catch up multiple epochs. Every iteration still publishes
        # and verifies the real challenge protocol before a payment can mature.
        for _ in range(100):
            super().close_epoch(final)
            if not self.db.execute('SELECT 1 FROM challenges WHERE result IS NULL').fetchone():
                return
            self.respond()
