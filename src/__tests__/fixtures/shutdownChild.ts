// Child process for gracefulShutdown.test.ts. Records N pending detections into a real SQLite
// file while the write-behind interval is set far beyond the test's duration, so the rows
// are still in memory when the stop signal arrives. Prints READY once they are buffered.
//
//   node --import tsx shutdownChild.ts <dbPath> <rows>
import { AdjudicationService } from '../../../server/services/adjudication.service.js';
import { installGracefulShutdown } from '../../../server/gracefulShutdown.js';

const [dbPath, rowsArg] = process.argv.slice(2);
const store = new AdjudicationService(dbPath);
installGracefulShutdown({
  flush: [{ name: 'adjudication pending queue', run: () => store.flushPending() }],
  log: () => {}
});

const rows = Number(rowsArg);
for (let i = 0; i < rows; i++) {
  store.recordPending({
    payload: `shutdown probe ${i}`,
    machineVerdict: 'ALLOW',
    machineScore: 0,
    machineFamily: 'CLEAN_TRAFFIC',
    machineSignatures: [],
    srcIp: '198.51.100.1'
  });
}

// Windows cannot deliver POSIX signals between processes (child.kill() there is
// TerminateProcess), so the parent asks over IPC and the signal is raised in-process.
process.on('message', (m: unknown) => {
  if (m === 'SIGTERM' || m === 'SIGINT') process.emit(m as NodeJS.Signals, m as NodeJS.Signals);
});

setInterval(() => {}, 60_000);
console.log('READY');
