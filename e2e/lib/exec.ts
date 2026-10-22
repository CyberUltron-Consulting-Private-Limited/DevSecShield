/**
 * Run a command-line tool without a shell.
 *
 * Arguments are an array and never pass through a shell, so file names and PDF text can contain any
 * character. The tools used here are poppler (pdfinfo, pdftotext, pdffonts, pdftoppm) and openssl: all
 * read-only on their inputs.
 */
import { execFileSync } from 'node:child_process';

export interface RunOptions {
  /** Kill the process after this many milliseconds (default 60 s). */
  timeoutMs?: number;
  /** Treat a non-zero exit status as a result instead of an error. */
  allowFailure?: boolean;
}

export interface RunResult {
  stdout: string;
  stderr: string;
  status: number;
}

export function run(cmd: string, args: string[], options: RunOptions = {}): RunResult {
  try {
    const stdout = execFileSync(cmd, args, {
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
      timeout: options.timeoutMs ?? 60_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { stdout, stderr: '', status: 0 };
  } catch (error) {
    const e = error as { status?: number; stdout?: string; stderr?: string; message: string };
    if (options.allowFailure && typeof e.status === 'number') {
      return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status };
    }
    throw new Error(`${cmd} ${args.join(' ')} failed: ${e.stderr || e.message}`);
  }
}
