import { describe, it, expect } from 'vitest';
import { formatBytes, formatDate, formatDuration } from './format';

describe('formatBytes', () => {
  it('formats 0 bytes', () => {
    expect(formatBytes(0)).toBe('0 B');
  });

  it('formats bytes', () => {
    expect(formatBytes(512)).toBe('512 B');
  });

  it('formats kilobytes', () => {
    expect(formatBytes(1536)).toBe('1.5 KB');
  });

  it('formats megabytes', () => {
    expect(formatBytes(1024 * 1024 * 2)).toBe('2.0 MB');
  });

  it('formats gigabytes', () => {
    expect(formatBytes(1024 ** 3 * 3.5)).toBe('3.5 GB');
  });
});

describe('formatDate', () => {
  it('returns em dash for null', () => {
    expect(formatDate(null)).toBe('—');
  });

  it('formats ISO string', () => {
    const iso = '2024-01-15T10:30:00.000Z';
    expect(formatDate(iso)).toContain('2024');
  });
});

describe('formatDuration', () => {
  it('returns em dash for null', () => {
    expect(formatDuration(null)).toBe('—');
  });

  it('formats seconds', () => {
    expect(formatDuration(45)).toBe('45s');
  });

  it('formats minutes and seconds', () => {
    expect(formatDuration(125)).toBe('2m 5s');
  });

  it('formats hours and minutes', () => {
    expect(formatDuration(3665)).toBe('1h 1m');
  });
});
