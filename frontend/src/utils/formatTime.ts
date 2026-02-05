/**
 * Format seconds into a human-readable time string.
 * Examples:
 *   - 45 -> "45s"
 *   - 90 -> "1m 30s"
 *   - 125.5 -> "2m 5s"
 */
export function formatTime(seconds: number): string {
  const totalSeconds = Math.round(seconds)
  if (totalSeconds < 60) {
    return `${totalSeconds}s`
  }
  const mins = Math.floor(totalSeconds / 60)
  const secs = totalSeconds % 60
  return `${mins}m ${secs}s`
}
