export function FeedStatus({ feed }) {
  if (!feed) return <span className="feed-status">PhishTank feed unavailable</span>
  return <span className={`feed-status ${feed.status === 'fresh' ? 'good' : 'warn'}`} title={feed.detail}>
    PhishTank · {feed.status} · {feed.count.toLocaleString()} URLs
    {feed.fetched_at && <small>Fetched {new Date(feed.fetched_at * 1000).toLocaleString()}</small>}
  </span>
}

export function UrlReputation({ value }) {
  if (!value || typeof value !== 'object') return <p>Reputation not recorded for this saved analysis.</p>
  const labels = {listed: 'Listed in PhishTank', listed_stale: 'Listed in an older snapshot', not_listed: 'Not listed', unavailable: 'Feed unavailable', stale: 'Feed stale; no match'}
  return <div className="url-reputation">
    <strong className={value.status === 'listed' ? 'danger' : value.status === 'not_listed' ? '' : 'warn'}>{labels[value.status] || value.status}</strong>
    <small>{value.detail}</small>
    {value.record_id && <small>PhishTank record {value.record_id} · feed {value.feed_status}</small>}
    {value.fetched_at && <small>Snapshot fetched {new Date(value.fetched_at * 1000).toLocaleString()}</small>}
  </div>
}
