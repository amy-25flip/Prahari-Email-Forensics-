import axios from 'axios'

// Regression (Antigravity-flagged, real): most components used the raw
// global `axios` directly instead of this configured instance -- each one
// hardcoded its own '/api/...' prefix, several manually re-added the SAME
// 'X-Requested-With' header per call (easy to forget on a future POST, which
// the backend's boundary() middleware rejects with 403 without it), and NONE
// of them got this instance's 90s timeout -- axios's own default timeout is
// 0 (no timeout at all), so a hung request could wait forever. One shared
// instance, imported everywhere, makes all of that impossible to omit by
// accident rather than a convention every new call site has to remember.
export default axios.create({ baseURL: '/api', headers: { 'X-Requested-With': 'Email-Threat-Detection' }, timeout: 90000 })
