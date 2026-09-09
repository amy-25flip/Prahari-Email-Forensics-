import { useEffect, useRef, useState } from 'react'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { geoNaturalEarth1, geoPath } from 'd3-geo'
import { feature } from 'topojson-client'
import land from 'world-atlas/land-110m.json'

const projection = geoNaturalEarth1().fitExtent([[12, 8], [788, 355]], feature(land, land.objects.land))
const path = geoPath(projection)(feature(land, land.objects.land))

export default function RelayMap({ result }) {
  const [interactive, setInteractive] = useState(false)
  const [tileError, setTileError] = useState(false)
  const container = useRef(null)
  const positions = (result.geo || []).filter(g => Number.isFinite(g.lat) && Number.isFinite(g.lon))
  useEffect(() => {
    if (!interactive || !container.current) return
    setTileError(false)
    const map = L.map(container.current, {scrollWheelZoom:false}).setView([20, 0], 2)
    const layer = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution:'&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      maxZoom:18, referrerPolicy:'origin'
    }).addTo(map)
    layer.on('tileerror', () => setTileError(true))
    const points = (result.geo || []).filter(g => Number.isFinite(g.lat) && Number.isFinite(g.lon))
    const coordinates = []
    points.forEach(g => {
      coordinates.push([g.lat, g.lon])
      const popup = document.createElement('div')
      popup.textContent = `${g.ip} | ${g.city}, ${g.country} | ${g.isp} | approximate infrastructure location`
      L.circleMarker([g.lat,g.lon], {radius:7,color:'#a3e635',fillColor:'#a3e635',fillOpacity:.9}).addTo(map).bindPopup(popup)
    })
    // Only connect adjacent observed hops when both have coordinates.
    const ordered = result.hops.map(h => h.ips.map(ip => points.find(p => p.ip === ip)).find(Boolean))
    for(let i=1;i<ordered.length;i++) {
      if(ordered[i-1] && ordered[i]) L.polyline([[ordered[i-1].lat,ordered[i-1].lon],[ordered[i].lat,ordered[i].lon]], {color:'#a3e635',weight:2,dashArray:'5 7'}).addTo(map)
    }
    if(coordinates.length===1) map.setView(coordinates[0],5)
    else if(coordinates.length>1) map.fitBounds(coordinates,{padding:[40,40],maxZoom:8})
    const observer = new ResizeObserver(() => map.invalidateSize())
    observer.observe(container.current)
    return () => { observer.disconnect(); map.remove() }
  }, [interactive, result])
  return <section className="section">
    <div className="section-head"><h3>Infrastructure map</h3><label><input type="checkbox" checked={interactive} onChange={e=>setInteractive(e.target.checked)}/> Interactive tiles (OpenStreetMap)</label></div>
    {interactive ? <div ref={container} className="interactive-map" aria-label="Interactive relay map"/> : <div className="map"><svg viewBox="0 0 800 365" role="img" aria-label="Offline infrastructure map"><path d={path} fill="#242b34" stroke="#353e48" strokeWidth=".5"/>{positions.map(g=>{const [x,y]=projection([g.lon,g.lat]);return <circle key={g.ip} cx={x} cy={y} r="5" fill="#a3e635"><title>{g.ip}: {g.city}, {g.country}</title></circle>})}</svg></div>}
    {tileError && <p className="map-status warn">Some map tiles could not load. Coordinates remain available; switch off interactive tiles for the offline map.</p>}
    <p className="map-status">{positions.length ? `${positions.length} approximate infrastructure locations. Dotted lines indicate header order, not verified transmission.` : 'No coordinates returned. Reserved fixture IPs cannot be geolocated; real public IPs require external enrichment.'}</p>
    {interactive && <p className="map-status">Tile requests disclose your browser IP and map viewport to OpenStreetMap.</p>}
    {(result.geo || []).map(g => <div className="header-row" key={g.ip}><strong className="mono">{g.ip}</strong><span>{g.lat != null ? `${g.city}, ${g.country} | ${g.isp || 'ISP unavailable'}${g.asn ? ` | AS${g.asn}` : ''}` : g.error || 'Unavailable'}{g.observed_at && <small className="lookup-date">{g.source} · {new Date(g.observed_at*1000).toLocaleString()}{g.cached ? ' · cached' : ''}</small>}</span></div>)}
  </section>
}
