"""Geometry for the relay-trace map, shared by the PDF and the UI.

The layout is computed here rather than inside either renderer so that the map
in the PDF and the map on screen are the same map: same projection, same hop
ordering, same decisions about what is drawn and what is refused.

Two deliberate choices:

*Equirectangular, and labelled as such.* ``x`` is a linear function of longitude
and ``y`` a linear function of latitude. It distorts area badly at high latitudes,
which is irrelevant here - the map exists to show that a message claiming to come
from an Indian bank entered the internet in Saint Petersburg, not to measure land.

*Unresolved hops are never plotted.* An IP with no location has ``lat = lon = 0``
in the schema default, and plotting that puts a marker in the Gulf of Guinea -
"null island", the most common false location in the industry. Those hops come
back in ``unlocated`` so the renderer can list them honestly as "hop 2, no
location available" instead of drawing a confident dot in the ocean.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

# Longitude/latitude bounds of the drawn frame. Antarctica is cropped: no mail
# server has ever been traced there and it wastes a third of the vertical
# space.
LON_MIN, LON_MAX = -180.0, 180.0
LAT_MIN, LAT_MAX = -60.0, 84.0

KIND_ORIGIN = "origin"
KIND_TRANSIT = "transit"
KIND_FINAL = "final"


def project(lat: float, lon: float) -> Dict[str, float]:
    """Equirectangular projection into the unit square, y measured downward."""
    x = (float(lon) - LON_MIN) / (LON_MAX - LON_MIN)
    y = (LAT_MAX - float(lat)) / (LAT_MAX - LAT_MIN)
    return {"x": min(max(x, 0.0), 1.0), "y": min(max(y, 0.0), 1.0)}


def graticule(lon_step: int = 30,
              lat_step: int = 20) -> Dict[str, List[Dict[str, Any]]]:
    """Meridian and parallel positions, so both renderers draw the same grid."""
    meridians = []
    lon = LON_MIN
    while lon <= LON_MAX:
        meridians.append({"lon": lon, "x": project(0.0, lon)["x"], "label": "%d%s" % (
            abs(int(lon)), "" if lon == 0 else ("E" if lon > 0 else "W"))})
        lon += lon_step
    parallels = []
    lat = -60
    while lat <= LAT_MAX:
        parallels.append({"lat": lat, "y": project(lat, 0.0)["y"], "label": "%d%s" % (
            abs(int(lat)), "" if lat == 0 else ("N" if lat > 0 else "S"))})
        lat += lat_step
    return {"meridians": meridians, "parallels": parallels}


def _nudge(markers: List[Dict[str, Any]], min_gap: float = 0.022) -> None:
    """Separate coincident markers.

    Several hops inside one country resolve to the same country centroid, which
    stacks the dots into one blob and makes a five-hop path look like a two-hop
    path. Later markers are pushed down slightly; the underlying coordinates are
    left untouched so the tabular data still reports the real values.
    """
    placed: List[Dict[str, float]] = []
    for m in markers:
        for _ in range(6):
            if all(abs(m["x"] -
                       p["x"]) > min_gap or abs(m["y"] -
                                                p["y"]) > min_gap for p in placed):
                break
            m["y"] = min(m["y"] + min_gap, 1.0)
            m["nudged"] = True
        placed.append({"x": m["x"], "y": m["y"]})


def layout(hops: Sequence[Any],
           origin_index: Optional[int] = None) -> Dict[str, Any]:
    """Turn relay hops into drawable markers, path segments and honest gaps.

    ``hops`` are :class:`~app.schemas.RelayHop` instances, earliest first.
    ``origin_index`` is the hop the analyser is willing to call the origin, so
    the map can mark it differently from the transit hops that follow it.
    """
    markers: List[Dict[str, Any]] = []
    unlocated: List[Dict[str, Any]] = []
    last = len(hops) - 1
    for i, hop in enumerate(hops):
        loc = getattr(hop, "location", None)
        place = ", ".join(
            p for p in (
                (getattr(
                    loc, "city", "") or ""), (getattr(
                        loc, "country", "") or "")) if p)
        row = {
            "index": getattr(hop, "index", i),
            "ip": getattr(hop, "ip", "") or "",
            "hostname": getattr(hop, "hostname", "") or "",
            "place": place,
            "country_code": getattr(loc, "country_code", "") or "",
            "asn": getattr(loc, "asn", "") or "",
            "isp": getattr(loc, "isp", "") or "",
            "source": getattr(loc, "source", "unavailable"),
            "anomalous": bool(getattr(hop, "is_anomalous", False)),
            "private": bool(getattr(hop, "is_private", False)),
        }
        if not (loc is not None and getattr(loc, "resolved", False)):
            row["reason"] = ("address is inside a private network, which has no public "
                             "location" if row["private"]
                             else "no location could be established for this address")
            unlocated.append(row)
            continue
        row.update(
            project(
                getattr(
                    loc, "lat", 0.0) or 0.0, getattr(
                    loc, "lon", 0.0) or 0.0))
        row["lat"] = getattr(loc, "lat", 0.0)
        row["lon"] = getattr(loc, "lon", 0.0)
        row["precision"] = "city" if getattr(
            loc, "city", "") else "country centroid"
        if origin_index is not None and row["index"] == origin_index:
            row["kind"] = KIND_ORIGIN
        elif i == last:
            row["kind"] = KIND_FINAL
        else:
            row["kind"] = KIND_TRANSIT
        markers.append(row)

    _nudge(markers)
    segments = [{"from": markers[i], "to": markers[i + 1]}
                for i in range(len(markers) - 1)]
    return {
        "projection": "equirectangular (linear in longitude and latitude)",
        "bounds": {
            "lon_min": LON_MIN,
            "lon_max": LON_MAX,
            "lat_min": LAT_MIN,
            "lat_max": LAT_MAX},
        "graticule": graticule(),
        "markers": markers,
        "segments": segments,
        "unlocated": unlocated,
        "drawable": bool(markers),
        "note": "%d of %d hops could be located; %d are listed without a position "
        "rather than plotted at a guessed one." %
        (len(markers),
         len(hops),
         len(unlocated)),
    }
