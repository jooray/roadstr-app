package app.roadstr.service.meshcore

import app.roadstr.core.geo.GeoMath
import app.roadstr.core.geo.GeoPoint
import app.roadstr.core.protocol.interop.BridgeSummaryCodec
import app.roadstr.core.protocol.interop.CompactCoordinates
import app.roadstr.core.protocol.nostr.RoadstrNostrEvents
import kotlin.math.roundToInt

/** The relays -> mesh rules of SPECIFICATION.md 4.3 (jooray/roadbeacon). Hard rules, not tuning. */
data class BridgeSummaryLimits(
    /** How long something heard on the radio counts as someone using the mesh there. */
    val demandWindowSeconds: Long = 2 * HOUR,
    /** Demand counts only this close to the bridge, and reports only this close to the demand. */
    val radiusMeters: Double = 25_000.0,
    /** One summary per area, after demand heard on the radio. */
    val areaIntervalSeconds: Long = 30 * MINUTE,
    /** One summary per area when a request asked for it. */
    val requestIntervalSeconds: Long = 10 * MINUTE,
    val summariesPerHour: Int = 6,
    /** 0.1 % of an hour. */
    val airtimeMillisPerHour: Double = 3_600.0,
    /** A report must still be shown this much longer to be worth airtime. */
    val minRemainingSeconds: Long = 5 * MINUTE,
    /** An entry already sent to an area counts as a repeat for this long. */
    val repeatWindowSeconds: Long = 2 * HOUR,
    /** Random wait after the demand, so the summary does not land on top of the frame that asked. */
    val holdMinMillis: Long = 2_000,
    val holdMaxMillis: Long = 10_000,
) {
    private companion object {
        const val MINUTE = 60L
        const val HOUR = 3_600L
    }
}

/** A report the bridge could put in a summary: verified, from the relays, not heard on the radio. */
data class SummaryCandidate(
    val id: String,
    val category: Int,
    val latitudeE6: Int,
    val longitudeE6: Int,
    val createdAt: Long,
    val shownUntil: Long,
    val stillThere: Int,
    val gone: Int,
)

/** Someone was heard on the radio near the bridge, or asked. */
data class SummaryDemand(
    val area: String,
    val point: GeoPoint,
    val at: Long,
    /** Hops the demand travelled, 255 when unknown or direct. */
    val hops: Int,
    val request: BridgeSummaryCodec.Request?,
)

data class SummarySelection(val demand: SummaryDemand, val entries: List<BridgeSummaryCodec.Entry>, val ids: List<String>)

/**
 * Decides when a bridge may send a summary and what goes in it. Pure: the clock is passed in, and
 * nothing here touches the radio or the relays. Not thread-safe; the bridge holds its lock.
 */
class BridgeSummaryPlanner(private val limits: BridgeSummaryLimits = BridgeSummaryLimits()) {
    private val frameDemand = LinkedHashMap<String, SummaryDemand>()
    private val requestDemand = LinkedHashMap<String, SummaryDemand>()
    private val lastServed = HashMap<String, Long>()
    private val sentToArea = HashMap<String, LinkedHashMap<String, Long>>()
    private val sends = ArrayDeque<Pair<Long, Double>>()

    /** A signed frame from another node was heard at [where]; null when it is not demand. */
    fun noteSignedFrame(where: GeoPoint, hops: Int?, bridge: GeoPoint?, now: Long): SummaryDemand? {
        if (bridge == null || GeoMath.distanceMeters(bridge, where) > limits.radiusMeters) return null
        val demand = SummaryDemand(areaOf(where), where, now, hops ?: UNKNOWN_HOPS, null)
        frameDemand[demand.area] = demand
        trim(now)
        return demand
    }

    /** A request frame; null when its point is too far from the bridge. */
    fun noteRequest(request: BridgeSummaryCodec.Request, hops: Int?, bridge: GeoPoint?, now: Long): SummaryDemand? {
        val where = GeoPoint(CompactCoordinates.degrees(request.latitudeE6), CompactCoordinates.degrees(request.longitudeE6))
        if (bridge == null || GeoMath.distanceMeters(bridge, where) > limits.radiusMeters) return null
        val demand = SummaryDemand(areaOf(where), where, now, hops ?: UNKNOWN_HOPS, request)
        requestDemand[demand.area] = demand
        trim(now)
        return demand
    }

    /** Another bridge's summary about [ref] was heard: that area is served. */
    fun noteSummaryHeard(ref: GeoPoint, now: Long) = markServed(areaOf(ref), now)

    /** Another bridge won the claim for [area]. */
    fun noteClaimLost(area: String, now: Long) = markServed(area, now)

    private fun markServed(area: String, now: Long) {
        lastServed[area] = maxOf(lastServed[area] ?: 0L, now)
        requestDemand.remove(area)
    }

    /** The demand a summary for [area] would answer now, or null when it is not due. */
    fun due(area: String, now: Long): SummaryDemand? {
        val served = lastServed[area]
        val request = requestDemand[area]?.takeIf { now - it.at <= limits.demandWindowSeconds }
        if (request != null && (served == null || now - served >= limits.requestIntervalSeconds)) return request
        val frame = frameDemand[area]?.takeIf { now - it.at <= limits.demandWindowSeconds } ?: return null
        return if (served == null || now - served >= limits.areaIntervalSeconds) frame else null
    }

    /** Up to five entries for [demand], newest first, with at least one the area has not had lately. */
    fun select(demand: SummaryDemand, candidates: List<SummaryCandidate>, now: Long): SummarySelection? {
        val pointLat = e6(demand.point.latitude)
        val pointLon = e6(demand.point.longitude)
        val request = demand.request
        val radius = request?.let { it.radiusKm * 1_000.0 }?.coerceAtMost(limits.radiusMeters) ?: limits.radiusMeters
        val sent = sentToArea[demand.area].orEmpty()
        val usable = candidates.filter { c ->
            c.shownUntil - now >= limits.minRemainingSeconds &&
                c.createdAt <= now &&
                (request == null || request.wants(c.category)) &&
                (request?.sinceSeconds == null || now - c.createdAt <= request.sinceSeconds) &&
                BridgeSummaryCodec.fits(pointLat, pointLon, c.latitudeE6, c.longitudeE6) &&
                GeoMath.distanceMeters(demand.point, pointOf(c)) <= radius
        }.distinctBy { it.id }
        val repeat = { c: SummaryCandidate -> (sent[c.id] ?: Long.MIN_VALUE) > now - limits.repeatWindowSeconds }
        val fresh = usable.filterNot(repeat).sortedByDescending { it.createdAt }
        if (fresh.isEmpty()) return null
        val chosen = (fresh + usable.filter(repeat).sortedByDescending { it.createdAt }).take(BridgeSummaryCodec.MAX_ENTRIES)
        val entries = chosen.map {
            BridgeSummaryCodec.Entry(
                latitudeE6 = it.latitudeE6,
                longitudeE6 = it.longitudeE6,
                category = it.category,
                ageSeconds = now - it.createdAt,
                remainingSeconds = it.shownUntil - now,
                stillThere = it.stillThere,
                gone = it.gone,
            )
        }
        return SummarySelection(demand, entries, chosen.map { it.id })
    }

    /** Whether one more transmission of [airtimeMillis] keeps the bridge inside its budget. */
    fun budgetAllows(airtimeMillis: Double, now: Long): Boolean {
        expireSends(now)
        return sends.size < limits.summariesPerHour &&
            sends.sumOf { it.second } + airtimeMillis <= limits.airtimeMillisPerHour
    }

    /** The radio accepted the summary. */
    fun recordSent(selection: SummarySelection, airtimeMillis: Double, now: Long) {
        val area = selection.demand.area
        lastServed[area] = now
        if (selection.demand.request != null) requestDemand.remove(area)
        val sent = sentToArea.getOrPut(area) { LinkedHashMap() }
        selection.ids.forEach { sent[it] = now }
        sends.addLast(now to airtimeMillis)
        trim(now)
    }

    fun holdMillis(random: java.util.Random): Long =
        limits.holdMinMillis + (random.nextDouble() * (limits.holdMaxMillis - limits.holdMinMillis)).toLong()

    private fun expireSends(now: Long) {
        while (sends.isNotEmpty() && now - sends.first().first >= HOUR) sends.removeFirst()
    }

    private fun trim(now: Long) {
        expireSends(now)
        val keep = maxOf(limits.demandWindowSeconds, limits.repeatWindowSeconds, limits.areaIntervalSeconds)
        frameDemand.values.removeAll { now - it.at > limits.demandWindowSeconds }
        requestDemand.values.removeAll { now - it.at > limits.demandWindowSeconds }
        lastServed.values.removeAll { now - it > keep }
        for (sent in sentToArea.values) sent.values.removeAll { now - it > limits.repeatWindowSeconds }
        sentToArea.values.removeAll { it.isEmpty() }
        while (frameDemand.size > MAX_AREAS) frameDemand.remove(frameDemand.keys.first())
        while (requestDemand.size > MAX_AREAS) requestDemand.remove(requestDemand.keys.first())
    }

    companion object {
        const val UNKNOWN_HOPS = 255
        private const val HOUR = 3_600L
        private const val MAX_AREAS = 64

        /** The geohash-4 cell (about 20 x 39 km) a summary area is named by. */
        fun areaOf(point: GeoPoint): String = RoadstrNostrEvents.geohash(point.latitude, point.longitude, 4)

        fun e6(degrees: Double): Int = (degrees * 1_000_000.0).roundToInt()

        private fun pointOf(c: SummaryCandidate) =
            GeoPoint(CompactCoordinates.degrees(c.latitudeE6), CompactCoordinates.degrees(c.longitudeE6))
    }
}
