import { useState, useEffect, useMemo } from 'react';
import { Search, AlertTriangle, ChevronDown, ChevronUp, Shield, BookOpen, Layers, Sparkles, Briefcase, Target, Filter, RefreshCw } from 'lucide-react';
import { getThreatArticles, getThreatCorrelations, refreshThreatFeed } from '../api/threatIntel';
import StatCard from './StatCard';

const severityColors = {
  CRITICAL: 'bg-critical text-white',
  HIGH: 'bg-high text-white',
  MEDIUM: 'bg-medium text-white',
  LOW: 'bg-low text-white',
};

function formatDate(isoDate) {
  if (!isoDate) return 'Unknown';
  return new Date(isoDate).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

function formatDateTime(isoDate) {
  if (!isoDate) return 'Never';
  try {
    return new Date(isoDate).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return 'Unknown';
  }
}

export default function ThreatFeedPage({ onNavigate }) {
  const [threats, setThreats] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [publishedFilter, setPublishedFilter] = useState('ALL');
  const [cvssRange, setCvssRange] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [vendorFilter, setVendorFilter] = useState('');
  const [technologyFilter, setTechnologyFilter] = useState('');
  const [hasMitreFilter, setHasMitreFilter] = useState(false);
  const [assetMatchFilter, setAssetMatchFilter] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [expandedIds, setExpandedIds] = useState([]);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshMessage, setRefreshMessage] = useState(null);

  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (searchTerm.trim()) count += 1;
    if (vendorFilter.trim()) count += 1;
    if (technologyFilter.trim()) count += 1;
    if (publishedFilter !== 'ALL') count += 1;
    if (cvssRange !== 'ALL') count += 1;
    if (severityFilter !== 'ALL') count += 1;
    if (sourceFilter !== 'ALL') count += 1;
    if (hasMitreFilter) count += 1;
    if (assetMatchFilter) count += 1;
    return count;
  }, [searchTerm, vendorFilter, technologyFilter, publishedFilter, cvssRange, severityFilter, sourceFilter, hasMitreFilter, assetMatchFilter]);

  useEffect(() => {
    loadThreats();
  }, []);

  const loadThreats = async () => {
    try {
      setLoading(true);
      const [articlesResult, correlationsResult] = await Promise.allSettled([
        getThreatArticles(1, 50),
        getThreatCorrelations(1, 200),
      ]);

      if (articlesResult.status === 'fulfilled') {
        setThreats(articlesResult.value.articles || []);
      } else {
        throw articlesResult.reason || new Error('Failed to load threat articles');
      }

      setCorrelations(correlationsResult.status === 'fulfilled' ? correlationsResult.value.correlations || [] : []);
      setError(null);
    } catch (err) {
      console.error('Failed to load threat feed:', err);
      setError('Failed to load threat feed');
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    if (refreshing) return;
    setRefreshing(true);
    setRefreshMessage(null);
    try {
      const result = await refreshThreatFeed();
      if (result && result.status === 'already_running') {
        setRefreshMessage(result.message || 'A threat feed collection is already in progress.');
      } else if (result) {
        const newCount = result.total_inserted ?? result.inserted ?? 0;
        const dupCount = result.total_duplicates ?? result.duplicates ?? 0;
        setRefreshMessage(
          `Refresh complete: ${newCount} new article(s) added, ${dupCount} duplicate(s) skipped.`
        );
        if (result.last_updated) {
          setLastUpdated(result.last_updated);
        }
        // Reload the feed so the user immediately sees new articles.
        await loadThreats();
      }
    } catch (err) {
      console.error('Failed to refresh threat feed:', err);
      setRefreshMessage('Failed to refresh threat feed. Please try again.');
    } finally {
      setRefreshing(false);
    }
  };

  const visibleThreats = useMemo(() => {
    const normalizedSearch = searchTerm.trim().toLowerCase();
    const vendorSearch = vendorFilter.trim().toLowerCase();
    const technologySearch = technologyFilter.trim().toLowerCase();
    const publishedDays = {
      ALL: null,
      '7D': 7,
      '30D': 30,
      '90D': 90,
    }[publishedFilter];
    const cvssBounds = {
      ALL: null,
      '0-3': [0, 3],
      '3-7': [3, 7],
      '7-10': [7, 10],
    }[cvssRange];
    const now = Date.now();

    return threats
      .map((threat) => {
        const relatedCorrelations = correlations.filter((correlation) => correlation.article_id === threat.id);
        const assetMatches = relatedCorrelations.length;
        const relatedAssets = relatedCorrelations
          .map((correlation) => {
            const tech = correlation.asset_technology || correlation.asset_vendor || correlation.asset_version;
            return tech ? `${tech}` : null;
          })
          .filter(Boolean);

        const publishedAt = threat.published_date ? new Date(threat.published_date) : null;
        const publishedAgeDays = publishedAt ? Math.floor((now - publishedAt.getTime()) / 86400000) : null;

        return {
          ...threat,
          hasMitre: Array.isArray(threat.mitre_techniques) && threat.mitre_techniques.length > 0,
          assetMatches,
          relatedAssets,
          publishedAt,
          publishedAgeDays,
          isRecent: publishedAgeDays != null && publishedAgeDays <= 30,
        };
      })
      .filter((threat) => {
        if (severityFilter !== 'ALL' && threat.severity !== severityFilter) {
          return false;
        }

        if (sourceFilter !== 'ALL' && threat.source !== sourceFilter) {
          return false;
        }

        if (publishedDays != null && threat.publishedAgeDays != null) {
          if (threat.publishedAgeDays > publishedDays) {
            return false;
          }
        }

        if (hasMitreFilter && !threat.hasMitre) {
          return false;
        }

        if (assetMatchFilter && threat.assetMatches === 0) {
          return false;
        }

        if (vendorSearch && !(
          (threat.vendors || []).some((vendor) => vendor.toLowerCase().includes(vendorSearch)) ||
          (threat.products || []).some((product) => product.toLowerCase().includes(vendorSearch)) ||
          (threat.customer_relevance || '').toLowerCase().includes(vendorSearch) ||
          (threat.summary || '').toLowerCase().includes(vendorSearch)
        )) {
          return false;
        }

        if (technologySearch && !(
          (threat.affected_technologies || []).some((tech) => tech.toLowerCase().includes(technologySearch)) ||
          (threat.products || []).some((product) => product.toLowerCase().includes(technologySearch)) ||
          (threat.threat_type || '').toLowerCase().includes(technologySearch) ||
          (threat.summary || '').toLowerCase().includes(technologySearch)
        )) {
          return false;
        }

        if (cvssBounds && threat.cvss_score != null) {
          if (threat.cvss_score < cvssBounds[0] || threat.cvss_score > cvssBounds[1]) {
            return false;
          }
        }

        if (normalizedSearch) {
          const searchFields = [
            threat.title,
            threat.summary,
            threat.threat_type,
            threat.customer_relevance,
            (threat.vendors || []).join(' '),
            (threat.products || []).join(' '),
            (threat.affected_technologies || []).join(' '),
            (threat.mitre_techniques || []).join(' '),
            (threat.relatedAssets || []).join(' '),
          ];

          if (!searchFields.some((field) => field?.toString().toLowerCase().includes(normalizedSearch))) {
            return false;
          }
        }

        return true;
      });
  }, [threats, severityFilter, publishedFilter, cvssRange, searchTerm, vendorFilter, technologyFilter, sourceFilter, hasMitreFilter, assetMatchFilter, correlations]);

  const toggleExpanded = (id) => {
    setExpandedIds(prev =>
      prev.includes(id) ? prev.filter(item => item !== id) : [...prev, id]
    );
  };

  if (loading) {
    return (
      <div className="h-full bg-panel border border-hairline rounded-lg overflow-hidden">
        <div className="p-4 border-b border-hairline">
          <div className="h-5 w-48 rounded-full bg-void/80 animate-pulse" />
        </div>
        <div className="p-4 space-y-4">
          {[...Array(4)].map((_, idx) => (
            <div key={idx} className="rounded-3xl border border-hairline bg-void/80 p-5 animate-pulse h-40" />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-sm text-error font-body">{error}</p>
      </div>
    );
  }

  if (threats.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <p className="text-sm text-mist font-body mb-2">No threat events found</p>
        <p className="text-xs text-mist font-body">Run CTI ingestion to populate threat intelligence</p>
      </div>
    );
  }

  return (
    <div className="h-full bg-panel border border-hairline rounded-lg overflow-hidden flex flex-col">
      <div className="p-6 border-b border-hairline">
        <div className="mb-6">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-ink font-display">Threat Intelligence Feed</h2>
              <p className="text-xs text-mist font-body mt-1">AI-enriched SOC analyst CTI with attack context, customer impact, and mitigation guidance.</p>
            </div>
            <div className="flex flex-col items-start sm:items-end gap-2">
              <div className="flex items-center gap-3">
                <span className="text-xs text-mist font-body">
                  Last updated: <span className="text-ink font-semibold">{formatDateTime(lastUpdated)}</span>
                </span>
                <button
                  type="button"
                  onClick={handleRefresh}
                  disabled={refreshing}
                  className="inline-flex items-center gap-2 rounded-full bg-ember-bright px-4 py-2 text-xs font-bold uppercase text-void transition hover:bg-ember-dim disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                  {refreshing ? 'Refreshing...' : 'Refresh Threat Feed'}
                </button>
              </div>
              {refreshMessage && (
                <span className="text-xs text-mist font-body">{refreshMessage}</span>
              )}
            </div>
          </div>
        </div>

        {/* Stat Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="Total Threats"
            value={threats.length}
            icon={Target}
            colorClass="text-ink"
            accentColor="#3B82F6"
          />
          <StatCard
            label="Critical"
            value={threats.filter(t => t.severity === 'CRITICAL').length}
            icon={AlertTriangle}
            colorClass="text-ember-bright"
            accentColor="#E2483C"
          />
          <StatCard
            label="High"
            value={threats.filter(t => t.severity === 'HIGH').length}
            icon={Shield}
            colorClass="text-ink"
            accentColor="#D65A3C"
          />
          <StatCard
            label="Active Filters"
            value={activeFilterCount}
            icon={Filter}
            colorClass="text-ink"
            accentColor="#8B5CF6"
          />
        </div>
      </div>
      <div className="sticky top-0 z-10 bg-panel p-4 border-b border-hairline">
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="relative min-w-0 flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-mist" />
              <input
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search CVE, description, vendor, technology, MITRE..."
                className="w-full rounded-full border border-hairline bg-void py-3 pl-11 pr-4 text-sm text-ink placeholder:text-mist focus:border-ember-bright focus:outline-none"
              />
            </div>
            <button
              type="button"
              onClick={() => setFiltersOpen((open) => !open)}
              className="inline-flex items-center justify-center gap-2 rounded-full border border-hairline bg-void px-4 py-2 text-xs font-semibold uppercase text-mist transition hover:bg-panel/80"
            >
              Filters
              {activeFilterCount > 0 && (
                <span className="inline-flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-ember-bright px-2 text-[10px] font-bold text-void">
                  {activeFilterCount}
                </span>
              )}
            </button>
          </div>

          <div className={`overflow-hidden transition-all duration-300 ${filtersOpen ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'} `}>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-full border border-hairline bg-void px-4 py-2">
                <label className="block text-[11px] font-semibold uppercase tracking-[0.24em] text-mist mb-2">
                  Vendor
                </label>
                <input
                  value={vendorFilter}
                  onChange={(e) => setVendorFilter(e.target.value)}
                  placeholder="Vendor"
                  className="w-full bg-transparent text-sm text-ink placeholder:text-mist focus:outline-none"
                />
              </div>

              <div className="rounded-full border border-hairline bg-void px-4 py-2">
                <label className="block text-[11px] font-semibold uppercase tracking-[0.24em] text-mist mb-2">
                  Technology
                </label>
                <input
                  value={technologyFilter}
                  onChange={(e) => setTechnologyFilter(e.target.value)}
                  placeholder="Technology"
                  className="w-full bg-transparent text-sm text-ink placeholder:text-mist focus:outline-none"
                />
              </div>

              <div className="rounded-full border border-hairline bg-void p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-mist mb-2">
                  Published
                </div>
                <div className="flex flex-wrap gap-2">
                  {['7D', '30D', '90D'].map((option) => (
                    <button
                      key={option}
                      type="button"
                      onClick={() => setPublishedFilter(option)}
                      className={`rounded-full px-3 py-2 text-xs font-semibold transition ${
                        publishedFilter === option ? 'bg-ember-bright text-void' : 'bg-panel text-mist border border-hairline hover:bg-panel/80'
                      }`}
                    >
                      {option.toLowerCase()}
                    </button>
                  ))}
                </div>
              </div>

              <div className="rounded-full border border-hairline bg-void p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-mist mb-2">
                  CVSS
                </div>
                <div className="flex flex-wrap gap-2">
                  {['ALL', '0-3', '3-7', '7-10'].map((range) => (
                    <button
                      key={range}
                      type="button"
                      onClick={() => setCvssRange(range)}
                      className={`rounded-full px-3 py-2 text-xs font-semibold transition ${
                        cvssRange === range ? 'bg-ember-bright text-void' : 'bg-panel text-mist border border-hairline hover:bg-panel/80'
                      }`}
                    >
                      {range === 'ALL' ? 'All' : range}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-full border border-hairline bg-void p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-mist mb-2">
                  Source
                </div>
                <div className="flex flex-wrap gap-2">
                  {['ALL', 'The Hacker News', 'BleepingComputer'].map((source) => (
                    <button
                      key={source}
                      type="button"
                      onClick={() => setSourceFilter(source)}
                      className={`rounded-full px-3 py-2 text-xs font-semibold transition ${
                        sourceFilter === source ? 'bg-ember-bright text-void' : 'bg-panel text-mist border border-hairline hover:bg-panel/80'
                      }`}
                    >
                      {source === 'ALL' ? 'All' : source.replace('The ', '')}
                    </button>
                  ))}
                </div>
              </div>

              <div className="rounded-full border border-hairline bg-void p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-mist mb-2">
                  Severity
                </div>
                <div className="flex flex-wrap gap-2">
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((level) => (
                    <button
                      key={level}
                      type="button"
                      onClick={() => setSeverityFilter(level)}
                      className={`rounded-full px-3 py-2 text-xs font-semibold transition ${
                        severityFilter === level ? 'bg-ember-bright text-void' : 'bg-panel text-mist border border-hairline hover:bg-panel/80'
                      }`}
                    >
                      {level === 'ALL' ? 'All' : level}
                    </button>
                  ))}
                </div>
              </div>

              <div className="rounded-full border border-hairline bg-void p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-mist mb-2">
                  Flags
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => setHasMitreFilter((value) => !value)}
                    className={`rounded-full px-3 py-2 text-xs font-semibold transition ${
                      hasMitreFilter ? 'bg-ember-bright text-void' : 'bg-panel text-mist border border-hairline hover:bg-panel/80'
                    }`}
                  >
                    Has MITRE
                  </button>
                  <button
                    type="button"
                    onClick={() => setAssetMatchFilter((value) => !value)}
                    className={`rounded-full px-3 py-2 text-xs font-semibold transition ${
                      assetMatchFilter ? 'bg-ember-bright text-void' : 'bg-panel text-mist border border-hairline hover:bg-panel/80'
                    }`}
                  >
                    Asset match
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {visibleThreats.length === 0 ? (
          <div className="rounded-2xl border border-hairline bg-void p-6 text-center">
            <p className="text-sm text-mist font-body">No threats match the selected filters.</p>
          </div>
        ) : (
          visibleThreats.map((threat) => {
            const expanded = expandedIds.includes(threat.id);
            const severityClass = severityColors[threat.severity] || 'bg-mist text-ink';
            const hasAdditionalDetails = !!(
              threat.summary ||
              threat.attack_scenario ||
              threat.technical_impact ||
              threat.exploitation_context ||
              threat.affected_technologies?.length ||
              threat.customer_relevance ||
              threat.recommendation ||
              threat.mitre_techniques?.length ||
              threat.vendors?.length ||
              threat.products?.length ||
              threat.cves?.length ||
              threat.malware?.length ||
              threat.threat_actors?.length ||
              threat.relatedAssets?.length
            );

            return (
              <div
                key={threat.id}
                className="bg-panel border border-hairline rounded-3xl p-5 shadow-sm hover:shadow-md hover:border-hairline/80 transition-all duration-200"
              >
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-3 mb-3">
                      <span
                        className={`inline-flex items-center gap-2 ${severityClass} rounded-full px-3 py-1 text-xs font-semibold uppercase`}
                        title={
                          `${threat.severity || 'UNKNOWN'} · ${threat.assetMatches || 0} findings`
                        }
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                        {threat.severity || 'UNKNOWN'}
                        <span className="text-[10px] font-normal uppercase text-void/80">
                          · {threat.assetMatches || 0}
                        </span>
                      </span>
                      <span className="text-xs text-mist font-mono">{threat.id}</span>
                    </div>

                    <h3 className="text-base font-semibold text-ink leading-6">{threat.title}</h3>

                    <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3 text-xs text-mist font-body">
                      <div className="inline-flex items-center gap-2 rounded-2xl bg-void/70 px-3 py-2">
                        <Shield className="w-3.5 h-3.5 text-ember-bright" />
                        Type: {threat.threat_type || 'Unknown'}
                      </div>
                      <div className="inline-flex items-center gap-2 rounded-2xl bg-void/70 px-3 py-2">
                        <BookOpen className="w-3.5 h-3.5 text-mist" />
                        {formatDate(threat.published_date)}
                      </div>
                      <div className="inline-flex items-center gap-2 rounded-2xl bg-void/70 px-3 py-2">
                        <Layers className="w-3.5 h-3.5 text-mist" />
                        Source: {threat.source || 'Threat feed'}
                      </div>
                    </div>
                  </div>

                  {hasAdditionalDetails && (
                    <button
                      type="button"
                      onClick={() => toggleExpanded(threat.id)}
                      className="inline-flex items-center gap-2 rounded-full border border-hairline bg-void px-4 py-2 text-xs font-semibold text-mist transition hover:border-ember-dim hover:text-ink"
                    >
                      {expanded ? 'Collapse details' : 'View details'}
                      {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </div>

                {threat.summary && (
                  <div className="mt-4 rounded-2xl bg-void/70 p-4 text-sm leading-6 text-mist">
                    {threat.summary}
                  </div>
                )}

                {expanded && (
                  <div className="mt-5 space-y-5 border-t border-hairline pt-5">
                    {threat.attack_scenario && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <Layers className="w-3.5 h-3.5" />
                          Attack scenario
                        </div>
                        <p className="text-sm text-ink">{threat.attack_scenario}</p>
                      </section>
                    )}

                    {threat.technical_impact && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <Briefcase className="w-3.5 h-3.5" />
                          Technical impact
                        </div>
                        <p className="text-sm text-ink">{threat.technical_impact}</p>
                      </section>
                    )}

                    {threat.exploitation_context && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Exploitation context
                        </div>
                        <p className="text-sm text-ink">{threat.exploitation_context}</p>
                      </section>
                    )}

                    {threat.affected_technologies?.length > 0 && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <Shield className="w-3.5 h-3.5" />
                          Affected technologies
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {threat.affected_technologies.map((tech, idx) => (
                            <span key={idx} className="rounded-full bg-void/70 px-3 py-1 text-xs text-mist">{tech}</span>
                          ))}
                        </div>
                      </section>
                    )}

                    {threat.customer_relevance && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <Sparkles className="w-3.5 h-3.5" />
                          Customer relevance
                        </div>
                        <p className="text-sm text-ink">{threat.customer_relevance}</p>
                      </section>
                    )}

                    {threat.recommendation && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <BookOpen className="w-3.5 h-3.5" />
                          Recommended action
                        </div>
                        <p className="text-sm text-ink">{threat.recommendation}</p>
                      </section>
                    )}

                    {threat.vendors?.length > 0 && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <Layers className="w-3.5 h-3.5" />
                          Vendors
                        </div>
                        <p className="text-sm text-ink">{threat.vendors.join(', ')}</p>
                      </section>
                    )}

                    {threat.products?.length > 0 && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <BookOpen className="w-3.5 h-3.5" />
                          Products
                        </div>
                        <p className="text-sm text-ink">{threat.products.join(', ')}</p>
                      </section>
                    )}

                    {threat.cves?.length > 0 && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <Shield className="w-3.5 h-3.5" />
                          CVEs
                        </div>
                        <p className="text-sm text-ink">{threat.cves.join(', ')}</p>
                      </section>
                    )}

                    {threat.malware?.length > 0 && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Malware / tools
                        </div>
                        <p className="text-sm text-ink">{threat.malware.join(', ')}</p>
                      </section>
                    )}

                    {threat.threat_actors?.length > 0 && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <Sparkles className="w-3.5 h-3.5" />
                          Threat actors
                        </div>
                        <p className="text-sm text-ink">{threat.threat_actors.join(', ')}</p>
                      </section>
                    )}

                    {threat.relatedAssets?.length > 0 && (
                      <section className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-mist font-semibold">
                          <Layers className="w-3.5 h-3.5" />
                          Related assets
                        </div>
                        <ul className="list-disc list-inside text-sm text-ink space-y-1">
                          {threat.relatedAssets.map((asset, idx) => (
                            <li key={idx}>{asset}</li>
                          ))}
                        </ul>
                      </section>
                    )}

                    {!hasAdditionalDetails && (
                      <p className="text-sm text-mist">No additional threat details are available for this item.</p>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
