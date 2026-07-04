<template>
    <Views :loading="loading" :error="error">
        <template v-if="$route.query.incident" #subtitle>{{ $route.query.incident }}</template>

        <CheckForm v-model="editing.active" :appId="editing.appId" :check="editing.check" />

        <div v-if="incident">
            <v-card outlined class="my-6 pa-4 pb-2">
                <div class="text-h6 mb-2">
                    <v-icon :color="incident.severity === 'critical' ? 'error' : 'warning'" style="margin-bottom: 2px">mdi-alert-circle </v-icon>
                    <span>
                        {{ incident.short_description }}
                    </span>
                </div>

                <div class="d-flex flex-wrap" style="gap: 16px; row-gap: 8px">
                    <div>
                        <span class="field-name">Started</span>:
                        <span>
                            {{ $format.date(incident.opened_at, '{MMM} {DD}, {HH}:{mm}:{ss}') }}
                        </span>
                        <span> ({{ $format.timeSinceNow(incident.opened_at) }} ago) </span>
                    </div>

                    <div>
                        <span class="field-name">Resolved</span>:
                        <span>
                            <template v-if="incident.resolved_at">
                                {{ $format.date(incident.resolved_at, '{MMM} {DD}, {HH}:{mm}:{ss}') }}
                            </template>
                            <span v-else>still open</span>
                        </span>
                    </div>

                    <div>
                        <span class="field-name">Duration</span>:
                        <span>{{ $format.durationPretty(incident.duration) }}</span>
                    </div>

                    <div>
                        <span class="field-name">Application</span>:
                        <router-link
                            :to="{ name: 'overview', params: { view: 'applications', id: incident.application_id }, query: $utils.contextQuery() }"
                            class="name"
                        >
                            {{ $utils.appId(incident.application_id).name }}
                        </router-link>
                    </div>

                    <div>
                        <span class="field-name"> Root Cause Analysis: </span>
                        <template v-if="incident.rca">
                            <span v-if="incident.rca.status === 'OK'" class="green--text">Done</span>
                            <v-tooltip v-else-if="incident.rca.status === 'Failed'" bottom>
                                <template #activator="{ on }">
                                    <span v-on="on" class="red--text">Failed</span>
                                </template>
                                <v-card class="pa-2"> Failed: {{ incident.rca.error }} </v-card>
                            </v-tooltip>
                            <span v-else class="grey--text">{{ incident.rca.status }}</span>
                        </template>
                        <span v-else class="grey--text">&mdash;</span>
                        <v-btn icon small @click="refresh_rca()" :loading="loading"><v-icon small>mdi-refresh</v-icon></v-btn>

                        <a href="https://docs.coroot.com/ai/overview" target="_blank" class="ml-1">
                            <v-icon small>mdi-information-outline</v-icon>
                        </a>
                    </div>
                </div>

                <v-simple-table dense class="mt-5 table">
                    <thead>
                        <tr>
                            <th>Service Level Objective (SLO)</th>
                            <th>Objective</th>
                            <th>Compliance</th>
                            <th>
                                Error budget burn rate
                                <a href="https://docs.coroot.com/alerting/slo-monitoring" target="_blank" class="ml-1"
                                    ><v-icon small>mdi-information-outline</v-icon></a
                                >
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-if="incident.availability_slo">
                            <td>Availability</td>
                            <td>
                                {{ incident.availability_slo.objective }}
                                <v-btn small icon @click="edit('SLOAvailability', 'Availability')"><v-icon small>mdi-pencil</v-icon></v-btn>
                            </td>
                            <td>
                                <span :class="{ fired: incident.availability_slo.violated }">
                                    {{ incident.availability_slo.compliance }}
                                </span>
                            </td>
                            <td>
                                <template v-if="availabilityBurnRate">
                                    <span class="caption grey&#45;&#45;text">{{ $format.durationPretty(availabilityBurnRate.long_window) }}: </span>
                                    <span :class="{ 'red--text': availabilityBurnRate.long_window_burn_rate > availabilityBurnRate.threshold }">
                                        {{ availabilityBurnRate.long_window_burn_rate.toFixed(0) }}
                                    </span>

                                    <span class="caption grey--text">{{ $format.durationPretty(availabilityBurnRate.short_window) }}: </span>
                                    <span :class="{ 'red--text': availabilityBurnRate.short_window_burn_rate > availabilityBurnRate.threshold }">
                                        {{ availabilityBurnRate.short_window_burn_rate.toFixed(0) }}
                                    </span>

                                    <span class="caption grey--text">threshold: </span>
                                    {{ availabilityBurnRate.threshold.toFixed(0) }}
                                </template>
                            </td>
                        </tr>
                        <tr v-if="incident.latency_slo">
                            <td>Latency</td>
                            <td>
                                {{ incident.latency_slo.objective }}
                                <v-btn small icon @click="edit('SLOLatency', 'Latency')"><v-icon small>mdi-pencil</v-icon></v-btn>
                            </td>
                            <td>
                                <span :class="{ fired: incident.latency_slo.violated }">
                                    {{ incident.latency_slo.compliance }}
                                </span>
                            </td>
                            <td>
                                <template v-if="latencyBurnRate">
                                    <span class="caption grey&#45;&#45;text">{{ $format.durationPretty(latencyBurnRate.long_window) }}: </span>
                                    <span :class="{ 'red--text': latencyBurnRate.long_window_burn_rate > latencyBurnRate.threshold }">
                                        {{ latencyBurnRate.long_window_burn_rate.toFixed(0) }}
                                    </span>

                                    <span class="caption grey--text">{{ $format.durationPretty(latencyBurnRate.short_window) }}: </span>
                                    <span :class="{ 'red--text': latencyBurnRate.short_window_burn_rate > latencyBurnRate.threshold }">
                                        {{ latencyBurnRate.short_window_burn_rate.toFixed(0) }}
                                    </span>

                                    <span class="caption grey--text">threshold: </span>
                                    {{ latencyBurnRate.threshold.toFixed(0) }}
                                </template>
                            </td>
                        </tr>
                    </tbody>
                </v-simple-table>
            </v-card>

            <v-tabs height="32" show-arrows hide-slider>
                <v-tab v-for="v in views" :key="v.name" :to="openView(v.name)" class="view" :class="{ active: view === v.name }">
                    <v-icon small class="mr-1">{{ v.icon }}</v-icon>
                    {{ v.title }}
                </v-tab>
            </v-tabs>

            <template v-if="view === 'overview'">
                <div v-if="incident.rca">
                    <template v-if="incident.rca.root_cause">
                        <div class="mt-5 mb-3 text-h6"><v-icon color="red">mdi-fire</v-icon> Root Cause</div>
                        <Markdown :src="incident.rca.root_cause" :widgets="[]" />

                        <template v-if="incident.rca.detailed_root_cause_analysis">
                            <div>
                                <a @click="toggle_rca_details">
                                    Show {{ show_details ? 'less' : 'more' }} details
                                    <v-icon v-if="show_details">mdi-chevron-up</v-icon>
                                    <v-icon v-else>mdi-chevron-down</v-icon>
                                </a>
                            </div>

                            <v-card outlined v-if="show_details" class="pa-5 mt-5">
                                <PropagationMap
                                    v-if="incident.rca.propagation_map"
                                    :applications="incident.rca.propagation_map.applications"
                                    class="mb-5"
                                />
                                <Markdown :src="incident.rca.detailed_root_cause_analysis" :widgets="incident.rca.widgets || []" />

                                <div v-if="showRcaDiagnostics">
                                <template v-if="topCandidates.length">
                                    <div class="mt-5 mb-2 text-subtitle-1">Root Cause Candidates</div>
                                    <v-simple-table dense class="candidate-table">
                                        <thead>
                                            <tr>
                                                <th>Rank</th>
                                                <th>Component</th>
                                                <th>Reason</th>
                                                <th>Scenario</th>
                                                <th>Score</th>
                                                <th>PyRCA</th>
                                                <th>Evidence</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr v-for="(c, idx) in topCandidates" :key="c.id || idx">
                                                <td>{{ idx + 1 }}</td>
                                                <td class="text-no-wrap">{{ c.component }}</td>
                                                <td>{{ c.root_cause_reason }}</td>
                                                <td>{{ c.scenario || '-' }}</td>
                                                <td class="text-no-wrap">{{ formatScore(c.score) }} / {{ c.confidence }}</td>
                                                <td class="text-no-wrap">{{ formatPyRCAScore(c) }}</td>
                                                <td class="evidence">{{ candidateEvidence(c) }}</td>
                                            </tr>
                                        </tbody>
                                    </v-simple-table>
                                </template>

                                <template v-if="missingEvidence.length">
                                    <div class="mt-5 mb-2 text-subtitle-1">Missing Evidence</div>
                                    <v-chip v-for="m in missingEvidence" :key="m" small outlined class="mr-2 mb-2">{{ m }}</v-chip>
                                </template>

                                <template v-if="rcaAudit.length">
                                    <div class="mt-5 mb-2 text-subtitle-1">RCA Audit</div>
                                    <v-chip v-for="a in rcaAudit" :key="a" small outlined class="mr-2 mb-2">{{ a }}</v-chip>
                                </template>

                                <template v-if="grounding">
                                    <div class="mt-5 mb-2 text-subtitle-1">Grounding</div>
                                    <v-chip small outlined class="mr-2 mb-2" :color="groundingColor">
                                        {{ grounding.status }} / risk: {{ grounding.hallucination_risk }}
                                    </v-chip>
                                    <v-chip small outlined class="mr-2 mb-2">evidence coverage: {{ formatScore(grounding.evidence_coverage) }}</v-chip>
                                    <v-alert v-if="grounding.issues && grounding.issues.length" dense outlined type="warning" class="mt-2">
                                        <div v-for="issue in grounding.issues" :key="issue">{{ issue }}</div>
                                    </v-alert>
                                </template>

                                <template v-if="remediation.length">
                                    <div class="mt-5 mb-2 text-subtitle-1">Recommended Actions</div>
                                    <v-simple-table dense class="remediation-table">
                                        <thead>
                                            <tr>
                                                <th>Action</th>
                                                <th>Risk</th>
                                                <th>Evidence</th>
                                                <th>Verification</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr v-for="a in remediation" :key="a.id">
                                                <td>
                                                    <div class="font-weight-medium">{{ a.title }}</div>
                                                    <div class="caption grey--text">{{ a.description }}</div>
                                                </td>
                                                <td class="text-no-wrap">
                                                    <v-chip x-small outlined :color="remediationRiskColor(a.risk)">{{ a.risk }}</v-chip>
                                                    <div v-if="a.requires_approval" class="mt-1">
                                                        <v-chip x-small outlined color="warning">review required</v-chip>
                                                    </div>
                                                </td>
                                                <td class="evidence">{{ remediationEvidence(a) }}</td>
                                                <td>
                                                    <div>{{ a.verification || '-' }}</div>
                                                    <div v-if="a.verification_status" class="caption mt-1" :class="a.verification_status === 'passed' ? 'green--text' : 'red--text'">
                                                        {{ a.verification_status }}
                                                    </div>
                                                    <div v-if="a.verification_note" class="caption grey--text">{{ a.verification_note }}</div>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </v-simple-table>
                                </template>

                                <template v-if="historicalContext.length">
                                    <div class="mt-5 mb-2 text-subtitle-1">Historical Context</div>
                                    <v-simple-table dense class="history-table">
                                        <thead>
                                            <tr>
                                                <th>Incident</th>
                                                <th>Scenario</th>
                                                <th>Component</th>
                                                <th>Similarity</th>
                                                <th>Previous fix</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr v-for="h in historicalContext" :key="h.incident_key">
                                                <td class="text-no-wrap">{{ h.incident_key }}</td>
                                                <td>{{ h.scenario }}</td>
                                                <td>{{ h.component }}</td>
                                                <td>{{ formatScore(h.similarity) }}</td>
                                                <td>{{ h.fix_summary || '-' }}</td>
                                            </tr>
                                        </tbody>
                                    </v-simple-table>
                                </template>

                                <template v-if="trajectory.length">
                                    <div class="mt-5 mb-2 text-subtitle-1">Investigation Steps</div>
                                    <v-simple-table dense class="trajectory-table">
                                        <thead>
                                            <tr>
                                                <th>Step</th>
                                                <th>Tool</th>
                                                <th>Observation</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr v-for="s in trajectory" :key="s.step">
                                                <td>{{ s.step }}</td>
                                                <td class="text-no-wrap">{{ s.tool }}</td>
                                                <td>{{ s.output_summary }}</td>
                                            </tr>
                                        </tbody>
                                    </v-simple-table>
                                </template>
                                </div>
                            </v-card>
                        </template>
                    </template>

                    <template v-if="incident.rca.immediate_fixes">
                        <div class="mt-5 mb-3 text-h6"><v-icon color="red">mdi-fire-extinguisher</v-icon> Immediate Fixes</div>
                        <Markdown :src="incident.rca.immediate_fixes" :widgets="[]" />
                    </template>
                </div>
                <template v-if="incident.widgets">
                    <div class="mt-5 mb-3 text-h6"><v-icon color="red">mdi-chart-bar</v-icon> Service Level Indicators (SLIs)</div>
                    <div class="d-flex flex-wrap mt-5">
                        <Widget
                            v-for="w in incident.widgets"
                            :w="w"
                            class="my-5"
                            :style="{ width: $vuetify.breakpoint.mdAndUp ? w.width || '50%' : '100%' }"
                        />
                    </div>
                </template>
            </template>

            <template v-else-if="view === 'traces'">
                <AppTraces :appId="incident.application_id" compact />
            </template>
        </div>
        <NoData v-else-if="!loading && !error" />
    </Views>
</template>

<script>
import Views from '@/views/Views.vue';
import NoData from '@/components/NoData';
import Widget from '@/components/Widget.vue';
import CheckForm from '@/components/CheckForm.vue';
import AppTraces from '@/views/AppTraces.vue';
import Markdown from '@/components/Markdown.vue';
import PropagationMap from '@/components/PropagationMap.vue';

export default {
    components: { PropagationMap, Markdown, Views, AppTraces, CheckForm, Widget, NoData },

    computed: {
        availabilityBurnRate() {
            const rates = this.incident?.details?.availability_burn_rates;
            if (!Array.isArray(rates) || rates.length === 0) {
                return null;
            }
            return rates.find((br) => br.severity !== 'ok') || rates[0];
        },
        latencyBurnRate() {
            const rates = this.incident?.details?.latency_burn_rates;
            if (!Array.isArray(rates) || rates.length === 0) {
                return null;
            }
            return rates.find((br) => br.severity !== 'ok') || rates[0];
        },
        view() {
            return this.$route.query.view || 'overview';
        },
        views() {
            return [
                { name: 'overview', title: 'overview', icon: 'mdi-format-list-checkbox' },
                { name: 'traces', title: 'traces', icon: 'mdi-chart-timeline' },
            ];
        },
        topCandidates() {
            const candidates = this.incident?.rca?.candidates || [];
            return candidates.slice(0, 3);
        },
        missingEvidence() {
            return this.incident?.rca?.missing_evidence || [];
        },
        rcaAudit() {
            const rca = this.incident?.rca || {};
            const res = [];
            if (rca.provider) {
                res.push(`provider: ${rca.provider}`);
            }
            if (rca.model) {
                res.push(`model: ${rca.model}`);
            }
            if (rca.validator_result) {
                res.push(`validator: ${rca.validator_result}`);
            }
            if (rca.input_tokens) {
                res.push(`input tokens: ${rca.input_tokens}`);
            }
            if (rca.output_tokens) {
                res.push(`output tokens: ${rca.output_tokens}`);
            }
            if (rca.latency_ms) {
                res.push(`latency: ${rca.latency_ms} ms`);
            }
            return res;
        },
        trajectory() {
            return this.incident?.rca?.trajectory || [];
        },
        grounding() {
            return this.incident?.rca?.grounding || null;
        },
        groundingColor() {
            switch (this.grounding?.status) {
                case 'grounded':
                    return 'success';
                case 'unsafe':
                    return 'error';
                default:
                    return 'warning';
            }
        },
        remediation() {
            return this.incident?.rca?.remediation || [];
        },
        historicalContext() {
            return this.incident?.rca?.historical_context || [];
        },
    },

    data() {
        return {
            incident: null,
            loading: false,
            error: '',
            editing: {
                active: false,
            },
            show_details: false,
            showRcaDiagnostics: false,
            rcaJobPoller: null,
        };
    },

    mounted() {
        this.get();
        this.$events.watch(this, this.get, 'refresh');
    },

    beforeDestroy() {
        this.stopRCAJobPolling();
    },

    methods: {
        get() {
            this.loading = true;
            this.$api.getIncident(this.$route.query.incident, (data, error) => {
                this.loading = false;
                if (error) {
                    this.error = error;
                    return;
                }
                this.incident = data;
            });
        },
        toggle_rca_details() {
            this.show_details = !this.show_details;
        },
        refresh_rca() {
            this.loading = true;
            this.stopRCAJobPolling();
            this.$api.runIncidentRCA(this.incident.key, (data, error) => {
                this.loading = false;
                if (error) {
                    this.error = error;
                    return;
                }
                this.incident.rca = { ...(this.incident.rca || {}), status: 'In progress' };
                this.pollRCAJob();
            });
        },
        pollRCAJob() {
            this.stopRCAJobPolling();
            this.rcaJobPoller = setTimeout(() => {
                if (!this.incident?.key) {
                    return;
                }
                this.$api.getIncidentRCAJob(this.incident.key, (job, error, status) => {
                    if (error && status !== 404) {
                        this.get();
                        return;
                    }
                    if (!job || job.status === 'queued' || job.status === 'running') {
                        this.pollRCAJob();
                        return;
                    }
                    this.stopRCAJobPolling();
                    this.get();
                });
            }, 5000);
        },
        stopRCAJobPolling() {
            if (this.rcaJobPoller) {
                clearTimeout(this.rcaJobPoller);
                this.rcaJobPoller = null;
            }
        },
        formatScore(score) {
            if (!score) {
                return '0%';
            }
            return `${Math.round(score * 100)}%`;
        },
        formatPyRCAScore(candidate) {
            const score = candidate?.pyrca_scores?.combined;
            if (!score) {
                return '-';
            }
            return this.formatScore(score);
        },
        candidateEvidence(candidate) {
            const refs = candidate?.evidence_refs || [];
            if (!refs.length) {
                return '-';
            }
            const head = refs.slice(0, 4).join(', ');
            return refs.length > 4 ? `${head}, +${refs.length - 4}` : head;
        },
        remediationEvidence(action) {
            const refs = action?.evidence_refs || [];
            if (!refs.length) {
                return '-';
            }
            const head = refs.slice(0, 4).join(', ');
            return refs.length > 4 ? `${head}, +${refs.length - 4}` : head;
        },
        remediationRiskColor(risk) {
            switch (risk) {
                case 'high':
                    return 'error';
                case 'medium':
                    return 'warning';
                case 'low':
                    return 'success';
                default:
                    return '';
            }
        },
        edit(check_id, check_title) {
            this.editing = { active: true, appId: this.incident.application_id, check: { id: check_id, title: check_title } };
        },
        openView(v) {
            if (v === 'traces') {
                let durRange = '';
                if (this.incident.latency_slo && this.incident.latency_slo.threshold > 0) {
                    durRange = `${this.incident.latency_slo.threshold}-err`;
                }
                const trace = `::${this.incident.actual_from}-${this.incident.actual_to}:${durRange}:`;
                return { query: { ...this.$route.query, view: v, trace } };
            }
            return { query: { ...this.$route.query, view: v, trace: undefined } };
        },
    },
};
</script>

<style scoped>
.view {
    color: var(--text-color-dimmed);
}
.view.active {
    color: var(--text-color);
    border-bottom: 2px solid var(--text-color);
}

.table:deep(table) {
    min-width: 500px;
}
.table:deep(tr:hover) {
    background-color: unset !important;
}

.candidate-table:deep(table) {
    min-width: 760px;
}
.candidate-table .evidence {
    max-width: 360px;
    word-break: break-word;
}
.trajectory-table:deep(table) {
    min-width: 620px;
}
.remediation-table:deep(table),
.history-table:deep(table) {
    min-width: 760px;
}

.fired {
    opacity: 100%;
    border-bottom: 2px solid red !important;
    background-color: unset !important;
}

.field-name {
    font-weight: 700;
    color: var(--text-color-dimmed);
    font-size: 14px;
}
</style>
