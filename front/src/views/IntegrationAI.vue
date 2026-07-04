<template>
    <div style="max-width: 800px">
        <p>
            Coroot leverages Large Language Models (LLMs) to automatically generate clear, concise summaries of root causes, helping your team
            troubleshoot faster.
        </p>
        <v-alert v-if="readonly" color="primary" outlined text>
            AI settings are defined through the config and cannot be modified via the UI.
        </v-alert>
        <v-form v-if="form" v-model="valid" :disabled="disabled || readonly" ref="form">
            <div class="subtitle-1 mt-3">Model Provider</div>
            <v-radio-group v-model="form.provider" row dense class="mt-0" hide-details>
                <v-radio value="anthropic">
                    <template #label>
                        <img :src="`${$coroot.base_path}static/img/icons/anthropic.svg`" height="20" width="20" class="mr-1" />
                        Anthropic
                    </template>
                </v-radio>
                <v-radio value="openai">
                    <template #label>
                        <img :src="`${$coroot.base_path}static/img/icons/openai.svg`" height="20" width="20" class="mr-1" />
                        OpenAI
                    </template>
                </v-radio>
                <v-radio value="openai_compatible">
                    <template #label>
                        <v-icon class="mr-1">mdi-cog-outline</v-icon>
                        OpenAI-compatible API
                    </template>
                </v-radio>
                <v-radio value="">
                    <template #label>
                        <v-icon class="mr-1">mdi-trash-can-outline</v-icon>
                        Disabled
                    </template>
                </v-radio>
            </v-radio-group>

            <template v-if="form.provider === 'anthropic'">
                <div class="subtitle-1 mt-3">API Key</div>
                <div class="caption">
                    To integrate Coroot with Anthropic models, provide your Anthropic API key. You can get started by following the
                    <a href="https://docs.anthropic.com/en/api/getting-started" target="_blank">official Anthropic API documentation</a>.
                </div>
                <v-text-field
                    v-model="form.anthropic.api_key"
                    :rules="[$validators.notEmpty]"
                    outlined
                    dense
                    hide-details
                    single-line
                    type="password"
                />
            </template>

            <template v-if="form.provider === 'openai'">
                <div class="subtitle-1 mt-3">API Key</div>
                <div class="caption">
                    To integrate Coroot with OpenAI models, provide your OpenAI API key. Learn more about the API on the
                    <a href="https://openai.com/index/openai-api/" target="_blank">OpenAI API overview page</a>.
                </div>
                <v-text-field v-model="form.openai.api_key" :rules="[$validators.notEmpty]" outlined dense hide-details single-line type="password" />
            </template>

            <template v-if="form.provider === 'openai_compatible'">
                <div class="subtitle-1 mt-3">Base URL</div>
                <div class="caption">
                    The base URL for API requests to the model provider. Refer to their documentation for configuration details.
                </div>
                <v-text-field v-model="form.openai_compatible.base_url" :rules="[$validators.isUrl]" outlined dense hide-details single-line />

                <div class="subtitle-1 mt-3">API Key</div>
                <div class="caption">To integrate Coroot with an OpenAI-compatible model, provide your API key.</div>
                <v-text-field
                    v-model="form.openai_compatible.api_key"
                    :rules="[$validators.notEmpty]"
                    outlined
                    dense
                    hide-details
                    single-line
                    type="password"
                />

                <div class="subtitle-1 mt-3">Model</div>
                <div class="caption">The name or ID of the model to use. Refer to your provider’s documentation for valid values.</div>
                <v-text-field v-model="form.openai_compatible.model" :rules="[$validators.notEmpty]" outlined dense hide-details single-line />
            </template>

            <v-checkbox
                v-model="form.incidents_auto_rca"
                label="Investigate incidents automatically"
                dense
                hide-details
                class="mt-3"
            />

            <v-alert v-if="error" color="red" icon="mdi-alert-octagon-outline" outlined text class="mt-3">
                {{ error }}
            </v-alert>
            <v-alert v-if="message" color="green" outlined text class="mt-3">
                {{ message }}
            </v-alert>
            <div class="mt-3 d-flex" style="gap: 8px">
                <v-btn color="primary" @click="save" :disabled="disabled || readonly || !valid || !changed" :loading="loading">Save</v-btn>
                <v-btn @click="test" :disabled="disabled || !valid || form.provider === ''" :loading="testing">
                    <v-icon small left>mdi-connection</v-icon>
                    Test connection
                </v-btn>
            </div>
        </v-form>

        <v-divider class="my-5" />

        <div class="subtitle-1">RCA Benchmark</div>
        <div class="caption">
            Demo parity fixture contract for NetworkChaos, bad deployment, CronJob CPU starvation, and recommendation memory leak scenarios.
        </div>
        <div class="mt-3">
            <v-btn small outlined @click="loadBenchmark" :loading="benchmarkLoading">
                <v-icon small left>mdi-chart-box-outline</v-icon>
                Load benchmark
            </v-btn>
        </div>
        <template v-if="benchmark">
            <v-alert :color="benchmark.report.passed ? 'green' : 'orange'" outlined text class="mt-3">
                {{ benchmark.mode }}:
                {{ benchmark.report.passed ? 'passed' : 'needs attention' }}
                ({{ benchmark.report.total }} fixtures)
            </v-alert>
            <v-simple-table dense class="benchmark-table">
                <tbody>
                    <tr>
                        <td>Scenario Accuracy</td>
                        <td>{{ formatPercent(benchmark.report.scenario_accuracy) }}</td>
                    </tr>
                    <tr>
                        <td>Recall@1 / Recall@3</td>
                        <td>{{ formatPercent(benchmark.report.root_component_recall_1) }} / {{ formatPercent(benchmark.report.root_component_recall_3) }}</td>
                    </tr>
                    <tr>
                        <td>Reason Accuracy</td>
                        <td>{{ formatPercent(benchmark.report.root_reason_accuracy) }}</td>
                    </tr>
                    <tr>
                        <td>Grounding Rate</td>
                        <td>{{ formatPercent(benchmark.report.grounding_rate) }}</td>
                    </tr>
                    <tr>
                        <td>Unsafe Fixes</td>
                        <td>{{ benchmark.report.unsafe_fixes }}</td>
                    </tr>
                </tbody>
            </v-simple-table>
        </template>
    </div>
</template>

<script>
export default {
    components: {},

    data() {
        return {
            disabled: false,
            readonly: false,
            form: { provider: '', anthropic: {}, openai: {}, openai_compatible: {}, incidents_auto_rca: true },
            valid: false,
            loading: false,
            testing: false,
            benchmarkLoading: false,
            benchmark: null,
            error: '',
            message: '',
            saved: {},
        };
    },

    mounted() {
        this.get();
    },
    computed: {
        changed() {
            return JSON.stringify(this.form) !== JSON.stringify(this.saved);
        },
    },

    methods: {
        get() {
            this.loading = true;
            this.error = '';
            this.$api.ai(null, (data, error) => {
                this.loading = false;
                if (error) {
                    this.error = error;
                    return;
                }
                this.readonly = data.readonly;
                this.form.provider = data.provider;
                this.form.anthropic = data.anthropic || {};
                this.form.openai = data.openai || {};
                this.form.openai_compatible = data.openai_compatible || {};
                this.form.incidents_auto_rca = data.incidents_auto_rca !== false;
                this.saved = JSON.parse(JSON.stringify(this.form));
            });
        },
        save() {
            this.loading = true;
            this.error = '';
            this.message = '';
            const form = JSON.parse(JSON.stringify(this.form));
            this.$api.ai(form, (data, error) => {
                this.loading = false;
                if (error) {
                    this.error = error;
                    return;
                }
                this.message = 'Settings were successfully updated.';
                setTimeout(() => {
                    this.message = '';
                }, 3000);
                this.get();
            });
        },
        test() {
            this.testing = true;
            this.error = '';
            this.message = '';
            const form = JSON.parse(JSON.stringify(this.form));
            this.$api.aiTest(form, (data, error) => {
                this.testing = false;
                if (error) {
                    this.error = error;
                    return;
                }
                this.message = `Connection successful: ${data.provider} / ${data.model}.`;
                setTimeout(() => {
                    this.message = '';
                }, 3000);
            });
        },
        loadBenchmark() {
            this.benchmarkLoading = true;
            this.error = '';
            this.$api.getRCABenchmark((data, error) => {
                this.benchmarkLoading = false;
                if (error) {
                    this.error = error;
                    return;
                }
                this.benchmark = data;
            });
        },
        formatPercent(value) {
            return `${Math.round((value || 0) * 100)}%`;
        },
    },
};
</script>

<style scoped>
.benchmark-table:deep(table) {
    max-width: 520px;
}
</style>
