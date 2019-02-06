
//
// Definition for threat-graph loader
//

// Import KSonnet library.
local k = import "ksonnet.beta.2/k.libsonnet";
local tnw = import "lib/tnw-common.libsonnet";

// Short-cuts to various objects in the KSonnet library.
local depl = k.extensions.v1beta1.deployment;
local container = depl.mixin.spec.template.spec.containersType;
local resources = container.resourcesType;
local env = container.envType;
local annotations = depl.mixin.spec.template.metadata.annotations;
local hpa = k.autoscaling.v1.horizontalPodAutoscaler;

local worker(config) = {

    local version = import "version.jsonnet",
    local pgm = "analytics-threat-graph",

    name: pgm,
    namespace: config.namespace,
    labels: {app:pgm, component:"analytics"},
    images: [config.containerBase + "/analytics-threat-graph:" + version],

    input: config.workers.queues.threat_graph.input,
    output: config.workers.queues.threat_graph.output,

    // Environment variables
    envs:: [

        // Hostname of Cherami
        env.new("AMQP_BROKER", "amqp://guest:guest@amqp:5672/"),

        // Gaffer REST API location.
        env.new("GAFFER_URL", "http://gaffer-threat:8080/rest/v1")

    ],

    // Container definition.
    containers:: [
        container.new(self.name, self.images[0]) +
            container.env(self.envs) +
            container.args([self.input] +
                           std.map(function(x) "output:" + x,
                                   self.output)) +
            container.mixin.resources.limits({
                memory: "128M", cpu: "0.55"
            }) +
            container.mixin.resources.requests({
                memory: "128M", cpu: "0.5"
            })
    ],

    // Deployment definition
    deployments:: [
        depl.new(self.name,
    config.workers.replicas.threat_graph.min,
                 self.containers,
                 self.labels) +
         depl.mixin.metadata.namespace($.namespace) +
  annotations({"prometheus.io/scrape": "true",
         "prometheus.io/port": "8080"})
    ],

    autoScalers:: [
		tnw.customHorizontalPodAutoscaler(
			$.name,
			$.labels,
			config.workers.replicas.threat_graph.min,
			config.workers.replicas.threat_graph.max,
			[
				{name: "rabbitmq_queue_messages_unacknowledged", target: 50},
				{name: "cpu", target: 20},
			],
			$.namespace
		)

  ],

  resources:
    if config.options.includeAnalytics then
      self.deployments + self.autoScalers
    else[],
};

[worker]
