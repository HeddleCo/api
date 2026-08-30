import {
  definePipeline,
  hostTargetEnvironment,
  sh,
} from "../dist/treadle-authoring.js";

/** Compact local-run pipeline. Host-exec v0 admits matching os/arch only. */
export default definePipeline({
  name: "local-host",
  defaults: { targetEnvironment: hostTargetEnvironment() },
  jobs: {
    fast: [
      sh("true-check", ["-c", "true"]),
      sh("echo-ok", ["-c", "echo ok"]),
    ],
    also: [
      sh("pwd-check", ["-c", "pwd"]),
    ],
  },
});
