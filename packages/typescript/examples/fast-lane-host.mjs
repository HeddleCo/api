import {
  definePipeline,
  hostTargetEnvironment,
  rust,
} from "../dist/treadle-authoring.js";

/** Compact rust-pack Fast Lane. Host-exec admits matching os/arch only. */
export default definePipeline({
  name: "fast-lane-host",
  defaults: { targetEnvironment: hostTargetEnvironment() },
  jobs: {
    fast: [
      rust.fmt(),
      rust.test([], { name: "test" }),
    ],
  },
});
