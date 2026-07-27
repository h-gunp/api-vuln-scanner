import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";

let report;
try {
  execFileSync("npm", ["audit", "--json"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  console.log("Dependency audit passed: no vulnerabilities found.");
  process.exit(0);
} catch (error) {
  if (!error.stdout) throw error;
  report = JSON.parse(error.stdout.toString());
}

const allowedAdvisory = "https://github.com/advisories/GHSA-qwww-vcr4-c8h2";
const advisories = Object.values(report.vulnerabilities ?? {}).flatMap(
  (entry) => entry.via.filter((item) => typeof item === "object"),
);
const unexpected = advisories.filter((item) => item.url !== allowedAdvisory);
if (unexpected.length > 0) {
  console.error("Dependency audit found unapproved advisories:");
  for (const item of unexpected)
    console.error(`- ${item.severity}: ${item.title} (${item.url})`);
  process.exit(1);
}

const source = readdirSync("src", { recursive: true })
  .map(String)
  .filter((path) => /\.(ts|tsx)$/.test(path))
  .map((path) => `src/${path}`)
  .map((path) => readFileSync(path, "utf8"))
  .join("\n");
const rscApis = [
  "RSCHydratedRouter",
  "RSCStaticRouter",
  "routeRSCServerRequest",
  "unstable_RSC",
];
const usedRscApis = rscApis.filter((name) => source.includes(name));
if (usedRscApis.length > 0) {
  console.error(
    `The allowed React Router RSC advisory is applicable: ${usedRscApis.join(", ")}`,
  );
  process.exit(1);
}

console.log("Dependency audit passed with a scoped mitigation:");
console.log(`- ${allowedAdvisory} affects unstable RSC APIs only.`);
console.log("- This Vite SPA does not import or use React Router RSC APIs.");
console.log("- Any additional advisory will fail this check.");
