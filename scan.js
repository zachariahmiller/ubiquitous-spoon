import { Octokit } from "@octokit/rest";
import fetch from "node-fetch";
import AdmZip from "adm-zip";
import fs from "fs";
import path from "path";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

const argv = yargs(hideBin(process.argv))
  .usage("Usage: $0 [type] [options]")
  .command(
    "$0 [type]",
    "Run the script with an optional type parameter",
    (yargs) => {
      yargs.positional("type", {
        describe: "Check for cves on all or delta (delta default)",
        type: "string",
        default: "delta",
      });
    },
  )
  .option("assignerShortName", {
    alias: "assigner",
    type: "string",
    description: "The CVE assigner's (CNA) short name to filter by",
    demandOption: false,
  })
  .option("product", {
    alias: "product",
    type: "string",
    description: "The product name to filter by",
    demandOption: false,
  })
  .help()
  .alias("help", "h")
  .parse();

const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN,
});

const REPO_OWNER = "CVEProject";
const REPO_NAME = "cvelistV5";
const TMP_DIR = path.join(process.cwd(), "tmp/gitlab_cve_analysis");
const OUTPUT_FILE = path.join(process.cwd(), "cve_details_output.json");
const TYPE = argv.type;
const sPath = TYPE === "all" ? "cves" : "deltaCves";


fs.mkdirSync(TMP_DIR, { recursive: true });
let allOutputs = [];

async function downloadLatestRelease() {
  const { data: releases } = await octokit.repos.listReleases({
    owner: REPO_OWNER,
    repo: REPO_NAME,
  });

  const latestRelease = releases[0];
  console.log(`Downloading release: ${latestRelease.tag_name}`);

  for (const asset of latestRelease.assets) {
    if (asset.name.includes(TYPE) && asset.name.endsWith(".zip")) {
      // Check for TYPE in asset name
      console.log(`Downloading asset: ${asset.name}`);
      const response = await fetch(asset.browser_download_url, {
        headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` },
      });
      const arrayBuffer = await response.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);
      const zip = new AdmZip(buffer);
      zip.extractAllTo(TMP_DIR, true);
      console.log(`Extracted ${asset.name} to ${TMP_DIR}`);
    }
    if (TYPE === "all") {
      const cveZip = new AdmZip(path.join(TMP_DIR, "cves.zip"));
      cveZip.extractAllTo(TMP_DIR, true);
    }
  }
}

function processFiles(directory) {
  fs.readdirSync(directory, { withFileTypes: true }).forEach((entry) => {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      processFiles(fullPath);
      // ignore the delta json files
    } else if (
      !entry.name.startsWith("delta") &&
      entry.name.endsWith(".json")
    ) {
      try {
        const rawData = fs.readFileSync(fullPath);
        if (!rawData.length) {
          console.error(`File ${fullPath} is empty.`);
          return;
        }
        const data = JSON.parse(rawData);
        console.debug(
          `Data read from file ${entry.name}: ${JSON.stringify(data.cveMetadata.cveId, null, 2)}`,
        );

        const matchesProduct = argv.product
          ? data.containers?.cna?.affected?.some(
              (a) =>
                a.product &&
                a.product.toLowerCase().includes(argv.product.toLowerCase()),
            )
          : true;
        const matchesAssigner = argv.assignerShortName
          ? data.cveMetadata?.assignerShortName
              .toLowerCase()
              .includes(argv.assignerShortName.toLowerCase())
          : true;

        if (matchesAssigner && matchesProduct) {
          const metrics = data.containers?.cna?.metrics?.[0];
          const baseSeverity =
            metrics?.cvssV3_1?.baseSeverity ||
            metrics?.cvssV3_0?.baseSeverity ||
            "Unknown Severity";
          const baseScore =
            metrics?.cvssV3_1?.baseScore ||
            metrics?.cvssV3_0?.baseScore ||
            "Unknown Score";
          const cvssV3_X =
            metrics?.cvssV3_1 || metrics?.cvssV3_0 || "Unknown cvssV3";

          const output = {
            "CVE ID": data.cveMetadata?.cveId ?? "Unknown CVE ID",
            "Assigner(CNA)":
              data.cveMetadata?.assignerShortName ?? "Unknown CNA",
            Description:
              data.containers?.cna?.descriptions?.[0]?.value ??
              "No description available",
            "Date Published": data.cveMetadata?.datePublished ?? "Unknown Date",
            Status: data.cveMetadata?.state ?? "Unknown Status",
            "Date Updated": data.cveMetadata?.dateUpdated ?? "Unknown Date",
            Product:
              data.containers?.cna?.affected?.[0]?.product ?? "Unknown Product",
            "Affected Versions":
              data.containers?.cna?.affected?.[0]?.versions
                ?.map((v) => `${v.version} (${v.status})`)
                .join(", ") ?? "No Versions Listed",
            "Base Severity": baseSeverity,
            "Base Score": baseScore,
            cvssV3_x: cvssV3_X,
          };

          allOutputs.push(output);
        }
      } catch (err) {
        console.error(
          `Error parsing JSON from file ${fullPath}: ${err.message}`,
        );
      }
    }
  });
}

async function main() {
  try {
    await downloadLatestRelease();
    processFiles(path.join(TMP_DIR, sPath));
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(allOutputs, null, 2));
    console.log("Final JSON output:");
    console.log(JSON.stringify(allOutputs, null, 2));
    console.log(`Output written to ${OUTPUT_FILE}`);
    console.log("Done!");
    console.log(`Assigner: ${argv.assignerShortName}`);
    console.log(`Product: ${argv.product}`);
  } catch (error) {
    console.error("Error occurred:", error);
  }
}

main();