# Product Requirements Document: Agentic Pipe Meter

## 1. Overview
The **Agentic Pipe Meter** is a performance measurement utility designed for the Network Ghost Agent ecosystem. It automates high-precision latency and throughput testing between any two VMs in a cloud network to establish performance baselines and identify network degradation. It is designed to run as a standalone tool or as an integrated component of a forensic RCA workflow.

## 2. Objective
To provide a conversational, "human-in-the-loop" interface that orchestrates complex performance testing (qperf and iperf2), handles statistical normalization (P90), and manages baseline comparisons without requiring manual CLI configuration on multiple endpoints.

## 3. Tool Specifications

### 3.1 Measurement Engines
* **Latency:** `qperf` (TCP latency, 1024 message size).
* **Throughput:** `iperf2` (Multi-threaded TCP throughput, 8 parallel streams).

### 3.2 Execution Logic
* **Default Iterations:** 8 (User-configurable).
* **Statistical Target:** Calculate and report the **P90** (90th percentile) value to filter out transient network noise.
* **Mode:** Independent/Standalone (Current) with a roadmap for Integration into the Network Ghost Agent.

3.3 Statistical Hygiene

Warm-up: Run 1 unrecorded test pass before the 8 recorded iterations to prime the network path.

Stability Check (The Gap Rule): If the difference between the Maximum and Minimum result across iterations is greater than 50%, the tool must flag the result as "Unstable" in the console output to alert the investigator to inconsistent performance. This should also be reported in the results.json.

## 4. Functional Requirements

### 4.1 Input Parameters
* `source_vm_ip`: The IP of the Client VM.
* `dest_vm_ip`: The IP of the Server VM.
* `test_type`: [`latency`, `throughput`, `both`].
* `iterations`: Number of runs (Default: 8).
* `is_baseline`: Boolean. If true, marks result as the reference for this IP pair. Default should be False.
* `storage_account_name` & `container_name`: Azure destinations for JSON artifacts.

### 4.2 Pre-Flight & Installation Logic
1.  **Connectivity Check:** Query NSGs/ASGs to ensure ports **5001** (iperf) and **19765** (qperf) are open.
    * *If closed:* Generate the exact Cloud Network Azure specific commands to open them.
2.  **Dependency Check:** Verify if `qperf` and `iperf` are installed on both VMs, the source VM will act as the client and the destination VM will act as the server.
    * *If missing:* Prompt the user: *"Dependencies missing on [VM_IP]. Would you like me to install qperf/iperf2 via apt/yum? [Y/N]"*. 
    * *Action:* Proceed with installation only upon explicit "Yes".

### 4.3 Baseline & Comparison
* The tool must check the specified storage container for a previous `.json` marked as `baseline` for the current source/destination pair.
* If found, the tool must calculate the percentage delta between the current P90 and the Baseline P90.

## 5. Output Requirements

### 5.1 Console Output (User-Facing)
A clean, high-level summary suppressed of iteration-level data:
* **Test Status:** Success/Failure.
* **Latency (P90):** [Value] [Unit] (vs Baseline: [Delta]%).
* **Throughput (P90):** [Value] [Unit] (vs Baseline: [Delta]%).
* **Audit Trail:** Location of the saved JSON report.

### 5.2 JSON Artifact Schema
Stored in Azure Blob Storage:
```json
{
  "test_metadata": {
    "source_ip": "10.0.0.4",
    "destination_ip": "10.0.0.5",
    "is_baseline": true,
    "timestamp": "2026-03-02T14:00:00Z",
    "iterations": 8
  },
  "results": {
    "is_stable": true,
    "latency_p90": 124.5,
    "latency_min": 105,
    "latency_max": 140,
    "throughput_p90": 9.4,
    "throughput_min": 9.1,
    "throughput_max": 9.7,
    "units": { "latency": "us", "throughput": "Gbps" },
    "iteration_data": [ ... ]
  }
}

6. Security & Hygiene
Process Cleanup: Explicitly kill iperf -s and qperf server processes on the destination VM immediately after testing.

Gated Actions: Any write action (installing binaries, opening NSG ports) requires human-in-the-loop confirmation.

7. Work with multiple Cloud flavors

Though the initial target for this release is to make this tool work in Azure, it should be agnostic enough to work later on over different clouds like GCP, AWS and OCI.
