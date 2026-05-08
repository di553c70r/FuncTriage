FuncTriage

FuncTriage is an IDA Pro script designed to triage and prioritize functions in binary analysis using structural heuristics, cross-reference data, and API usage patterns.

It helps reverse engineers quickly identify high-value or suspicious functions such as:

unpacking / decoding routines
hooking and trampoline logic
memory injection behavior
thread manipulation and execution control
core orchestration logic in unknown binaries
🔍 Overview

FuncTriage scans all functions in a binary and assigns a heuristic score based on:

Control-flow complexity (basic blocks)
Cross-reference frequency (function usage)
API usage patterns
Zero-xref function heuristics (potential hidden logic)

It then groups functions into:

✔ Referenced Functions

Functions that are actively called by other parts of the binary.

⚠ Zero-Xref Functions (Heuristic)

Functions with no detected incoming references but strong behavioral indicators—often hidden or indirectly used logic.

⚙️ Features
Function scoring system based on structure + behavior
API extraction from direct and indirect calls
Cross-reference analysis for call frequency
Zero-xref detection for hidden logic paths
Clean, structured output in IDA console
Lightweight and fast execution
📊 Example Output
Referenced Functions

Functions ranked by importance score, including:

address
name
xref count
basic blocks
heuristic score
Zero-Xref Functions

Functions with no incoming references but strong structural or behavioral signals.

Add screenshots here to visually demonstrate output.

Example:

screenshots/referenced_functions.png  
screenshots/zero_xref_functions.png
🚀 Usage
Open a binary in IDA Pro
Load the script into the IDA Python environment
Run:
main()
Review the ranked function output in the console
📁 Output Fields
Field	Description
Address	Function entry address
Function	Function name
Xrefs	Number of incoming references
BBs	Basic block count (CFG complexity)
Score	Final heuristic importance score
APIs	Detected API calls
🧠 Use Cases

FuncTriage is useful for:

Malware analysis
Binary unpacking workflows
Reverse engineering unknown binaries
Identifying core logic quickly
Reducing manual function inspection time

## Real Usage

### Sample 1

![Sample 1]([screenshots/referenced_functions.png](https://github.com/di553c70r/FuncTriage/blob/main/sample1.png))

### Sample 2

![Sample 2]([screenshots/zero_xref_functions.png](https://github.com/di553c70r/FuncTriage/blob/main/sample2.png))
