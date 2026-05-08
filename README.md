FuncTriage

FuncTriage is an IDA Pro script designed to triage and prioritize functions during binary analysis using structural heuristics, cross-reference analysis, and behavioral indicators.

It helps reverse engineers quickly surface high-value or suspicious routines such as:

Unpacking / decoding logic
Hooking and trampoline routines
Memory injection behavior
Thread manipulation and execution control
Core orchestration logic in unknown binaries
🔍 Overview

FuncTriage scans every function in a binary and assigns a heuristic score based on:

Control-flow complexity (basic block count)
Cross-reference frequency
API usage patterns
Zero-xref heuristics (potential hidden or indirectly invoked logic)

The script categorizes results into two major groups:

✔ Referenced Functions

Functions actively referenced or called throughout the binary.

⚠ Zero-Xref Functions (Heuristic)

Functions with no detected incoming references but strong structural or behavioral indicators that may suggest hidden, indirect, or dynamically resolved execution paths.

⚙️ Features
Heuristic-based function scoring
CFG complexity analysis
Cross-reference frequency analysis
API extraction from direct and indirect calls
Zero-xref function detection
Clean, structured console output
Lightweight and fast execution
Useful for malware triage and unknown binary analysis
📊 Output

FuncTriage ranks functions using multiple structural and behavioral signals.

Each entry includes:

Field	Description
Address	Function entry address
Function	Function name
Xrefs	Number of incoming references
BBs	Basic block count (CFG complexity)
Score	Final heuristic importance score
APIs	Detected API calls
🚀 Usage
Open a binary in IDA Pro
Load the script into the IDA Python environment
Run:
main()
Review the ranked analysis output in the IDA console
🧠 Use Cases

FuncTriage is useful for:

Malware analysis
Binary unpacking workflows
Reverse engineering unknown binaries
Identifying core execution logic
Prioritizing functions during manual analysis
Reducing reverse engineering time
🔥 Real Usage
Sample 1 — Referenced Functions
<p align="center"> <img src="https://github.com/di553c70r/FuncTriage/blob/main/sample1.png" width="1000"> </p>
Sample 2 — Zero-Xref Functions
<p align="center"> <img src="https://github.com/di553c70r/FuncTriage/blob/main/sample2.png" width="1000"> </p>
