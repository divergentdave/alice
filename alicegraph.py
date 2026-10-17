#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ALICE Graph Generator:
Generates Mermaid and Graphviz (DOT) dependency graphs from ALICE traces and check results.
"""

import os
import sys
import argparse
import pickle
import shutil
import collections

sys.path.append(os.getenv("ALICE_HOME", os.path.dirname(os.path.abspath(__file__))))
from alice import Replayer, init_aliceconfig, aliceconfig
from alicedefaultfs import defaultfs
import alicedefaultexplorer

def generate_graph(traces_dir, checker_tool, output_prefix="alice_graph", threads=4):
    f = open(os.path.join(traces_dir, "config"), "r")
    config = pickle.load(f)
    f.close()

    scratchpad_dir = '/dev/shm/alice-graph-' + str(os.getpid())
    if not os.path.exists(scratchpad_dir):
        os.makedirs(scratchpad_dir)

    alice_config = {
        'strace_file_prefix': os.path.join(traces_dir, "strace.out"),
        'initial_snapshot': os.path.join(traces_dir, "initial_snapshot"),
        'base_path': config['workload_dir'],
        'starting_cwd': config['starting_wd'],
        'checker_tool': os.path.abspath(checker_tool),
        'debug_level': 0,
        'ignore_mmap': False,
        'scratchpad_dir': scratchpad_dir,
        'log_dir': None
    }

    init_aliceconfig(alice_config)
    replayer = Replayer(alice_config)
    replayer.set_fs(defaultfs('count', 1))

    mops = replayer.micro_ops
    mops_count = len(mops)

    for i in range(0, threads):
        t = alicedefaultexplorer.MultiThreadedChecker(i, None)
        t.setDaemon(True)
        t.start()

    # 1. Check ordering vulnerabilities
    ordering_vulns = []
    replayer.load(0)
    alicedefaultexplorer.MultiThreadedChecker.reset()

    for i in range(0, mops_count):
        if replayer.dops_len(i) == 0:
            continue
        for j in range(0, replayer.dops_len(i)):
            replayer.dops_omit((i, j))
        for j in range(i + 1, mops_count):
            if replayer.dops_len(j) == 0:
                continue
            replayer.dops_end_at((j, replayer.dops_len(j) - 1))
            if replayer.is_legal():
                d = os.path.join(scratchpad_dir, 'graph-dir-' + str(i) + '-' + str(j))
                replayer.construct_crashed_dir(d, d + '.input_stdout')
                alicedefaultexplorer.MultiThreadedChecker.check_later(d, (i, j), "omit_{}_{}".format(i, j))
        for j in range(0, replayer.dops_len(i)):
            replayer.dops_include((i, j))

    checker_outputs = alicedefaultexplorer.MultiThreadedChecker.wait_and_get_outputs()
    vuln_nodes = set()
    for i in range(0, mops_count):
        for j in range(i + 1, mops_count):
            if (i, j) in checker_outputs and checker_outputs[(i, j)] != 0:
                ordering_vulns.append((i, j))
                vuln_nodes.add(i)
                vuln_nodes.add(j)
                break

    # 2. Check atomicity vulnerabilities
    atomicity_vulns = set()
    for mode in (('count', 1), ('count', 3), ('aligned', 4096)):
        replayer.set_fs(defaultfs(*mode))
        alicedefaultexplorer.MultiThreadedChecker.reset()
        atomicity_explanations = dict()
        for i in range(0, mops_count):
            for j in range(0, replayer.dops_len(i) - 1):
                replayer.dops_end_at((i, j))
                if replayer.is_legal():
                    d = os.path.join(scratchpad_dir, 'atom-dir-' + mode[0] + '-' + str(i) + '-' + str(j))
                    replayer.construct_crashed_dir(d, d + '.input_stdout')
                    alicedefaultexplorer.MultiThreadedChecker.check_later(d, (mode, i, j), "atom_{}_{}".format(i, j))
                    atomicity_explanations[(mode, i, j)] = replayer.get_op(i).hidden_disk_ops[j].atomicity
        atom_outputs = alicedefaultexplorer.MultiThreadedChecker.wait_and_get_outputs()
        for (m, i, j), code in atom_outputs.items():
            if code != 0:
                atomicity_vulns.add(i)
                vuln_nodes.add(i)

    shutil.rmtree(scratchpad_dir, ignore_errors=True)

    def clean_label(text):
        return text.replace('"', '\\"').replace('\n', '\\n').replace('\'', '')

    # 3. Generate Mermaid diagram
    mmd_lines = [
        "```mermaid",
        "graph TD",
        "    classDef default fill:#f9f9f9,stroke:#666,stroke-width:1px;",
        "    classDef vuln fill:#ffcdd2,stroke:#d32f2f,stroke-width:2px;",
        "    classDef sync fill:#c8e6c9,stroke:#388e3c,stroke-width:2px;",
        "    classDef atom fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;"
    ]

    for i in range(mops_count):
        op_str = clean_label(str(mops[i]))
        is_sync = ('sync' in op_str or 'fdatasync' in op_str or 'fsync' in op_str)
        is_atom = (i in atomicity_vulns)
        is_vuln = (i in vuln_nodes)

        badge = ""
        if is_atom:
            badge = " [ATOM VULN]"
        if is_sync:
            badge = " [BARRIER]"

        mmd_lines.append("    Op{}[\"{}: {}{}\"]".format(i, i, op_str, badge))
        if is_sync:
            mmd_lines.append("    class Op{} sync;".format(i))
        elif is_atom:
            mmd_lines.append("    class Op{} atom;".format(i))
        elif is_vuln:
            mmd_lines.append("    class Op{} vuln;".format(i))

    # Sequential execution edges
    for i in range(mops_count - 1):
        # Check if there is an explicit vulnerability between these or later
        mmd_lines.append("    Op{} --> Op{}".format(i, i + 1))

    # Vulnerability edges
    for (src, dst) in ordering_vulns:
        mmd_lines.append("    Op{} -.->|MISSING FSYNC / ORDERING VULN| Op{}".format(src, dst))

    mmd_lines.append("```\n")
    mmd_content = "\n".join(mmd_lines)

    # 4. Generate Graphviz DOT diagram
    dot_lines = [
        "digraph ALICE_Dependency_Graph {",
        "    rankdir=TB;",
        "    node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\", fontsize=10];",
        "    edge [fontname=\"Helvetica\", fontsize=9];"
    ]

    for i in range(mops_count):
        op_str = clean_label(str(mops[i]))
        is_sync = ('sync' in op_str or 'fdatasync' in op_str or 'fsync' in op_str)
        is_atom = (i in atomicity_vulns)
        is_vuln = (i in vuln_nodes)

        fillcolor = "#f5f5f5"
        color = "#9e9e9e"
        if is_sync:
            fillcolor = "#e8f5e9"
            color = "#2e7d32"
        elif is_atom:
            fillcolor = "#fffde7"
            color = "#f57f17"
        elif is_vuln:
            fillcolor = "#ffebee"
            color = "#c62828"

        dot_lines.append("    n{} [label=\"{}: {}\", fillcolor=\"{}\", color=\"{}\", penwidth=2];".format(
            i, i, op_str, fillcolor, color
        ))

    for i in range(mops_count - 1):
        dot_lines.append("    n{} -> n{} [color=\"#9e9e9e\"];".format(i, i + 1))

    for (src, dst) in ordering_vulns:
        dot_lines.append("    n{} -> n{} [label=\"MISSING FSYNC!\", style=dashed, color=\"#d32f2f\", penwidth=2];".format(
            src, dst
        ))

    dot_lines.append("}\n")
    dot_content = "\n".join(dot_lines)

    # Write files
    mmd_file = output_prefix + ".mmd"
    dot_file = output_prefix + ".dot"
    with open(mmd_file, "w") as f_out:
        f_out.write(mmd_content)
    with open(dot_file, "w") as f_out:
        f_out.write(dot_content)

    print("Graph generated successfully:")
    print(" - Mermaid:  " + mmd_file)
    print(" - Graphviz: " + dot_file)
    print("\n" + mmd_content)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ALICE Dependency Graph Visualizer")
    parser.add_argument("--traces_dir", required=True, help="Directory containing strace files")
    parser.add_argument("--checker", required=True, help="Path to checker script")
    parser.add_argument("--output", default="alice_graph", help="Output file prefix")
    parser.add_argument("--threads", type=int, default=4, help="Number of checker threads")
    args = parser.parse_args()

    generate_graph(args.traces_dir, args.checker, args.output, args.threads)
