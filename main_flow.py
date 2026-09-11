"""
main_flow.py – Programmatic test harness for the SOC Investigation Flow.

Usage:
    export PYTHONPATH=/path/to/ibm-watsonx-orchestrate-adk/src:/path/to/ibm-watsonx-orchestrate-adk
    python3 main_flow.py
"""

import asyncio
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from flows.soc_investigation_flow import build_soc_investigation_flow


GENERATED_DIR = Path(__file__).resolve().parent / "generated"


async def main() -> None:
    """Compile, deploy, and invoke the SOC investigation flow."""
    GENERATED_DIR.mkdir(exist_ok=True)

    print("Compiling and deploying soc_investigation_flow …")
    flow_def = await build_soc_investigation_flow().compile_deploy()

    # Persist the compiled flow spec for inspection / version control
    spec_path = GENERATED_DIR / "soc_investigation_flow.json"
    flow_def.dump_spec(str(spec_path))
    print(f"Flow spec written to: {spec_path}")

    # -----------------------------------------------------------------------
    # Test case 1 – Normal traffic (safe external IP)
    # -----------------------------------------------------------------------
    print("\n[Test 1] Normal HTTP traffic")
    result_1 = await flow_def.invoke(
        {
            "duration": 8,
            "src_bytes": 181,
            "dst_bytes": 5450,
            "count": 8,
            "srv_count": 8,
            "source_ip": "203.0.113.42",
        },
        debug=True,
    )
    print("Result:", result_1)

    # -----------------------------------------------------------------------
    # Test case 2 – Potential DoS (high count / srv_count, zero bytes)
    # -----------------------------------------------------------------------
    print("\n[Test 2] Potential DoS pattern")
    result_2 = await flow_def.invoke(
        {
            "duration": 0,
            "src_bytes": 0,
            "dst_bytes": 0,
            "count": 511,
            "srv_count": 511,
            "source_ip": "198.51.100.77",
        },
        debug=True,
    )
    print("Result:", result_2)

    # -----------------------------------------------------------------------
    # Test case 3 – Suspicious port scan (Probe)
    # -----------------------------------------------------------------------
    print("\n[Test 3] Suspicious Probe / port-scan pattern")
    result_3 = await flow_def.invoke(
        {
            "duration": 0,
            "src_bytes": 491,
            "dst_bytes": 0,
            "count": 2,
            "srv_count": 2,
            "source_ip": "192.0.2.55",
        },
        debug=True,
    )
    print("Result:", result_3)

    # -----------------------------------------------------------------------
    # Test case 4 – Policy violation (critical internal IP)
    # -----------------------------------------------------------------------
    print("\n[Test 4] Policy guard – attempts to block critical gateway IP")
    result_4 = await flow_def.invoke(
        {
            "duration": 0,
            "src_bytes": 0,
            "dst_bytes": 0,
            "count": 300,
            "srv_count": 300,
            "source_ip": "10.0.0.1",
        },
        debug=True,
    )
    print("Result:", result_4)


if __name__ == "__main__":
    asyncio.run(main())
