import argparse
from server import generate_forensic_report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run forensic correlation analysis.")
    parser.add_argument("filename", help="Path to the file to analyze")
    parser.add_argument("keyword", nargs="?", default="modified", help="Keyword to search in logs")
    args = parser.parse_args()

    report = generate_forensic_report(args.filename, args.keyword)

    if report.get("status") == "error":
        print("Failed:", report.get("message", "Unknown error"))
    else:
        print(f"File: {report['filename']}")
        print(f"Keyword searched in logs: '{report['keyword']}'")
        print(f"File modified at: {report['file_modified_time']}")
        print("Matching log entries (sample):")
        for line in report.get("log_hits", []):
            print("  •", line.strip())
        print("\n✅ Correlation found:" if report["correlation_found"] else "\nCorrelation found: No")