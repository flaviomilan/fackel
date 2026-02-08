import argparse
import os
import sys

import markdown2

from processors.osint_processor import OsintProcessor


def save_report_as_html(markdown_content: str, filename: str):
    """
    Converts markdown content to a styled HTML file.
    """
    print(f"\n[Exporter] Converting report to HTML and saving as {filename}...")
    try:

        html_body = markdown2.markdown(
            markdown_content, extras=["tables", "fenced-code-blocks", "strike"]
        )

        css_style = """
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; margin: 0 auto; max-width: 800px; padding: 20px; color: #333; }
        h1, h2, h3 { color: #2c3e50; border-bottom: 1px solid #ecf0f1; padding-bottom: 10px; }
        h1 { font-size: 2.5em; }
        h2 { font-size: 2em; }
        h3 { font-size: 1.5em; }
        code { background-color: #ecf0f1; padding: 3px 5px; border-radius: 4px; font-family: "Courier New", Courier, monospace; }
        pre { background-color: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
        pre code { background-color: transparent; padding: 0; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        blockquote { border-left: 4px solid #3498db; padding-left: 15px; color: #7f8c8d; }
        """

        full_html = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fackel OSINT Report</title>
    <style>{css_style}</style>
</head>
<body>
    <h1>Fackel OSINT Report</h1>
    {html_body}
</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(full_html)
        print(f"[Exporter] Report successfully saved to {filename}")

    except Exception as e:
        print(f"\n[Exporter] Error saving HTML report: {e}")


def main():
    """
    Main function to run the OSINT analysis tool.
    """
    parser = argparse.ArgumentParser(
        description="Fackel - An OSINT analysis tool powered by a LangChain agent."
    )
    parser.add_argument(
        "domain", type=str, help="The domain to perform OSINT analysis on."
    )
    parser.add_argument(
        "--active-scan",
        action="store_true",
        help="Enable active scanning tools like Nmap. Use with caution and only with permission.",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Save the final report to an HTML file (e.g., --output report.html).",
    )

    args = parser.parse_args()

    if not args.domain:
        print("Error: A domain must be provided.")
        parser.print_help()
        sys.exit(1)

    if args.active_scan:
        print(
            """
        *** WARNING: Active Scanning Enabled ***
        You have enabled active scanning tools. This will send packets directly to the target.
        Ensure you have explicit permission to scan the target domain.
        """
        )

    try:

        processor = OsintProcessor(active_scan=args.active_scan)

        report_content, store = processor.process_domain(args.domain)

        if args.output and report_content:
            save_report_as_html(report_content, args.output)

        # Persist structured data for correlação posterior
        if store:
            store_path = args.output.replace(".html", ".json") if args.output else f"{args.domain}_report.json"
            store.save_json(store_path)
            print(f"[Exporter] Structured report saved to {store_path}")

    except ValueError as e:
        print(f"Configuration Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
