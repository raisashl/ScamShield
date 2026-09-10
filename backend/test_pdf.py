import sys
from pypdf import PdfReader
from document_analyzer import analyze_document

if len(sys.argv) < 2:
    print('Usage: python test_pdf.py "path-to-pdf"')
    sys.exit(1)

pdf_path = sys.argv[1]

print("================================")
print("   SCAMSHIELD PDF TESTER")
print("================================")

print("\nReading PDF...")

reader = PdfReader(pdf_path)

text = "\n\n".join(
    page.extract_text() or ""
    for page in reader.pages
)

print(f"Pages: {len(reader.pages)}")
print(f"Extracted characters: {len(text)}")

print("\nAnalyzing document...")

result = analyze_document(text)

print("\n================================")
print("DOCUMENT ANALYSIS")
print("================================")

print(
    f"\nOverall Risk Score: "
    f"{result['overall_risk']:.2f}%"
)

print(
    f"Risk Level: "
    f"{result['risk_level']}"
)

print("\nHighest Risk Sections:")
print("--------------------------------")

for i, section in enumerate(
    result["sections"],
    1
):
    print(
        f"\n{i}. Combined Risk: "
        f"{section['combined_score']:.2f}%"
    )

    print(
        f"   ML Score: "
        f"{section['ml_score']:.2f}%"
    )

    print(
        f"   Rule Score: "
        f"{section['rule_score']:.2f}%"
    )

    if section["flags"]:
        print(
            "   Red Flags: "
            + ", ".join(section["flags"])
        )

    print("\n   Text:")
    print("   " + section["text"][:500])

    if len(section["text"]) > 500:
        print("   ...")

print("\n================================")
print("Analysis complete.")
print("================================")