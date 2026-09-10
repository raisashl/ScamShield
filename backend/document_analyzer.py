import re
import joblib

from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# LOAD ML MODEL
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "scamshield_model.pkl"

model = joblib.load(MODEL_PATH)


# ============================================================
# SCAM DETECTION PATTERNS
# ============================================================

PATTERNS = {

    "Payment request": [
        r"\bpay\b",
        r"\bpayment\b",
        r"\bfee\b",
        r"\bcharge\b",
        r"\bdeposit\b",
        r"\btransfer\b",
        r"\bsend money\b",
        r"\bprocessing fee\b",
        r"\bregistration fee\b",
        r"\bsecurity deposit\b"
    ],

    "Prize/reward claim": [
        r"\byou won\b",
        r"\bwon a prize\b",
        r"\bprize\b",
        r"\breward\b",
        r"\bcongratulations\b",
        r"\bcash prize\b",
        r"\bclaim your\b",
        r"\blottery\b"
    ],

    "OTP/password request": [
        r"\botp\b",
        r"\bone[- ]time password\b",
        r"\bverification code\b",
        r"\bpassword\b",
        r"\bpin\b",
        r"\bcvv\b",
        r"\bcard number\b",
        r"\baccount details\b"
    ],

    "Urgency/threat language": [
        r"\bimmediately\b",
        r"\burgent\b",
        r"\bact now\b",
        r"\bwithin \d+ hours?\b",
        r"\btoday\b",
        r"\blast warning\b",
        r"\bwill be blocked\b",
        r"\bwill be suspended\b",
        r"\baccount will be closed\b",
        r"\bdo not delay\b"
    ],

    "Suspicious link": [
        r"https?://",
        r"www\.",
        r"\bclick here\b",
        r"\bopen this link\b",
        r"\bverify.*link\b",
        r"\bverification link\b"
    ],

    "Employment payment request": [
        r"\bjob\b",
        r"\bjoining\b",
        r"\binterview\b",
        r"\bemployment\b",
        r"\brecruitment\b",
        r"\bsalary\b",
        r"\bsecurity deposit\b",
        r"\bregistration fee\b",
        r"\btraining fee\b",
        r"\bpay.*before.*joining\b",
        r"\bpay.*to.*join\b"
    ],

    "Investment scam pattern": [
        r"\binvestment\b",
        r"\binvest\b",
        r"\bguaranteed returns\b",
        r"\bguaranteed profit\b",
        r"\bdouble your money\b",
        r"\bhigh returns\b",
        r"\bquick profit\b",
        r"\bcrypto\b",
        r"\btrading profit\b"
    ],

    "Refund scam pattern": [
        r"\brefund\b",
        r"\brefund.*fee\b",
        r"\brefund.*payment\b",
        r"\bpay.*refund\b",
        r"\bprocessing.*refund\b"
    ],

    "Delivery scam pattern": [
        r"\bdelivery\b",
        r"\bcourier\b",
        r"\bpackage\b",
        r"\bparcel\b",
        r"\bshipping\b",
        r"\bcustoms\b",
        r"\bdelivery fee\b",
        r"\baddress.*verify\b"
    ]
}


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):
    """
    Analyze a URL for suspicious structural characteristics.

    IMPORTANT:
    This function does NOT visit the website.
    It only examines the URL structure.
    """

    url = url.strip()

    if not url:
        return {
            "detected": False,
            "score": 0,
            "flags": []
        }

    test_url = url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        test_url
    ):
        test_url = "http://" + test_url

    try:
        parsed = urlparse(test_url)

    except Exception:
        return {
            "detected": True,
            "score": 40,
            "flags": [
                "Invalid or unusual URL structure"
            ]
        }

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    path = parsed.path.lower()
    query = parsed.query.lower()

    flags = []
    score = 0

    # HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":

        flags.append(
            "Website does not use HTTPS"
        )

        score += 10

    # IP address instead of domain
    if re.match(
        r"^\d{1,3}(\.\d{1,3}){3}$",
        hostname
    ):

        flags.append(
            "URL uses an IP address instead of a domain name"
        )

        score += 25

    # Multiple subdomains
    parts = hostname.split(".")

    if len(parts) >= 4:

        flags.append(
            "URL contains multiple subdomains"
        )

        score += 15

    # Suspicious URL keywords
    suspicious_keywords = [
        "verify",
        "verification",
        "secure",
        "security",
        "login",
        "signin",
        "account",
        "update",
        "confirm",
        "password",
        "wallet",
        "bonus",
        "prize",
        "reward",
        "claim",
        "refund",
        "payment",
        "bank"
    ]

    found_keywords = []

    combined_url = (
        hostname +
        path +
        query
    )

    for keyword in suspicious_keywords:

        if keyword in combined_url:

            found_keywords.append(
                keyword
            )

    if found_keywords:

        flags.append(
            "URL contains sensitive or high-risk keywords"
        )

        score += min(
            len(found_keywords) * 5,
            20
        )

    # @ symbol
    if "@" in url:

        flags.append(
            "URL contains an unusual @ symbol"
        )

        score += 20

    # Too many hyphens
    if hostname.count("-") >= 3:

        flags.append(
            "Domain contains many hyphens"
        )

        score += 10

    # Very long URL
    if len(url) > 150:

        flags.append(
            "URL is unusually long"
        )

        score += 10

    # URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "cutt.ly",
        "shorturl.at"
    ]

    if any(
        hostname == domain
        or hostname.endswith("." + domain)
        for domain in shorteners
    ):

        flags.append(
            "URL uses a URL shortening service"
        )

        score += 15

    # Encoded domain
    if "xn--" in hostname:

        flags.append(
            "Domain uses encoded characters"
        )

        score += 20

    # Many unusual characters
    special_count = len(
        re.findall(
            r"[%_=]",
            url
        )
    )

    if special_count >= 6:

        flags.append(
            "URL contains many unusual characters"
        )

        score += 10

    score = min(
        score,
        100
    )

    return {
        "detected": True,
        "score": score,
        "flags": flags,
        "hostname": hostname
    }


# ============================================================
# EXTRACT URLS
# ============================================================

def extract_urls(text):

    return re.findall(
        r"https?://[^\s<>\"]+|www\.[^\s<>\"]+",
        text,
        re.IGNORECASE
    )


# ============================================================
# PATTERN DETECTION
# ============================================================

def detect_patterns(text):

    text_lower = text.lower()

    detected = []
    details = []

    for pattern_name, patterns in PATTERNS.items():

        matched = False

        for pattern in patterns:

            if re.search(
                pattern,
                text_lower,
                re.IGNORECASE
            ):

                matched = True
                break

        if matched:

            detected.append(
                pattern_name
            )

            details.append({
                "category": pattern_name,
                "message": pattern_name
            })

    return detected, details


# ============================================================
# IMPROVED RULE-BASED RISK SCORE
# ============================================================

def calculate_rule_score(text, detected):

    score = 0

    # --------------------------------------------------------
    # Basic pattern score
    # --------------------------------------------------------

    score += len(detected) * 10

    # --------------------------------------------------------
    # Individual scam indicators
    # --------------------------------------------------------

    if "Payment request" in detected:
        score += 20

    if "OTP/password request" in detected:
        score += 25

    if "Suspicious link" in detected:
        score += 20

    if "Urgency/threat language" in detected:
        score += 15

    if "Prize/reward claim" in detected:
        score += 20

    if "Investment scam pattern" in detected:
        score += 20

    if "Employment payment request" in detected:
        score += 20

    if "Refund scam pattern" in detected:
        score += 15

    if "Delivery scam pattern" in detected:
        score += 15

    # --------------------------------------------------------
    # Strong scam combinations
    # --------------------------------------------------------

    # Job + payment
    if (
        "Employment payment request" in detected
        and "Payment request" in detected
    ):

        score += 20

    # Prize + payment
    if (
        "Prize/reward claim" in detected
        and "Payment request" in detected
    ):

        score += 30

    # OTP + urgency
    if (
        "OTP/password request" in detected
        and "Urgency/threat language" in detected
    ):

        score += 25

    # Suspicious link + urgency
    if (
        "Suspicious link" in detected
        and "Urgency/threat language" in detected
    ):

        score += 20

    # Investment + payment
    if (
        "Investment scam pattern" in detected
        and "Payment request" in detected
    ):

        score += 25

    # Refund + payment
    if (
        "Refund scam pattern" in detected
        and "Payment request" in detected
    ):

        score += 20

    # Delivery + payment
    if (
        "Delivery scam pattern" in detected
        and "Payment request" in detected
    ):

        score += 20

    return min(
        score,
        100
    )


# ============================================================
# ANALYZE ONE SECTION
# ============================================================

def analyze_section(text):

    # --------------------------------------------------------
    # ML MODEL SCORE
    # --------------------------------------------------------

    probabilities = model.predict_proba(
        [text]
    )[0]

    ml_score = float(
        probabilities[1] * 100
    )

    # --------------------------------------------------------
    # RULE DETECTION
    # --------------------------------------------------------

    detected, details = detect_patterns(
        text
    )

    rule_score = calculate_rule_score(
        text,
        detected
    )

    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    urls = extract_urls(
        text
    )

    url_flags = []
    url_score = 0

    for url in urls:

        url_result = analyze_url(
            url
        )

        url_flags.extend(
            url_result["flags"]
        )

        url_score = max(
            url_score,
            url_result["score"]
        )

    # If URL is suspicious
    if url_score > 0:

        if "Suspicious link" not in detected:

            detected.append(
                "Suspicious link"
            )

        rule_score = min(
            rule_score
            + int(url_score * 0.5),
            100
        )

    # --------------------------------------------------------
    # COMBINE ML + RULES + URL
    # --------------------------------------------------------

    combined_score = (

        ml_score * 0.55

        + rule_score * 0.30

        + url_score * 0.15
    )

    combined_score = min(
        combined_score,
        100
    )

    return {

        "risk": round(
            combined_score,
            2
        ),

        "ml_score": round(
            ml_score,
            2
        ),

        "rule_score": round(
            rule_score,
            2
        ),

        "url_score": round(
            url_score,
            2
        ),

        "flags": detected,

        "url_flags": list(
            dict.fromkeys(
                url_flags
            )
        ),

        "details": details
    }


# ============================================================
# SPLIT DOCUMENT INTO SECTIONS
# ============================================================

def split_into_sections(text):

    paragraphs = [

        p.strip()

        for p in re.split(
            r"\n\s*\n",
            text
        )

        if p.strip()
    ]

    sections = []

    for paragraph in paragraphs:

        if len(paragraph) <= 1500:

            sections.append(
                paragraph
            )

        else:

            words = paragraph.split()

            chunk_size = 150

            for i in range(
                0,
                len(words),
                chunk_size
            ):

                chunk = " ".join(
                    words[
                        i:i + chunk_size
                    ]
                )

                if chunk.strip():

                    sections.append(
                        chunk
                    )

    if not sections:

        sections = [text]

    return sections


# ============================================================
# COMPLETE DOCUMENT ANALYSIS
# ============================================================

def analyze_document(text):

    text = text.strip()

    if not text:

        return {

            "overall_risk": 0,

            "risk_level": "LOW",

            "patterns": [],

            "sections": []
        }

    # --------------------------------------------------------
    # SPLIT DOCUMENT
    # --------------------------------------------------------

    sections = split_into_sections(
        text
    )

    analyzed_sections = []

    all_patterns = []
    all_url_flags = []

    # --------------------------------------------------------
    # ANALYZE EACH SECTION
    # --------------------------------------------------------

    for section in sections:

        result = analyze_section(
            section
        )

        analyzed_sections.append({

            "text": section[:500],

            "risk": result["risk"],

            "ml_score": result["ml_score"],

            "rule_score": result["rule_score"],

            "url_score": result["url_score"],

            "flags": result["flags"],

            "url_flags": result["url_flags"]
        })

        all_patterns.extend(
            result["flags"]
        )

        all_url_flags.extend(
            result["url_flags"]
        )

    # Remove duplicate patterns
    all_patterns = list(
        dict.fromkeys(
            all_patterns
        )
    )

    # Remove duplicate URL flags
    all_url_flags = list(
        dict.fromkeys(
            all_url_flags
        )
    )

    # --------------------------------------------------------
    # SORT SECTIONS BY RISK
    # --------------------------------------------------------

    analyzed_sections.sort(
        key=lambda x: x["risk"],
        reverse=True
    )

    # --------------------------------------------------------
    # TOP SECTION RISK
    # --------------------------------------------------------

    if analyzed_sections:

        top_sections = analyzed_sections[:5]

        section_risk = sum(
            s["risk"]
            for s in top_sections
        ) / len(top_sections)

    else:

        section_risk = 0

    # --------------------------------------------------------
    # DOCUMENT-LEVEL RULE SCORE
    # --------------------------------------------------------

    pattern_score = calculate_rule_score(
        text,
        all_patterns
    )

    # --------------------------------------------------------
    # DOCUMENT URL SCORE
    # --------------------------------------------------------

    urls = extract_urls(
        text
    )

    document_url_score = 0

    for url in urls:

        url_result = analyze_url(
            url
        )

        document_url_score = max(
            document_url_score,
            url_result["score"]
        )

    # --------------------------------------------------------
    # FINAL DOCUMENT RISK
    # --------------------------------------------------------

    overall_risk = (

        section_risk * 0.45

        + pattern_score * 0.40

        + document_url_score * 0.15
    )

    # --------------------------------------------------------
    # EXTRA STRONG SCAM COMBINATIONS
    # --------------------------------------------------------

    if (
        "Employment payment request"
        in all_patterns

        and

        "Payment request"
        in all_patterns
    ):

        overall_risk += 10

    if (
        "Employment payment request"
        in all_patterns

        and

        "Refund scam pattern"
        in all_patterns
    ):

        overall_risk += 10

    if (
        "Prize/reward claim"
        in all_patterns

        and

        "Payment request"
        in all_patterns
    ):

        overall_risk += 10

    if (
        "OTP/password request"
        in all_patterns

        and

        "Urgency/threat language"
        in all_patterns
    ):

        overall_risk += 10

    if (
        "Suspicious link"
        in all_patterns

        and

        "Urgency/threat language"
        in all_patterns
    ):

        overall_risk += 8

    # --------------------------------------------------------
    # STRONG URL RISK
    # --------------------------------------------------------

    if document_url_score >= 60:

        overall_risk += 10

    elif document_url_score >= 40:

        overall_risk += 5

    # --------------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------------

    overall_risk = min(
        overall_risk,
        100
    )

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if overall_risk >= 70:

        risk_level = "HIGH"

    elif overall_risk >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # --------------------------------------------------------
    # FINAL RESPONSE
    # --------------------------------------------------------

    return {

        "overall_risk": round(
            overall_risk,
            2
        ),

        "risk_level": risk_level,

        "patterns": all_patterns,

        "url_score": round(
            document_url_score,
            2
        ),

        "url_flags": all_url_flags,

        "sections": analyzed_sections[:10]
    }