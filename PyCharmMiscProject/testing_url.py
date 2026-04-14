from analyzer import analyze_qr_data, RiskLevel


def run_confusion_matrix_evaluation():
    print("Starting Security Efficacy Evaluation (N=40)...\n")

    # --- CATEGORY 1: 10 SAFE URLs (Expected Outcome: SAFE) ---
    safe_urls = [
        "https://www.bbc.co.uk",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://www.amazon.co.uk",
        "https://www.gov.uk",
        "https://www.nhs.uk",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.chase.com",
        "https://www.nike.com"
    ]

    # --- CATEGORY 2, 3 & 4: 30 MALICIOUS URLs (Expected Outcome: MALICIOUS) ---
    malicious_urls = [
        # Category 2: Known Phishing/Social Engineering formats
        "https://secure-update-required-now.com/login",
        "https://verification-account-status.com/auth",
        "https://customer-support-refund-portal.net",
        "https://office365-password-reset-urgent.com",
        "https://banking-authorization-check.com",
        "https://invoice-download-document.net/file.exe",
        "https://dhl-package-tracking-fee.com",
        "https://netflix-subscription-failed.com/renew",
        "https://amazon-locked-account-recovery.com",
        "https://paypal-resolution-center-urgent.com",

        # Category 3: Typosquatting & Homograph URLs (Fuzzy/Visual Spoofing)
        "https://www.paypal-security.com",
        "https://www.apple-login.com",
        "https://www.micr0soft.com",
        "https://www.googIe.com",
        "https://www.pàypal.com",
        "https://www.ámazon.com",
        "https://www.nétflix.com",
        "https://www.bänk.com",
        "https://www.drópbox.com",
        "https://www.support-apple-device.com",

        # Category 4: DGA URLs (Information Theory / Shannon Entropy)
        "https://www.secure-login.com/x8f92j3b9a8f7d6c",
        "https://www.update-server.net/z9y8x7w6v5u4t3s2",
        "https://www.auth-gateway.com/q1w2e3r4t5y6u7i8",
        "https://www.service-portal.org/a1s2d3f4g5h6j7k8",
        "https://www.cloud-host.net/z1x2c3v4b5n6m7l8",
        "https://www.web-traffic.com/p0o9i8u7y6t5r4e3",
        "https://www.data-stream.org/m1n2b3v4c5x6z7l8",
        "https://www.backend-node.net/k8j7h6g5f4d3s2a1",
        "https://www.api-endpoint.com/qazwsxedcrfvtgby",
        "https://www.cdn-route.net/pL9kR2mX5vB8nW1q"
    ]

    TP = 0  # True Positive (Threat blocked)
    TN = 0  # True Negative (Safe link allowed)
    FP = 0  # False Positive (Safe link blocked)
    FN = 0  # False Negative (Threat allowed)

    print("--- EVALUATING SAFE URLs ---")
    for url in safe_urls:
        result = analyze_qr_data(url)
        if result.level == RiskLevel.MALICIOUS:
            FP += 1
            print(f"[FALSE POSITIVE] Blocked a safe link: {url} \n -> Reason: {result.message}\n")
        else:
            TN += 1

    print("--- EVALUATING MALICIOUS URLs ---")
    for url in malicious_urls:
        result = analyze_qr_data(url)
        if result.level == RiskLevel.MALICIOUS:
            TP += 1
        else:
            FN += 1
            print(f"[FALSE NEGATIVE] Missed a threat: {url} \n -> Reason: {result.message}\n")

    total_tests = TP + TN + FP + FN
    accuracy = (TP + TN) / total_tests
    recall = TP / (TP + FN)

    print("=" * 50)
    print("GENUINE CONFUSION MATRIX RESULTS")
    print("=" * 50)
    print(f"Total Payloads Tested : {total_tests}")
    print(f"True Positives (TP)   : {TP}")
    print(f"True Negatives (TN)   : {TN}")
    print(f"False Positives (FP)  : {FP}")
    print(f"False Negatives (FN)  : {FN}")
    print("-" * 50)
    print(f"Accuracy Formula      : ({TP} + {TN}) / {total_tests}")
    print(f"Overall Accuracy      : {accuracy * 100:.1f}%")
    print(f"Recall Formula        : {TP} / ({TP} + {FN})")
    print(f"Overall Recall        : {recall * 100:.1f}%")
    print("=" * 50)


if __name__ == "__main__":
    import logging

    logging.getLogger("QRSecurityEngine").setLevel(logging.CRITICAL)
    run_confusion_matrix_evaluation()