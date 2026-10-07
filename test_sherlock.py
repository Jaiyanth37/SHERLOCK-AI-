from engine.rules import analyze_threat


TEST_CASES = [

    {
        "name": "Phishing Attack",
        "input": "I received an urgent email asking me to verify my account using a suspicious link and provide my password."
    },

    {
        "name": "Brute Force Attack",
        "input": "There are multiple failed logins and repeated authentication failures with password guessing."
    },

    {
        "name": "Ransomware Attack",
        "input": "All my files are encrypted and I received a ransom note asking for bitcoin payment to decrypt files."
    },

    {
        "name": "Malware",
        "input": "A suspicious executable and unknown malicious file was downloaded onto the computer."
    },

    {
        "name": "DDoS Attack",
        "input": "The website is unavailable because of a huge traffic flood and distributed requests."
    },

    {
        "name": "SQL Injection",
        "input": "The attacker entered UNION SELECT and tried to manipulate a database query."
    },

    {
        "name": "XSS Attack",
        "input": "The attacker injected <script> javascript code into a web page."
    },

    {
        "name": "Credential Theft",
        "input": "Someone attempted credential dumping and password harvesting to steal login credentials."
    },

    {
        "name": "Unknown Scenario",
        "input": "The office printer is making unusual noises."
    }
]


def run_tests():

    print("\n")
    print("=" * 70)
    print("              SHERLOCK AI - INTELLIGENCE TEST")
    print("=" * 70)

    passed = 0
    failed = 0

    for number, test in enumerate(TEST_CASES, start=1):

        print("\n" + "-" * 70)
        print(f"TEST {number}: {test['name']}")
        print("-" * 70)

        try:

            result = analyze_threat(test["input"])

            print(f"Input: {test['input']}")

            print(f"\nIOC Type: {result['ioc']['type']}")
            print(f"Confidence: {result['ioc']['confidence']}%")

            print(
                f"Risk Score: "
                f"{result['risk']['score']}/100"
            )

            print(
                f"Severity: "
                f"{result['risk']['severity']}"
            )

            print("\nDetected Threats:")

            if result["threats"]:

                for threat in result["threats"]:
                    print(
                        f"  - {threat['name']} "
                        f"[{threat['severity']}]"
                    )

            else:
                print("  - No threat detected")

            print("\nMITRE ATT&CK:")

            if result["mitre"]:

                print(result["mitre"])

            else:

                print("  - No MITRE mapping")

            print("\nReasoning:")

            for reason in result["reasoning"]:
                print(f"  - {reason}")

            print("\nRecommendations:")

            for action in result["recommendations"]:
                print(f"  - {action}")

            passed += 1

            print("\nRESULT: PASS")

        except Exception as error:

            failed += 1

            print("\nRESULT: FAIL")
            print(f"ERROR: {error}")

    print("\n")
    print("=" * 70)
    print("                    TEST SUMMARY")
    print("=" * 70)

    print(f"Total Tests : {len(TEST_CASES)}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")

    if failed == 0:

        print("\n🔥 SHERLOCK INTELLIGENCE ENGINE PASSED ALL TESTS 🔥")

    else:

        print("\n⚠️ Some tests failed.")
        print("Check the error messages above.")

    print("=" * 70)
    print()


if __name__ == "__main__":
    run_tests()