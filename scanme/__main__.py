"""Entry point for python -m scanme"""

import sys

from scanme.cli import run


def main():
    try:
        run()
    except KeyboardInterrupt:
        print("\n\033[31m[!] Interrupted by user\033[0m")
        sys.exit(130)


if __name__ == "__main__":
    main()
